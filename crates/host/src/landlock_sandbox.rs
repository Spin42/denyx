//! Landlock (Linux 5.13+ LSM) subprocess sandboxing — the enforcement
//! side of `[subprocess].sandbox = "landlock"`. Availability probing
//! lives in `denyx_policy::landlock_available` (checked at policy-load
//! time via `Policy::guard_sandbox_available`); this module only
//! applies the actual restriction once a `subprocess.exec` call has
//! already passed every other gate.
//!
//! ## How this differs from `sandbox = "bwrap"`
//!
//! Bwrap wraps the child in an external process that builds a fresh
//! Linux namespace + bind-mount jail: the child's filesystem view is
//! CONSTRUCTED to contain only what the policy permits, and process/
//! network namespaces are unshared too. Landlock is narrower and
//! applied differently: there's no wrapper process and no namespace
//! construction. Instead, the target binary's OWN process (after
//! `fork()`, before `exec()`) calls `landlock_restrict_self` on
//! itself, attaching a ruleset that the kernel enforces against every
//! subsequent filesystem/network syscall for the rest of that
//! process's life (and everything it execs afterward — Landlock
//! rulesets are inherited across `exec()`, unlike most process state).
//!
//! Concretely, Landlock here gets you:
//! - Filesystem access scoped to the policy's allow lists plus a
//!   minimal set of system directories needed to exec at all (same
//!   list `bwrap_argv` uses for `--ro-bind-try`).
//! - TCP bind/connect denied entirely when the policy grants no
//!   network capability (mirrors bwrap's `--unshare-net`) — on
//!   kernels new enough for Landlock ABI v4 (6.7+); older kernels
//!   silently skip just this part in best-effort mode, still getting
//!   the filesystem restriction.
//!
//! Landlock does NOT get you (unlike bwrap):
//! - PID/UTS/IPC namespace isolation — the child can still see (though
//!   not necessarily touch, if procfs access is itself restricted)
//!   other processes on the system.
//! - A reconstructed filesystem view — the real directory tree is
//!   still there; Landlock denies *access* to paths outside the
//!   ruleset, it doesn't hide their existence the way an unmounted
//!   bind-mount jail does. `stat()` on a denied path can still succeed
//!   in some cases even though `open()` would fail.
//! - UDP or non-TCP network restriction — Landlock's network hooks
//!   (as of the ABI versions this crate targets) only cover TCP
//!   bind/connect.
//!
//! Prefer Landlock over bwrap specifically when bwrap's unprivileged
//! user namespace requirement isn't available (some containers,
//! hardened kernels — see `crates/host/tests/sandbox_bwrap.rs`'s
//! `bwrap_works()` for exactly this failure mode) but Landlock is.
//! They are complementary, not competing — see
//! `docs/landlock-evaluation.md`.

use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};

/// Minimal system paths a spawned child needs read+execute access to
/// just to run at all. Matches
/// `denyx_policy::Policy::bwrap_argv`'s `--ro-bind-try` list exactly.
/// Deliberately individual files under `/etc`, not the whole
/// directory — granting all of `/etc` would include `/etc/passwd`,
/// `/etc/shadow`, and similar, which neither backend intends to
/// expose just to let the dynamic linker and DNS resolution work.
/// `/proc` matches bwrap's separate `--proc` mount.
const SYSTEM_DIRS_READONLY: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/hosts",
    "/proc",
];

/// `/dev` needs read-WRITE, not just read: `/dev/null`, `/dev/zero`,
/// and similar are commonly opened `O_RDWR` by entirely ordinary
/// programs (git and ssh both do this for `/dev/null` redirection).
/// Landlock enforces the exact access mode requested per path, unlike
/// bwrap's `--dev /dev` mount (which sets up a fresh, permissive
/// pseudo-filesystem) — found live while testing this module: an
/// initial read-only grant broke `git ls-remote` with "could not open
/// '/dev/null' for reading and writing: Permission denied" before the
/// command ever reached the network layer this sandbox is also
/// supposed to be restricting.
const SYSTEM_DIRS_READWRITE: &[&str] = &["/dev"];

/// The Landlock ABI version this module targets. `CompatLevel::BestEffort`
/// (used throughout below) means a kernel that only supports an older
/// ABI silently gets the subset of these restrictions it can enforce,
/// rather than failing the call — consistent with the project's
/// established "graceful degradation with an honest doc note, not a
/// hard requirement" posture for defense-in-depth layers.
const TARGET_ABI: ABI = ABI::V4;

/// Register a `pre_exec` hook on `cmd` that restricts the forked
/// child via Landlock before it execs, using the given read/write
/// path allow-lists (see `Policy::sandbox_fs_paths`) and whether
/// network access should be denied entirely (see
/// `Policy::any_network_capability_granted` — pass `true` here when
/// that returns `false`, i.e. deny network when nothing needs it,
/// mirroring `bwrap_argv`'s `--unshare-net` condition exactly).
///
/// # Safety / signal-safety note
///
/// `pre_exec` closures run in the forked child between `fork()` and
/// `exec()`, where the child is still single-threaded and technically
/// bound by async-signal-safety rules that plain Rust code (which may
/// allocate) doesn't strictly satisfy. This is the same trade-off
/// every real-world Rust `pre_exec` user (including this crate's own
/// bwrap path indirectly, via `std::process::Command` itself) already
/// accepts in practice on Linux: the child has no other threads racing
/// the allocator at this point, so allocation here is safe in
/// practice even though it isn't POSIX-pure. All the actual Landlock
/// syscalls this closure makes are raw syscalls with no internal
/// locking, so they're signal-safe on their own merits regardless.
pub(crate) fn wire_pre_exec(
    cmd: &mut std::process::Command,
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    deny_network: bool,
) {
    unsafe {
        cmd.pre_exec(move || {
            apply(&read_paths, &write_paths, deny_network)
                .map_err(|e| std::io::Error::other(format!("landlock: {e}")))
        });
    }
}

/// Build a ruleset from the given paths and apply it to the CURRENT
/// process via `restrict_self()`. Must only ever be called from
/// within a freshly forked child (via `wire_pre_exec` above) — this
/// is a one-way door for whatever process calls it, which is exactly
/// right for a `pre_exec` child that's about to exec into the real
/// target binary (or fail to, in which case it exits without ever
/// having been a "real" long-lived process anyway).
fn apply(
    read_paths: &[PathBuf],
    write_paths: &[PathBuf],
    deny_network: bool,
) -> anyhow::Result<()> {
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(TARGET_ABI))?;
    if deny_network {
        ruleset = ruleset.handle_access(AccessNet::from_all(TARGET_ABI))?;
    }
    let created = ruleset
        .create()?
        // Missing paths are silently skipped by `path_beneath_rules`
        // (filter_map over a failed PathFd::new) — mirrors
        // `bwrap_argv`'s `--ro-bind-try` (try, don't require) so an
        // operator's `write_allow` entry for a not-yet-created
        // directory doesn't break the sandboxed call.
        .add_rules(path_beneath_rules(
            SYSTEM_DIRS_READONLY,
            AccessFs::from_read(TARGET_ABI),
        ))?
        .add_rules(path_beneath_rules(
            SYSTEM_DIRS_READWRITE,
            AccessFs::from_all(TARGET_ABI),
        ))?
        .add_rules(path_beneath_rules(
            read_paths,
            AccessFs::from_read(TARGET_ABI),
        ))?
        .add_rules(path_beneath_rules(
            write_paths,
            AccessFs::from_all(TARGET_ABI),
        ))?;
    // No NetPort rules are added even when `deny_network` requested
    // handling AccessNet above — an empty rule set for a handled
    // access class means nothing is granted, i.e. every bind/connect
    // is denied. This mirrors bwrap_argv's `--unshare-net`: total
    // denial, not a port allow-list. When `deny_network` is false, we
    // never called `handle_access` for AccessNet at all, so network
    // is left entirely unrestricted by this layer (Denyx's own
    // `net.*` Starlark gate is still the control for THAT channel;
    // this only ever concerns ambient subprocess network access).

    created.restrict_self()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Fork a throwaway child (never actually exec'ing anything — see
    /// the `std::process::exit` calls below), apply Landlock exactly
    /// as `wire_pre_exec` would, then run `probe` in that SAME child
    /// post-restriction and report its bool result via exit code.
    /// Self-contained: no external binaries, no argv path-gate, no
    /// ambient-file friction from a real program's own startup
    /// behavior (git, curl, etc. — see this module's doc comment for
    /// why testing through a real command hits that noise). Returns
    /// `None` if the child didn't exit with a 0/1 code, which would
    /// mean `apply()` itself errored (exit 2) or something else went
    /// wrong — inconclusive, not a pass or fail.
    fn run_after_restrict<F>(
        read_paths: Vec<PathBuf>,
        write_paths: Vec<PathBuf>,
        deny_network: bool,
        probe: F,
    ) -> Option<bool>
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        let mut cmd = std::process::Command::new("true");
        unsafe {
            cmd.pre_exec(move || {
                if apply(&read_paths, &write_paths, deny_network).is_err() {
                    std::process::exit(2);
                }
                std::process::exit(if probe() { 1 } else { 0 });
            });
        }
        let status = cmd.status().ok()?;
        match status.code() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        }
    }

    /// `denyx_policy::landlock_available()` only checks ABI V1
    /// (filesystem), the minimum this module requires — it does NOT
    /// guarantee ABI V4 (network, Linux 6.7+), which the network
    /// tests below specifically need for a strict pass. `apply()`
    /// itself is always safe to call regardless (best-effort mode
    /// silently skips network handling on an older kernel), but
    /// asserting network denial strictly requires actually checking
    /// for V4.
    fn abi_v4_network_available() -> bool {
        use landlock::{AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr, ABI};
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessNet::from_all(ABI::V4))
            .and_then(|r| r.create())
            .is_ok()
    }

    fn skip_if_unavailable() -> bool {
        if denyx_policy::landlock_available() {
            false
        } else {
            eprintln!(
                "skipping: Landlock is not available on this kernel/environment \
                 (needs Linux 5.13+, and some containers/hardened configs disable it \
                 even on a new-enough kernel)"
            );
            true
        }
    }

    #[test]
    fn denies_read_outside_any_granted_path() {
        if skip_if_unavailable() {
            return;
        }
        let secret = std::env::temp_dir().join(format!(
            "denyx_landlock_secret_{}_{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&secret, "x").unwrap();
        let probe_path = secret.clone();
        let result = run_after_restrict(vec![], vec![], false, move || {
            std::fs::File::open(&probe_path).is_ok()
        });
        let _ = std::fs::remove_file(&secret);
        assert_eq!(
            result,
            Some(false),
            "expected reading a path outside every granted list to fail under Landlock"
        );
    }

    #[test]
    fn allows_read_inside_a_granted_read_path() {
        if skip_if_unavailable() {
            return;
        }
        let allowed = std::env::temp_dir().join(format!(
            "denyx_landlock_allowed_{}_{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&allowed, "x").unwrap();
        let probe_path = allowed.clone();
        let result = run_after_restrict(vec![allowed.clone()], vec![], false, move || {
            std::fs::File::open(&probe_path).is_ok()
        });
        let _ = std::fs::remove_file(&allowed);
        assert_eq!(
            result,
            Some(true),
            "expected reading an explicitly granted path to succeed under Landlock"
        );
    }

    #[test]
    fn denies_write_to_a_read_only_granted_path() {
        if skip_if_unavailable() {
            return;
        }
        let allowed = std::env::temp_dir().join(format!(
            "denyx_landlock_readonly_{}_{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&allowed, "x").unwrap();
        let probe_path = allowed.clone();
        // Granted via read_paths (read-only), NOT write_paths.
        let result = run_after_restrict(vec![allowed.clone()], vec![], false, move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&probe_path)
                .is_ok()
        });
        let _ = std::fs::remove_file(&allowed);
        assert_eq!(
            result,
            Some(false),
            "expected write to a read-only-granted path to fail under Landlock"
        );
    }

    #[test]
    fn allows_write_to_a_write_granted_path() {
        if skip_if_unavailable() {
            return;
        }
        let allowed = std::env::temp_dir().join(format!(
            "denyx_landlock_writable_{}_{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&allowed, "x").unwrap();
        let probe_path = allowed.clone();
        let result = run_after_restrict(vec![], vec![allowed.clone()], false, move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&probe_path)
                .is_ok()
        });
        let _ = std::fs::remove_file(&allowed);
        assert_eq!(
            result,
            Some(true),
            "expected write to an explicitly write-granted path to succeed under Landlock"
        );
    }

    #[test]
    fn denies_tcp_connect_when_network_denied() {
        if skip_if_unavailable() {
            return;
        }
        if !abi_v4_network_available() {
            eprintln!(
                "skipping: this kernel doesn't support Landlock ABI v4 (network, \
                 Linux 6.7+) — apply() still succeeds via best-effort degradation, \
                 it just can't enforce network denial on this kernel"
            );
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || for _ in listener.incoming() {});
        let result = run_after_restrict(vec![], vec![], true, move || {
            std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        });
        assert_eq!(
            result,
            Some(false),
            "expected a TCP connect to be denied when deny_network=true under Landlock"
        );
    }

    #[test]
    fn allows_tcp_connect_when_network_not_denied() {
        if skip_if_unavailable() {
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || for _ in listener.incoming() {});
        let result = run_after_restrict(vec![], vec![], false, move || {
            std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        });
        assert_eq!(
            result,
            Some(true),
            "expected a TCP connect to succeed when deny_network=false (this layer \
             doesn't restrict network at all in that case)"
        );
    }
}
