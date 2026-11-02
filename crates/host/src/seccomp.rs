//! Seccomp-bpf syscall denylist for spawned subprocesses — the second
//! kernel-level confinement layer, applied alongside Landlock in the
//! child's `pre_exec` (see `landlock_sandbox::wire_pre_exec`).
//!
//! ## Why, on top of Landlock
//!
//! Landlock restricts filesystem reach and TCP bind/connect, but it
//! leaves the rest of the syscall surface untouched. A child that
//! slips past Denyx's argv gate (an interpreter, `make`, `find -exec`)
//! can still reach escape and evasion primitives Landlock never sees:
//!
//! - `ptrace`, `process_vm_readv`/`writev`, `kcmp` — inspect or inject
//!   into other processes.
//! - `bpf`, `userfaultfd`, `perf_event_open` — classic local-exploit
//!   primitives.
//! - `io_uring_*` — submits file and network I/O through a ring whose
//!   operations the seccomp *syscall* filter never observes; leaving
//!   it open is a hole in THIS filter. Denied so a program falls back
//!   to ordinary syscalls (which Landlock + this filter do see).
//! - `setns`, `unshare`, `mount`, `umount2`, `pivot_root`, `chroot`,
//!   and the new mount API (`fsopen`/`move_mount`/…) — build or enter
//!   namespaces/mounts to confuse or escape the sandbox. `unshare`
//!   into a new user namespace is unprivileged. `clone` is denied only
//!   when it requests a new namespace; `clone3`, whose flags the filter
//!   cannot read, reports `ENOSYS` so callers fall back to `clone`.
//! - `open_by_handle_at` — opens a file from an opaque handle rather
//!   than a path, sidestepping Landlock's path-based rules.
//! - `keyctl`/`add_key`/`request_key`, the kernel-module and `kexec`
//!   loaders — kernel surfaces no sandboxed child needs.
//!
//! The action is `EPERM`, not kill: a denied syscall fails like any
//! other denied operation, so a program that merely probes one (tries
//! `io_uring`, falls back to `epoll`) keeps working instead of dying.
//! This is a denylist — defense in depth, not a complete syscall jail
//! — chosen because the child runs arbitrary allowed programs (cargo,
//! git, rustc, python) whose full syscall needs can't be enumerated.
//!
//! `apply` sets `no_new_privs` itself, so it is self-contained (and in
//! production runs after Landlock, which already set it — the second
//! set is idempotent).

use std::collections::BTreeMap;

use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};

#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;

/// Syscalls denied (with `EPERM`) to a sandboxed child: each is an
/// escape/evasion primitive or a kernel surface no sandboxed build or
/// scripting tool needs. Numbers come from `libc::SYS_*`, which are
/// correct for the compile-time target architecture, so the filter and
/// its `TargetArch` always agree.
fn denied_syscalls() -> Vec<i64> {
    let raw: &[libc::c_long] = &[
        // Process inspection / injection.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        // Local-exploit primitives.
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        // I/O ring: submits I/O the syscall filter can't observe.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // Namespace / mount manipulation.
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        // Path-gate evasion: open by opaque handle, not by path.
        libc::SYS_open_by_handle_at,
        // Kernel keyring.
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        // Kernel-module and kexec loaders.
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
    ];
    let mut v: Vec<i64> = raw.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

/// Build and install the seccomp denylist on the CURRENT process (the
/// forked child, from `pre_exec`). Sets `no_new_privs` first, as the
/// kernel requires for an unprivileged `seccomp()` filter install.
///
/// Returns `Ok(())` on success. The caller decides whether an error
/// is fatal to the spawn (explicit `sandbox = "landlock"`) or
/// best-effort (a future confine-by-default mode).
pub(crate) fn apply() -> anyhow::Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args and has
    // no memory-safety requirements; called from a single-threaded
    // forked child.
    let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp != 0 {
        return Err(anyhow::anyhow!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = denied_syscalls()
        .into_iter()
        .map(|nr| (nr, vec![]))
        .collect();
    rules.insert(libc::SYS_clone, clone_namespace_rules()?);
    let filter = SeccompFilter::new(
        rules,
        // Default for any syscall NOT listed above: allow.
        SeccompAction::Allow,
        // Action for a listed syscall (empty rule set = always match).
        SeccompAction::Errno(libc::EPERM as u32),
        TARGET_ARCH,
    )?;
    let program: BpfProgram = filter.try_into()?;
    apply_filter(&program)?;

    // clone3 takes its flags through a user-space struct the filter
    // cannot inspect, so namespace creation through it can't be told
    // apart from a plain fork. ENOSYS makes glibc and std fall back to
    // clone, which the rules above do inspect.
    let clone3 = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_clone3, vec![])]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        TARGET_ARCH,
    )?;
    let program: BpfProgram = clone3.try_into()?;
    apply_filter(&program)?;
    Ok(())
}

/// One rule per `CLONE_NEW*` bit: `clone` is denied when any of them is
/// set in its flags argument, the same namespace creation `unshare`
/// would perform.
fn clone_namespace_rules() -> anyhow::Result<Vec<SeccompRule>> {
    [
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ]
    .into_iter()
    .map(|bit| {
        let bit = bit as u64;
        Ok(SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(bit),
            bit,
        )?])?)
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    /// Fork a throwaway child (never actually exec'ing — the `pre_exec`
    /// closure exits first), install the seccomp filter in that child,
    /// run `probe` post-install, and report its bool via exit code.
    /// `None` means the filter couldn't be installed (exit 2) or the
    /// child didn't exit 0/1 — inconclusive, treated as skip by callers
    /// (some CI sandboxes block the `seccomp()` syscall itself).
    fn run_after_apply<F>(probe: F) -> Option<bool>
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        let mut cmd = std::process::Command::new("true");
        unsafe {
            cmd.pre_exec(move || {
                if apply().is_err() {
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

    fn denied(rc: i64) -> bool {
        rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[test]
    fn denies_ptrace_with_eperm() {
        let r = run_after_apply(|| {
            denied(unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) })
        });
        match r {
            Some(true) => {}
            Some(false) => panic!("ptrace was not denied — seccomp filter is ineffective"),
            None => eprintln!("skipping: seccomp could not be installed in this environment"),
        }
    }

    #[test]
    fn denies_unshare_with_eperm() {
        let r = run_after_apply(|| {
            denied(unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER as libc::c_long) })
        });
        match r {
            Some(true) => {}
            Some(false) => panic!("unshare was not denied — seccomp filter is ineffective"),
            None => eprintln!("skipping: seccomp could not be installed in this environment"),
        }
    }

    /// Raw `clone` with `flags`; a child that gets created exits at once.
    fn raw_clone(flags: libc::c_long) -> i64 {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_clone,
                flags | libc::SIGCHLD as libc::c_long,
                0,
                0,
                0,
                0,
            )
        };
        if rc == 0 {
            unsafe { libc::_exit(0) };
        }
        rc
    }

    /// AEG-PEN-R5-011: namespace creation through clone must be denied
    /// like unshare is.
    #[test]
    fn denies_clone_with_new_namespace_flags() {
        let r = run_after_apply(|| {
            [
                libc::CLONE_NEWUSER,
                libc::CLONE_NEWNET,
                libc::CLONE_NEWNS,
                libc::CLONE_NEWPID,
            ]
            .into_iter()
            .all(|f| denied(raw_clone(f as libc::c_long)))
        });
        match r {
            Some(true) => {}
            Some(false) => panic!("clone with a CLONE_NEW* flag was not denied"),
            None => eprintln!("skipping: seccomp could not be installed in this environment"),
        }
    }

    /// clone3 passes its flags in memory the filter cannot read, so it
    /// is refused as unsupported; libc and std then fall back to clone.
    #[test]
    fn clone3_reports_enosys() {
        let r = run_after_apply(|| {
            let mut args = [0u64; 11];
            args[0] = libc::CLONE_NEWUSER as u64;
            args[4] = libc::SIGCHLD as u64;
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_clone3,
                    args.as_mut_ptr(),
                    std::mem::size_of_val(&args),
                )
            };
            if rc == 0 {
                unsafe { libc::_exit(0) };
            }
            rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS)
        });
        match r {
            Some(true) => {}
            Some(false) => panic!("clone3 was not refused with ENOSYS"),
            None => eprintln!("skipping: seccomp could not be installed in this environment"),
        }
    }

    #[test]
    fn plain_fork_still_works() {
        let r = run_after_apply(|| raw_clone(0) > 0);
        match r {
            Some(true) => {}
            Some(false) => panic!("a plain fork was blocked — clone rule too broad"),
            None => eprintln!("skipping: seccomp could not be installed in this environment"),
        }
    }

    #[test]
    fn allows_unlisted_syscall() {
        // getpid is not on the denylist; the default action is Allow.
        let r = run_after_apply(|| unsafe { libc::syscall(libc::SYS_getpid) } > 0);
        match r {
            Some(true) => {}
            Some(false) => panic!("an unlisted syscall (getpid) was blocked — filter too broad"),
            None => eprintln!("skipping: seccomp could not be installed in this environment"),
        }
    }
}
