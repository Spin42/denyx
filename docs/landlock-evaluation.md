# Landlock evaluation — `[subprocess].sandbox = "landlock"`

> ← [Back to docs README](README.md) · [Policy file: subprocess is a privilege boundary](06-policy-file.md#subprocess-is-a-privilege-boundary)

## Why this exists

`[subprocess].sandbox = "bwrap"` is Denyx's only OS-level isolation for
a spawned child (as opposed to the language-runtime argv path-gate,
which is always active). Bubblewrap requires unprivileged user
namespaces, which some containers and hardened kernel configurations
disable even when the kernel version itself is new enough — see
`crates/host/tests/sandbox_bwrap.rs`'s `bwrap_works()`, which probes
for exactly this failure mode rather than trusting `bwrap --version`.
On a host where bwrap is installed but non-functional, an operator who
set `sandbox = "bwrap"` expecting isolation got a hard load-time
refusal (the right failure mode) but no alternative OS-level backend.

[Landlock](https://landlock.io) (Linux 5.13+, an unprivileged LSM —
no user namespaces, no external binary, no elevated capabilities
required) is a second backend for exactly that gap. It was mentioned
once in this project's docs before this evaluation, as a competitor
feature (`docs/comparison.md`), never assessed for Denyx itself.

## What Landlock provides here

Implemented in `crates/host/src/landlock_sandbox.rs`. Applied via
`std::process::Command::pre_exec` in the forked child, calling
`landlock_restrict_self` on itself before `exec()` — no wrapper
process, unlike bwrap.

- **Filesystem access scoped to the policy's allow lists** plus a
  minimal set of system paths needed to exec at all (the same list
  `bwrap_argv` uses for `--ro-bind-try`, individually-named files
  under `/etc` rather than the whole directory — see the module's
  `SYSTEM_DIRS_READONLY` doc comment for why).
- **TCP bind/connect denied entirely when the policy grants no network
  capability** (mirrors bwrap's `--unshare-net` — total denial, not a
  port allow-list), on kernels supporting Landlock ABI v4 (Linux
  6.7+). Uses `denyx_policy::Policy::any_network_capability_granted`,
  the exact same condition `bwrap_argv` already used, extracted to a
  shared method rather than re-derived a third time (see the Phase 3
  wasm/native parity review for why re-deriving the same condition
  independently is exactly the class of bug that produces silent
  divergence).

Both properties were verified against a real running kernel (Linux
7.0.11, this development environment), not just unit-tested against
mocked syscalls — `crates/host/src/landlock_sandbox.rs`'s test module
forks a real child, applies real restrictions, and probes real file
opens and a real loopback TCP connect from inside that child,
asserting the actual kernel-enforced outcome.

## What Landlock does NOT provide (unlike bwrap)

- **No PID/UTS/IPC namespace isolation.** The child can still see
  other processes on the system (though not necessarily touch them,
  if procfs access is itself restricted by the filesystem ruleset).
  Bwrap's `--unshare-pid/uts/ipc` has no Landlock equivalent.
- **No reconstructed filesystem view.** The real directory tree is
  still there. Landlock denies *access* to paths outside the ruleset;
  it doesn't hide their existence the way an unmounted bind-mount jail
  does. `stat()` on a denied path can succeed in some cases even
  though `open()` fails.
- **No UDP or non-TCP network restriction.** Landlock's network hooks,
  as of the ABI version this module targets (v4), cover TCP bind/
  connect only.
- **No `--die-with-parent` equivalent.** A Landlock-restricted child
  that outlives its parent is still just a normal orphaned process,
  same as any unsandboxed one.

Landlock and bwrap are **complementary, not competing**. Prefer
Landlock when bwrap's unprivileged user-namespace requirement isn't
available but Landlock is (see the container/hardened-kernel case
above); prefer bwrap when the stronger namespace isolation matters and
the environment supports it. Both remain narrower than a real VM/
container boundary for an operator whose threat model includes kernel
exploits — see `docs/04-security-threat-model.md`'s "OS-level kernel
bugs / sandbox escape" bullet, which applies to both backends equally.

## Real friction found while implementing this

Documented here rather than silently smoothed over, per this project's
practice of recording what was actually tested, including the
mistakes:

- **An initial `/dev` grant was read-only, which broke ordinary
  commands.** `git` and `ssh` both open `/dev/null` with `O_RDWR` for
  routine redirection; Landlock enforces the exact access mode
  requested per path (unlike bwrap's `--dev /dev` mount, which sets up
  a fresh, uniformly-permissive pseudo-filesystem). Fixed by granting
  `/dev` read-write in the system-path baseline
  (`SYSTEM_DIRS_READWRITE`) rather than folding it into the read-only
  list.
- **A blanket `/etc` grant would have been over-broad.** The natural
  first instinct — grant the whole `/etc` directory for "system
  config" — would include `/etc/passwd`, `/etc/shadow`, and similar,
  which neither Denyx backend intends to expose just so the dynamic
  linker and DNS resolution work. Individual files, matching
  `bwrap_argv`'s existing list, avoid this.
- **Real-world commands (`git`, in particular) touch more ambient
  files than the minimal system-path baseline anticipates** (e.g.
  `/etc/gitconfig`). This is not Landlock-specific — bwrap's identical
  minimal baseline has the same friction (its own end-to-end tests hit
  an analogous gap with `ssh` needing `/etc/passwd` to resolve a
  username, documented in `docs/security-pentest-r4-wasm-path-regressions.md`'s
  live reproducers). Both backends trade "some ordinary commands need
  a wider baseline than the minimal one provides" for "the baseline
  stays small and auditable." This is an inherent property of minimal
  system sandboxing, not a defect unique to either implementation.

## Verification

- `crates/policy/src/landlock_probe.rs`: a cheap, no-fork availability
  check (`Ruleset::create()` under `CompatLevel::HardRequirement`,
  which surfaces "kernel too old / feature disabled" as an error
  without ever restricting the calling process — `restrict_self()` is
  never called by the probe). Wired into
  `Policy::guard_sandbox_available`, so a policy with
  `sandbox = "landlock"` refuses to load on a kernel that can't
  support it, same posture as the `bwrap`-on-PATH check.
- `crates/host/src/landlock_sandbox.rs`'s test module: 6 tests forking
  a real child and asserting real kernel-enforced outcomes — read
  outside/inside granted paths, write to a read-only vs. write-granted
  path, and TCP connect denied/allowed depending on `deny_network`.
  All skip cleanly (not fail) when the kernel doesn't support the
  relevant Landlock ABI version, mirroring `sandbox_bwrap.rs`'s
  `bwrap_works()` skip-clean convention for restricted environments.
- Full workspace test suite and `./scripts/precommit.sh` clean after
  this work landed.

## What was NOT done in this evaluation

- **No `denyx doctor` check for Landlock specifically.** Unlike the
  `LocalExecutorNotIsolated`-style silent-gap checks elsewhere in this
  project, there's no equivalent needed here: `guard_sandbox_available`
  already fails policy *load* (not just a doctor warning) when
  `sandbox = "landlock"` is set on a kernel that can't support it — the
  same hard-refusal posture bwrap already has, not a softer diagnostic.
- **No automatic backend selection.** An operator must explicitly
  choose `sandbox = "bwrap"` or `sandbox = "landlock"`; Denyx does not
  probe both and pick whichever works. This mirrors the existing
  bwrap-only design (no "try landlock, fall back to none" auto-
  detection either) and avoids a policy's effective security
  properties silently depending on which backend happened to be
  available on a given host.
- **No macOS/Windows Landlock support**, because Landlock is a Linux
  kernel feature — this doesn't reopen the sandbox-exec/AppContainer
  question already closed in `docs/macos-deployment.md` and
  `docs/windows-deployment.md`; the recommended path on those
  platforms remains a Linux VM (Lima/WSL2) with either bwrap or
  Landlock available inside it.
