# Denyx Security Audit — Bypass Assessment

> ← [Back to docs README](README.md)

This document records a deliberate, hostile-eyes review of every way
an agent script running under Denyx could subvert a policy that
the operator wrote in good faith. The assessment was triggered by
finding the **subprocess argv-bypass** (where `subprocess.exec(["cat",
"/etc/passwd"])` could reach files the policy denied for `fs.read`)
— after fixing that, we did a full sweep to find anything else of
the same shape.

The methodology is simple: walk every effecting builtin and every
runtime layer, ask "what does an adversarial agent with full
knowledge of the policy do here", and either confirm safety or
record a finding.

## Status legend

- **✅ Verified safe** — reviewed, no bypass path found.
- **🔧 Real bug, fixed** — bypass identified, fix landed in this
  iteration (each gets its own commit).
- **📖 Documented limitation** — known gap, can't or won't fix at
  the runtime layer; documented honestly so operators know where
  the boundary is.

---

## Findings summary

| # | Surface | Status | Fix commit |
|---|---|---|---|
| 1 | `subprocess.exec` argv reaching denied paths | 🔧 Fixed (prior commit) | `9e53bf0` |
| 2 | `subprocess.exec` shell-evaluator / inline-interpreter bypass | 🔧 Fixed (`bwrap` sandbox + tightened defaults) | `b096596` |
| 3 | `fs.read` / `fs.write` / `fs.delete` not canonicalizing symlinks | 🔧 Fixed in this audit | (this audit) |
| 4 | `net.http_*` follows redirects without re-checking the new URL | 🔧 Fixed in this audit | (this audit) |
| 5 | Starlark error messages can leak tainted values past the redaction boundary | 🔧 Fixed in this audit | (this audit) |
| 6 | URL parsing tricks (userinfo, fragments) | ✅ Safe — `url` crate parses correctly |  |
| 7 | Path traversal via `..` from policy root | ✅ Safe — allow patterns are root-anchored |  |
| 8 | Raw `_denyx_*` builtin name access | ✅ Safe — verifier rejects, runtime gate fires anyway |  |
| 9 | Starlark struct monkey-patching (`fs = struct(read=fake)`) | ✅ Safe — doesn't grant new powers |  |
| 10 | Reflection / `dir(globals())` exposure of internals | ✅ Safe — Starlark has no reflection over Rust-side `Evaluator::extra` |  |
| 11 | Env reads via name-only check | ✅ Safe — no path resolution involved |  |
| 12 | TOCTOU between policy check and operation (single-script) | ✅ Safe — Denyx evaluation is single-threaded |  |
| 13 | Audit log floods | 📖 Bounded by `[runtime].max_seconds` |  |
| 14 | Pure-CPU busy loops | 📖 Documented limitation; container is the answer |  |
| 15 | Unicode normalization (path/URL) | 📖 Operator's responsibility — patterns must match the byte form they expect |  |
| 16 | DNS rebinding (hostname re-resolves between check and connect) | 📖 Documented; resolved-IP pinning is future work |  |

Three real bugs found during this audit. Each is fixed in a
focused commit; each has a regression test pinning the closure.

---

## Detail per surface

### 1. `subprocess.exec` argv reaching denied paths — fixed earlier

Before the fix: `subprocess.exec(["cat", "/etc/passwd"])` succeeded
because the OS opens the file in the child, where Denyx has no
visibility. The script's own `fs.read("/etc/passwd")` would
correctly be denied; the agent could route around the gate by
going through any file-touching binary.

Fix: `Policy::check_subprocess_argv_paths` walks every argv element
that looks like a path (absolute, tilde, contains `/`, or names an
existing file at the policy root) and checks it against the same
`[filesystem]` rules as fs.read. Rejects on deny match or no allow
match. See commit `9e53bf0`.

### 2. Shell-evaluator / inline-interpreter bypass — fixed by sandbox

The argv path-gate from #1 catches paths that appear *as separate
argv elements*. It cannot catch paths constructed inside an inline
interpreter string: `python3 -c "open(chr(47)+'etc'+chr(47)+'passwd').read()"`
contains no literal `/`, the path is computed at runtime, and Denyx
has no visibility into the Python heap.

Fix: opt-in `[subprocess].sandbox = "bwrap"` mode wraps every call
with bubblewrap, which constructs a Linux-namespace bind-mount jail
per call. The child's filesystem view is exactly what the policy
permits — paths outside the bind layout don't exist for the child,
no matter what obfuscation the interpreter uses. See commit
`b096596`. Plus the secure-defaults preset will deny shell evaluators
and inline interpreters by default in a follow-up commit so even
operators who don't enable the sandbox aren't trivially bypassed.

### 3. Symlink resolution in `fs.*` — fixed in this audit

**Found**: `resolve_path` normalizes `..` / `.` components but does
not call `canonicalize`, so symlinks are not resolved before the
policy check. A symlink at `<policy_root>/src/secret` pointing to
`/etc/passwd` would let the agent read `/etc/passwd` via
`fs.read("src/secret")` — the path matches `read_allow = ["src/**"]`,
the policy says yes, then `std::fs::read_to_string` follows the
symlink and reads the target.

Same shape for `fs.write` and `fs.delete` — a symlink-replace pattern
lets the agent reach files outside `write_allow` / `delete_allow`.

**Fix**: every fs builtin canonicalizes the path (resolving symlinks
at every component) BEFORE running the policy check. For `fs.write`
of a path that doesn't yet exist, the parent directory is
canonicalized and the leaf name is appended; the canonical full path
is what gets checked. If canonicalization fails (the path or any
ancestor doesn't exist for a read/delete), the operation fails before
the policy check ever runs.

### 4. HTTP redirects not re-checked — fixed in this audit

**Found**: `ureq` follows up to 5 redirects by default. After the
initial URL check passes, a 302 to `http://10.0.0.1/` is followed
without Denyx re-running the host / IP check on the new URL. An
allowed origin server can hand the agent any internal URL it likes.

**Fix**: configure ureq's agent with `redirects(0)`. Denyx no longer
auto-follows. If the script wants to follow a redirect, it has to
read the `Location` header from the response and call `net.http_get`
again — at which point the policy check fires on the new URL.
Documented as the deliberate trade-off: HTTP semantics still work,
but every hop is a separate gated call.

### 5. Tainted values in Starlark error messages — fixed in this audit

**Found**: `outcome.printed` is scrubbed for taint via the redaction
registry, and audit-event payloads are scrubbed at emit time. But
the **Starlark error path** is not. A script that does
`secret = env.read("OPENAI_API_KEY"); fail(secret)` raises a
Starlark error whose message contains the secret. That message
flows out through `DenyxError::Starlark(msg)` to the caller — and
in the CLI, lands on stderr. Same for any error whose rendering
happens to include a value derived from a tainted source.

**Fix**: `Runner::run` scrubs `starlark_msg` and any captured
error message through `redact()` against the taint registry before
constructing the `DenyxError`. The error path now respects the same
boundary as the printed-line path.

### 6-16. Verified safe / documented limitations

**6. URL parsing.** `url::Url::parse("https://allowed.com#@evil.com/")`
correctly returns `host = allowed.com` (the `#` is fragment
delimiter, the rest is fragment, not host). `https://a@b.com/` →
host = `b.com`, userinfo doesn't shift the host. The crate handles
the obvious tricks; operator's responsibility for IDN homograph
attacks (`а.com` cyrillic vs `a.com`).

**7. Path traversal `..`.** `resolve_path` does normalize `..`
which CAN escape the policy root. But allow patterns are
root-anchored (`src/**` translates to `<root>/**/src/**`), so a
resolved path of `/etc/passwd` won't match. Net effect: the escape
exists but the policy-check still rejects. Tested.

**8. Raw `_denyx_*` builtin names.** The pre-execution verifier
strips strings/comments and word-boundary-scans for any registered
capability name (both dotted `fs.read` and underscored
`_denyx_fs_read`). Calling a raw name still goes through the same
runtime gate. Aliasing (`r = _denyx_fs_read; r(...)`) trips the
verifier (`_denyx_fs_read` is a token in the source).

**9. Struct monkey-patching.** `fs = struct(read = lambda: "fake")`
replaces the prelude's binding in the script's local scope. This
doesn't *grant* new capabilities — the script's monkey-patched
`fs.read` is just a lambda that returns "fake". To call the real
gated builtin under a different binding, the script has to
reference `_denyx_fs_read` (caught by the verifier) or pass the
function value through a chain — and at every actual invocation,
the runtime gate fires.

**10. Reflection.** Starlark's `Dialect::Standard` exposes a small
set of builtins. There is no `globals()` / `locals()` /
`__builtins__` / `__import__` / `dir(<module>)` reflection over the
Rust-side `Evaluator::extra` (where `HostCtx` lives). The pointer
is opaque to script.

**11. Env reads.** Name-only allow/deny check; no path resolution.
`env.read("PATH")` returns the env value as a Starlark string.
Subject to the local-only-vars taint mechanism (already audited).

**12. TOCTOU.** Denyx evaluation is single-threaded inside one run.
A fs.read at time T returns content as of T; nothing in the same
script can race with itself. Cross-run TOCTOU exists (an agent run
reads a path, a later run sees a swapped path) but that's a
property of the filesystem, not Denyx.

**13. Audit log floods.** Each effecting call emits one event. A
script that calls `fs.read` in a tight loop could grow the log
fast. Bounded by `[runtime].max_seconds`. Without a deadline, an
operator who doesn't want the flood should either set the deadline
or rotate/cap the log file.

**14. Pure-CPU busy loops.** `while True: x = 1` inside a `def`.
No I/O, no capability calls, so the deadline check at builtin
entry doesn't fire. Starlark has no public per-statement abort
hook in 0.13. Documented in
[04-policy-file.md](04-policy-file.md#runtime). For total
isolation, run inside a container.

**15. Unicode normalization.** Different byte sequences for
visually-identical paths (NFC vs NFD on macOS HFS+, IDN homograph
in URLs). Denyx matches against the byte sequence the policy
provides. Operators who care about Unicode confusion need to
normalize their patterns themselves.

**16. DNS rebinding.** `evil.example.com` resolves to `1.2.3.4` at
policy-check time, then to `10.0.0.1` at connect time. ureq doesn't
expose resolved-IP pinning. Documented as a known limitation;
fully closing this requires either a custom resolver or the
agent-runtime layer pinning the resolved IP.

---

## Methodology notes

For future audits or external review:

- **Walk every effecting builtin top-down** in `crates/host/src/lib.rs:register_builtins`. For each, ask: what argument shapes are checked, what shapes aren't, what happens on the side of the underlying syscall after the check.
- **Walk every output boundary** for taint coverage: `outcome.printed` (scrubbed), `AuditEvent` payloads at emit (scrubbed), MCP tool result text (joined from outcome.printed, so transitively scrubbed), DenyxError messages on the error path (NOW scrubbed after fix #5), Starlark stack traces (subject to the same fix).
- **Walk every external library** for behavior the policy can't see: `url::Url::parse` parsing semantics, `ureq` redirect behavior (now disabled), `globset` matching semantics, `std::fs` symlink behavior (now canonicalized).
- **Walk every Starlark surface** for reflection or escape: `LibraryExtension` enables (Print, StructType, NamespaceType, Json, Map, Filter, Debug). None expose `Evaluator::extra` or arbitrary FS/network/exec.
- **Build adversarial test cases**, not just happy-path tests: a test for "this attack is blocked" carries more value than ten tests for "this legitimate use works".
