# Denyx Security Threat Model

> ← [Back to docs README](README.md)

This is the one-page review companion. If you're a security engineer
sitting down with the codebase for the first time, **read this first**
— it lists exactly what Denyx claims to defend against, what it
explicitly does *not* defend against, and where the trust boundaries
sit. Everything below is what you should hold the implementation
accountable to.

For the systematic post-implementation bypass review, see
[security-audit.md](security-audit.md). For the AI-driven adversarial
pentest against the IFC layer specifically (Sonnet + Opus, with risk
ratings and closure verification), see
[security-pentest-report.md](security-pentest-report.md). For the
policy file reference, see [06-policy-file.md](06-policy-file.md).

## What Denyx is

A Rust runtime that runs Starlark agent code under a TOML-declared
policy. Three crates do the work: `denyx-policy` parses and resolves
the policy; `denyx-host` embeds Starlark and enforces the policy at
every effecting builtin (`fs.*`, `net.*`, `subprocess.exec`,
`env.read`); `denyx-mcp` exposes the same enforcement over JSON-RPC
to MCP-aware orchestrators. There is no plugin model and no dynamic
policy: every effect goes through one of nine Rust functions, all in
`crates/host/src/`.

`denyx-host` ships with two interchangeable runners. The default
`WasmRunner` (selected by `denyx run` / `denyx-mcp` in v0.4.0+; pass
`--no-wasm` to opt out) loads the `starlark-rust` interpreter compiled
to `wasm32-wasip1` from `denyx-runtime-starlark` and runs it under
`wasmtime` — the Starlark interpreter executes inside a wasmtime
sandbox, with fuel-based preemption and interpreter-bug containment
as additional layers over the shared policy gate. The legacy
in-process `Runner` evaluates the same `starlark-rust` interpreter
directly in the host process, with no sandbox around the interpreter
itself. The policy gate stays in Rust on the host side on both paths
— every effecting call goes through the same `Policy::check_*`
machinery. See [wasm-sandbox.md](wasm-sandbox.md) for the parity
table, the new attack surface wasmtime introduces, and the pentest
result on the wasm path.

## What it defends against

| Threat | How |
|--------|-----|
| **Prompt-injection telling the agent to run a destructive command** | The script can only call namespaced builtins, each gated against the policy in Rust before any side effect. A natural-language prompt cannot reach `os.system`, `subprocess.Popen`, or `eval` because the language has none of them. |
| **Agent reading credentials it has no business reading** | `[filesystem].deny` (e.g. `**/.env*`, `~/.aws/**`) and `[environment].deny_vars` (e.g. `AWS_SECRET_ACCESS_KEY`) fail the call at the Rust gate. `secure-defaults` ships with a curated baseline of these. |
| **Agent exfiltrating local-only secrets to a cloud orchestrator via printed output** | `[environment].local_only_vars`, `[filesystem].local_only_read`, `[network].local_only_hosts`, and `[subprocess].local_only_commands` mark values as tainted. Enforcement runs in two layers: a pre-execution verifier check refuses scripts whose literal-argument `env.read`/`fs.read` of a local-only value is paired with an output-producing call; the runtime IFC scrubs values that flow through variable-argument reads against a documented transform set (reverse, hex, single-byte XOR + hex(XOR), base64 std + url-safe ± padding, ROT-1..25) plus a chunking detector, and refuses tainted bytes at every outbound argument (`fs.write`, `fs.delete`, `net.http_*`, `subprocess.exec` to non-local-only commands). The transform set is finite by intent. **Limited — see "Known limitations" below.** |
| **Agent spawning a shell to escape the policy** (`subprocess.exec(["bash", "-c", "cat /etc/passwd"])`) | `secure-defaults` denies shells, interpreters, and generic command runners (`bash`, `sh`, `python`, `node`, `ruby`, `env`, `xargs`, ...). Argv path-arguments to allowed commands are also checked against `[filesystem]` rules — `subprocess.exec(["cat", "/etc/passwd"])` is rejected. |
| **Agent following an HTTP redirect to a denied host** | `net.http_*` does not auto-follow 3xx; the call returns a typed error and the script must re-issue against the new URL (which gets gated again). |
| **Agent reading a denied path via a symlink the operator allowed** | `fs.*` canonicalize paths before the policy check; the symlink target — not the symlink itself — is what the policy sees. |
| **Agent modifying its own policy or audit log** | `Policy::guard_audit_log` and the self-writable guard refuse to start if the policy file or audit log is reachable to the agent under any of `write_allow` / `delete_allow`. |
| **Audit log tampering after the fact** | Each line carries a SHA-256 chain (`denyx_seq` + `denyx_prev_hash`); `denyx audit verify` detects in-place mutations, line removals, and seq jumps. |
| **MCP tool definition poisoning reaching the cloud orchestrator (local-executor deployment)** | In the `denyx-local-mcp` architecture the cloud orchestrator's MCP tool list contains only `delegate_to_local`, so other servers' tool descriptions cannot reach its context — **provided** the host is launched with `--strict-mcp-config` (or equivalent) and denyx-local-mcp is the only MCP server configured. This is a precondition on operator setup, not enforced by Denyx itself. The local executor model receives tool routing metadata only from the operator-controlled policy file. See [Round 2 pentest report](security-pentest-r2-tool-poisoning.md). |
| **Reads of resources the policy doesn't mention** | Default-deny: `fs.read` of a path not in `read_allow` or `local_only_read` returns `PolicyError::PathDenied`; `env.read` of a name not in `allow_vars` or `local_only_vars` returns `PolicyError::EnvDenied`; `subprocess.exec` of a command not in `allow_commands` or `local_only_commands` returns `PolicyError::SubprocessDenied`. **Operator caveat:** a too-broad rooted glob in `read_allow` (e.g. `["**"]` or `["/tmp/**"]`) silently defeats the property. Narrow allow-lists are the operator's responsibility. |
| **Pure-CPU runaway in the agent script** *(wasm path only — default in v0.4.0+, opt out with `--no-wasm`)* | wasmtime fuel budget (`DEFAULT_WASM_FUEL = 200_000_000`) traps `for _ in range(10**9): pass` within ~1 sec of CPU as `DenyxError::RuntimeLimit` (exit 6). The in-process runner has no equivalent — `[runtime].max_seconds` is wall-time, not instruction count, so it doesn't catch pure-CPU loops that finish before the deadline. This is a wasm-path-only addition. |
| **Interpreter bugs reaching host memory** *(wasm path only — default in v0.4.0+, opt out with `--no-wasm`)* | `starlark-rust` runs inside `wasmtime`'s linear-memory sandbox. A miscompilation or memory-safety bug in the interpreter stays inside the wasm boundary instead of corrupting the host. Empirically validated under adversarial workload in the Round 2 v5 pentest (one WASM_TRAP fire — Opus's quadratic string-concat caused the Starlark interpreter to `process::abort` inside the wasm guest; the sandbox contained the abort cleanly). **Defence-in-depth, not a primary control** — the interpreter is a maintained dependency, not a known-hostile component. |

## What it does NOT defend against

Read these honestly. **Each is a real gap, not a hypothetical.**

- **Information-flow tracking is finite-transform, not full IFC.**
  The local-only enforcement covers a documented set of
  substring-detectable transforms (original bytes, byte-reverse,
  hex lower/upper of original and reverse, XOR with each single-
  byte key including hex-encoded XOR results) plus subsequence-
  chunking detection on joined output, plus arg-side denial at
  every outbound effect. This catches every full-secret bypass
  the adversarial probe currently knows about — but it cannot
  catch **a transform with a script-generated key** (AES, RC4,
  a custom invertible permutation): the redactor doesn't know
  the key, so the ciphertext doesn't match any pre-computed
  pattern. Closing that gap requires real value-level taint
  propagation through Starlark's evaluator, which would be
  intrusive to the upstream `starlark-rust` crate. Operators
  whose threat model includes scripts running their own crypto
  should not rely on `local_only_*` for that adversary class.
  Empirical: the exfil probe in
  [examples/local_executor/run_exfil.py](../examples/local_executor/run_exfil.py)
  runs 12 hand-written attack scripts and currently records
  **0 LEAK / 3 WEAK_LEAK / 9 REDACTED**. Every full-secret
  exfil shape in the probe (raw print, byte-reverse, hex,
  XOR + hex, per-char chunking, `fs.write` to a host-readable
  path, `subprocess.exec` argv to a non-local-only command,
  `fail()` with a mutated form) is now caught — either at the
  output boundary (transform-aware scrub or chunking detection)
  or at the arg-side gate (refused before any bytes leave the
  runtime). The 3 remaining WEAK_LEAK side-channels are
  inherent non-byte channels: `len(secret)`, single-character
  comparison oracle (`secret[0] == "s"`), and substring-guess
  oracle (`"MNOP" in secret`). Each reveals at most O(log L)
  bits per query; defeating them requires forbidding `len()`,
  comparison, and `in` on tainted values, which would break
  every legitimate use of a secret as a string.
- **MCP tool definition poisoning (direct `denyx-mcp` deployment).** When
  `denyx-mcp` is configured as one MCP server among several, the cloud model
  reads all co-installed servers' tool descriptions directly — before Denyx
  is in the picture. A malicious description can manipulate the model's
  reasoning; Denyx's gate still fires on the resulting *actions*, but the
  reasoning-layer manipulation is not detected or prevented. Use the
  `denyx-local-mcp` local-executor architecture when MCP tool poisoning is
  in your threat model: the cloud model only sees `delegate_to_local` and
  the local model only sees policy-file routing hints.
- **Prompt injection at the local executor's LLM layer.** The step text
  reaching `delegate_to_local` is treated as untrusted by the system
  prompt and wrapped in `<task>…</task>` delimiters, but on the four
  local code models we tested (qwen2.5-coder 7B/14B, phi4-14B,
  codestral-22B), these wrappers did not measurably reduce obedience to
  injected instructions — the model emits Starlark that does whatever
  the injection asks. The defenses that actually catch the resulting
  effects are the IFC + capability gate + arg-side gate, which work on
  the emitted script's runtime behaviour, not on the LLM's reasoning.
  Operators whose threat model assumes the LLM-side wrappers stop
  injection should not rely on that assumption. See
  [Round 2 pentest report](security-pentest-r2-tool-poisoning.md).
- **Pure-CPU denial-of-service inside the script (in-process runner
  only).** `[runtime].max_seconds` bounds wall time, but during that
  window an agent can busy-loop or allocate freely on the in-process
  runner — wall-time deadlines don't catch pure-CPU loops. The
  WasmRunner closes this via fuel preemption (see the row in the
  defends-against table); on the in-process runner it remains a gap.
  Fork-bomb-class subprocess exhaustion is a separate concern handled
  by the optional `[subprocess].sandbox = "bwrap"` layer on Linux, or
  by running inside a container/VM.
- **OS-level subprocess sandboxing is opt-in and addresses a different
  threat from the wasm sandbox.** The WasmRunner contains the Starlark
  interpreter — a runtime bug in the interpreter, or a runaway
  pure-CPU loop, stays inside the wasmtime guest. It does **not**
  isolate subprocesses the script spawns: a permitted `python3` runs
  as a normal child of the host process, bounded only by the policy's
  argv path-gate and `subprocess.deny_args`. For OS-level subprocess
  isolation (kernel namespaces, fresh bind-mount layout per call),
  enable `[subprocess].sandbox = "bwrap"` on Linux or run inside the
  recommended VM on macOS / Windows. The wasm sandbox and bwrap are
  not substitutes — they protect different boundaries. See the
  [policy-file `[subprocess]` section](06-policy-file.md#subprocess)
  for the bwrap layer's properties.
- **OS-level kernel bugs / sandbox escape.** Denyx is a *language-runtime*
  gate. Even with `[subprocess].sandbox = "bwrap"`, a kernel-level
  exploit defeats it. Run inside a VM if you care about kernel
  exploits.
- **DNS rebinding.** Hostname-allowlist checks happen against a
  resolved IP, but a malicious resolver can return a different IP
  on the next lookup the OS does. Resolved-IP pinning is future
  work.
- **Unicode normalization tricks in paths/URLs.** Operators must
  write patterns matching the byte form they expect; we don't
  normalize NFC/NFD on either side of the match.
- **AI-generated code review.** Almost all of this codebase was
  written by Claude. The architectural decisions are human; the
  implementation is not. This is the single biggest reason for
  this doc — please read with hostile eyes.
- **wasmtime bugs on the wasm path** (default in v0.4.0+). The wasm runner
  introduces wasmtime as a dependency. wasmtime is widely-used and
  security-audited, but past CVEs have hit its SIMD bounds checks,
  JIT codegen, and WASI implementation. A wasmtime exploit
  defeats the sandbox boundary the `WasmRunner` relies on for
  interpreter-bug containment — though the Policy gate stays in
  Rust on the host side, so the gate itself is unaffected.
  See [wasm-sandbox.md](wasm-sandbox.md#new-attack-surface) for
  the full surface accounting.

## Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ Untrusted: Starlark script (whatever the agent emits)       │
│  - Has no `import`, `open`, `os`, `sys`, `__import__`       │
│  - Can ONLY reach effects via fs.*, net.*, subprocess.*,    │
│    env.* — every other effect path was never there          │
└──────────────────┬──────────────────────────────────────────┘
                   │ each call
┌──────────────────▼──────────────────────────────────────────┐
│ Trusted: Rust capability builtins (crates/host/src/lib.rs)  │
│  - Look up Policy → make decision → audit → side-effect     │
│  - Taint values returned from local_only_* sources          │
│  - Scrub printed output / audit / errors at boundary        │
└──────────────────┬──────────────────────────────────────────┘
                   │ policy queries
┌──────────────────▼──────────────────────────────────────────┐
│ Trusted: Policy (parsed from operator-controlled TOML)      │
│  - Single source of truth for what's allowed                │
│  - Default-deny: undeclared resource = no effect            │
│  - Operator (not agent) writes this                         │
└─────────────────────────────────────────────────────────────┘
```

The boundary that matters: the agent never sees Rust function names,
never sees the policy struct, never sees `Evaluator::extra`. It sees
nine namespaced functions. If those nine functions enforce correctly,
the agent has no other surface.

## Assumptions

- **Policy file is operator-controlled.** Denyx treats the policy
  as ground truth. If the agent can edit the policy, the policy is
  worthless — that's why `Policy::guard_self_writable` refuses to
  start with a policy that grants write/delete on itself.
- **Single-threaded evaluation.** No TOCTOU between policy check
  and operation within one script — the evaluator is single-threaded.
  Two concurrent `denyx run` invocations against shared state are
  the operator's problem, not Denyx's.
- **Filesystem rooted at the policy file.** Relative patterns
  (`src/**`) anchor at the policy-file directory, not the CWD.
  Operators don't need to leak their machine's directory structure
  into the policy.
- **Network policy is hostname-first.** Most policies match on
  hostname; `[network].deny_ips` is a CIDR-aware second layer for
  IMDS / RFC1918 SSRF protection.

## Where to look in the code

If you're reviewing with hostile intent, these are the highest-value
files:

- `crates/policy/src/lib.rs` — every policy decision routes through
  here. Read `check_*` functions and the matchers
  (`PathMatcher`, `HostMatcher`, `IpNet` parsing).
- `crates/host/src/lib.rs` — every effecting builtin. Look for the
  pattern: pre-check, policy query, audit, side-effect, taint-on-return.
- `crates/host/src/taint.rs` — `TaintRegistry`, transform
  computation (reverse, hex of original/reverse, XOR + hex(XOR)
  compositions), `redact_lines` (substring scrub + chunking
  detection), and `arg_taint_reason` (the arg-side oracle every
  outbound builtin queries before performing the effect).
  **Confirm for yourself that the documented transform set
  actually matches the cases the exfil probe exercises, and
  identify any practical transform we're missing.**
- `crates/host/src/verifier.rs` — pre-execution AST scan. The
  defence-in-depth layer that rejects scripts referencing
  capabilities whose resource section is empty before evaluation.
- `crates/host/src/audit.rs` — the SHA-256 chain.

## Where this doc fits

| Doc | Purpose |
|-----|---------|
| **This doc** (`04-security-threat-model.md`) | What Denyx claims to defend; what it doesn't. Read first. |
| [security-audit.md](security-audit.md) | The 16-surface bypass assessment that triggered the recent security work. Findings + fixes. |
| [security-pentest-report.md](security-pentest-report.md) | Round-1 AI-driven pentest report (Sonnet + Opus). Two High findings (base64, ROT-N), both remediated and closure-verified. Methodology + scope + residual risk. |
| [06-policy-file.md](06-policy-file.md) | Policy file reference (operator-facing). |
| [wasm-sandbox.md](wasm-sandbox.md) | What the wasm runner adds (default in v0.4.0+; opt out with `--no-wasm`), what it doesn't change, what's still open. |
| [03-architecture.md](03-architecture.md) | How the runtime is structured (developer-facing). |
| [examples/local_executor/run_exfil.py](../examples/local_executor/run_exfil.py) | The adversarial exfiltration probe — runs hand-written Starlark that *tries* to leak `local_only_var` values. Empirical version of the "what we don't defend against" list. |
