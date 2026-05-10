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

## What it defends against

| Threat | How |
|--------|-----|
| **Prompt-injection telling the agent to run a destructive command** | The script can only call namespaced builtins, each gated against the policy in Rust before any side effect. A natural-language prompt cannot reach `os.system`, `subprocess.Popen`, or `eval` because the language has none of them. |
| **Agent reading credentials it has no business reading** | `[filesystem].deny` (e.g. `**/.env*`, `~/.aws/**`) and `[environment].deny_vars` (e.g. `AWS_SECRET_ACCESS_KEY`) fail the call at the Rust gate. `secure-defaults` ships with a curated baseline of these. |
| **Agent exfiltrating local-only secrets to a cloud orchestrator via printed output** | `[environment].local_only_vars`, `[filesystem].local_only_read`, `[network].local_only_hosts`, and `[subprocess].local_only_commands` mark values as tainted. The runtime then enforces three layers at the boundary: (1) substring scrub against the value AND the documented transform set (reverse, hex lower/upper, XOR with each single-byte key, hex(XOR) compositions); (2) subsequence-chunking detection on the joined printed output (catches per-character prints interleaved with cover text); (3) arg-side denial at every outbound effect (`fs.write`, `fs.delete`, `subprocess.exec` to non-local-only commands, `net.http_*` to non-local-only hosts) — the call is *refused* with a typed error if any string argument carries tainted bytes in any covered form. **Limited — see "Known limitations" below.** |
| **Agent spawning a shell to escape the policy** (`subprocess.exec(["bash", "-c", "cat /etc/passwd"])`) | `secure-defaults` denies shells, interpreters, and generic command runners (`bash`, `sh`, `python`, `node`, `ruby`, `env`, `xargs`, ...). Argv path-arguments to allowed commands are also checked against `[filesystem]` rules — `subprocess.exec(["cat", "/etc/passwd"])` is rejected. |
| **Agent following an HTTP redirect to a denied host** | `net.http_*` does not auto-follow 3xx; the call returns a typed error and the script must re-issue against the new URL (which gets gated again). |
| **Agent reading a denied path via a symlink the operator allowed** | `fs.*` canonicalize paths before the policy check; the symlink target — not the symlink itself — is what the policy sees. |
| **Agent modifying its own policy or audit log** | `Policy::guard_audit_log` and the self-writable guard refuse to start if the policy file or audit log is reachable to the agent under any of `write_allow` / `delete_allow`. |
| **Audit log tampering after the fact** | Each line carries a SHA-256 chain (`denyx_seq` + `denyx_prev_hash`); `denyx audit verify` detects in-place mutations, line removals, and seq jumps. |
| **MCP tool definition poisoning (local-executor deployment)** | In the `denyx-local-mcp` architecture, the cloud orchestrator sees exactly one tool — `delegate_to_local` — so third-party MCP tool descriptions never enter its context. The local executor model receives tool metadata only from the operator-controlled policy file (`[tools.X]` routing entries), not from live MCP server schemas. A poisoned tool description in any co-installed MCP server has no path to either model's reasoning. |

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
- **Pure-CPU denial-of-service inside the script.** `[runtime].max_seconds`
  bounds wall time, but during that window an agent can busy-loop,
  allocate, or fork-bomb on Linux without `bwrap`. Run inside a
  container if you care about resource exhaustion.
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
| [03-architecture.md](03-architecture.md) | How the runtime is structured (developer-facing). |
| [examples/local_executor/run_exfil.py](../examples/local_executor/run_exfil.py) | The adversarial exfiltration probe — runs hand-written Starlark that *tries* to leak `local_only_var` values. Empirical version of the "what we don't defend against" list. |
