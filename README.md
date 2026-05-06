# Denyx — _previously known as Aegis_

**A safe-by-design local tooling layer for agentic AI, with deliberate
control over permissions through a policy file.**

[![CI](https://github.com/Spin42/denyx/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Spin42/denyx/actions/workflows/ci.yml)
[![Mutation testing (weekly)](https://github.com/Spin42/denyx/actions/workflows/mutants.yml/badge.svg?branch=main)](https://github.com/Spin42/denyx/actions/workflows/mutants.yml)
[![codecov](https://codecov.io/gh/Spin42/denyx/branch/main/graph/badge.svg)](https://codecov.io/gh/Spin42/denyx)

> Badge meaning, since "passing" is doing a lot of work in those
> labels: **CI** is the per-PR build + test + fmt + clippy +
> 80%-line-coverage gate (everything green = the whole gate passed).
> **Mutation testing** is a weekly cron — the badge reflects whether
> the most recent scheduled run completed, not the kill rate (the
> kill rate lives in [docs/mutation-testing.md](docs/mutation-testing.md)
> and the workflow's Step Summary). **codecov** is the live line-
> coverage percentage uploaded by the `coverage` CI job on every
> push to `main`.

Denyx embeds Starlark (Python's safe subset), exposes a small set of
effecting builtins (`fs.read`, `net.http_get`, `subprocess.exec`,
`env.read`, ...), and enforces a TOML-declared policy at every call.
The runtime is default-deny end-to-end; what an agent can do is
exactly what the policy file permits, no more. Forbidden operations
fail at the **system layer** — in Rust, before or during evaluation —
not in a wrapper that asks the model nicely.

> ## ⚠ Status & honest disclosures
>
> - **Pre-1.0, use at your own risk.** No published crates, no
>   pre-built binaries, schema may shift in minor ways before v1.
>   Don't run it against systems you can't afford to recover.
> - **AI-generated codebase.** Most of the code, tests, and docs were
>   written by Claude (Anthropic) under human direction; the
>   architecture and threat model are human, the implementation is
>   not. **Read the diffs before trusting them** — especially the
>   policy crate, the verifier, and the taint-redaction code in
>   `crates/host/`.
> - **Empirically tested, not human-reviewed.** A 16-surface static
>   bypass assessment ([docs/security-audit.md](docs/security-audit.md)),
>   a 12-technique exfil probe at **0 LEAK / 3 WEAK_LEAK / 9
>   REDACTED**, an AI-driven pentest with Sonnet and Opus (two High
>   findings, both closed;
>   [docs/security-pentest-report.md](docs/security-pentest-report.md)),
>   and `cargo-fuzz` + a 200 000-iteration regression sweep
>   ([fuzz/](fuzz/README.md)). **No human security engineer has read
>   the code with hostile intent yet** — that external review is the
>   single biggest gating item between today and unattended
>   production use.
> - **Threat-model scope.** Defends against prompt engineering — the
>   policy is Rust-enforced; clever phrasing can't bypass it. The
>   local-only IFC layer covers a documented transform set (reverse,
>   hex, single-byte XOR + hex(XOR), base64 std/url-safe, ROT-1..25,
>   chunking detection) plus arg-side denial at outbound effects. It
>   does NOT catch scripts running their own crypto (AES, custom
>   permutations) or pure side channels (length, comparison oracles,
>   substring guesses). Full scope in
>   [docs/security-threat-model.md](docs/security-threat-model.md).
> - **`requires_approval` is not always a real user prompt.** The
>   CLI prompts on stdin. The MCP server's default `auto` mode sends
>   `elicitation/create` only if the client advertises the
>   capability; most don't yet (including Claude Code 2.1.x in `-p`
>   mode), so `auto` falls back to `auto-deny` with a structured
>   `confirm_denied` tag for the orchestrator. The runtime denies
>   correctly either way; a real prompt is delivered only by the CLI
>   or elicitation-capable clients. See
>   [docs/07-claude-code.md](docs/07-claude-code.md#empirical-findings-what-claude-code-actually-does).
> - **OS isolation is opt-in and platform-specific.** Linux:
>   `[subprocess].sandbox = "bwrap"`. macOS: Lima VM
>   ([docs/macos-deployment.md](docs/macos-deployment.md)). Windows:
>   WSL2 ([docs/windows-deployment.md](docs/windows-deployment.md)).
>   Without one of these, Denyx is the language-level gate only.

## The problem

Today's coding agents (Claude Code, Cursor, opencode, Aider, custom
CLI bots) sit on a spectrum between *"approve every command"*
(friction-heavy, fatigue-prone, the user clicks through anyway) and
*"YOLO mode"* (no safety, every shell call runs). Both modes share a
critical property: the **agent runtime decides what's safe** based on
what the model emitted, and the model can phrase commands to look
more innocuous than they are.

Specifically, today's agentic stacks struggle with:

- destructive shell commands (`rm -rf`, `git push --force`,
  `terraform apply` against prod)
- credential exfiltration (reading `~/.aws/credentials`,
  `$AWS_SECRET_ACCESS_KEY`, etc.)
- prompt-injection vectors that send commands as text inside fetched
  content
- secret keys leaking from a local executor up to a cloud orchestrator
  (the agent reads your API key, summarizes the call, and the key
  shows up in the orchestrator's context)

None of these should be solved by hoping the model doesn't choose to
do the bad thing.

## How Denyx solves it: safe by design

The whole runtime is built around one rule: **what's not in the policy
doesn't happen**. There is no "best-effort" mode, no soft-warn, no
fallback path that quietly does the action anyway. This is what
"safe by design" means in this project — the enforcement is structural,
not advisory.

A declarative policy file (TOML) is the single source of truth that
controls every effect:

```toml
inherits = "secure-defaults"   # universal denies for credentials,
                                # cloud-metadata IPs, RFC1918, dangerous
                                # commands, secret env vars, etc.

[filesystem]
read_allow      = ["src/**", "tests/**"]
local_only_read = ["~/.config/myapp/token"]   # readable, never bubbles up
write_allow     = ["src/**", "/tmp/**"]

[network]
http_get_allow   = ["api.github.com"]
local_only_hosts = ["api.openai.com"]   # response tainted at boundary
deny_ips         = ["169.254.0.0/16", "10.0.0.0/8"]   # CIDR-aware

[environment]
allow_vars      = ["PATH", "USER"]
local_only_vars = ["OPENAI_API_KEY"]    # the agent can use it; it can't leak it
deny_vars       = ["AWS_SECRET_ACCESS_KEY"]

[subprocess]
allow_commands = ["git", "make", "python3"]

[subprocess.deny_args]
git = ["push --force", "reset --hard", "filter-branch"]
```

The capabilities the script may call (`fs.read`, `fs.write`,
`net.http_get`, `env.read`, `subprocess.exec`) are **derived from
which resource sections you populated** — there is no separate
`[functions]` allowlist to keep in sync.

Three lines of defense, all in the runtime — none of them depend on
prompting:

1. **Pre-execution verifier** rejects any script referencing a
   capability whose resource section is empty before evaluation
   starts.
2. **Capability gate at every call** re-checks the policy at runtime;
   a forbidden read/write/fetch/exec raises a typed error that
   surfaces as a non-zero exit code.
3. **Output-boundary redaction** scrubs any `local_only_*` value from
   printed output, audit-log payloads, and MCP tool results — so a
   secret the local agent reads cannot bubble up to a cloud
   orchestrator (or to your chat transcript) even if the model puts
   it in a string.

Three visibility levels per resource: **forbidden** / **local-only** /
**public**. Default-deny everywhere; deny wins over allow.

## The design principle

> **Start from a limited language the models already know the syntax of, then extend only with what we need.**

That sentence is the load-bearing decision the rest of Denyx follows
from. Two properties, both load-bearing on their own:

**"A limited language the models already know"** means we get to
free-ride on pre-training. Stock LLMs arrive ~90% fluent in Starlark
on day one because Starlark is Python with three rules removed. The
remaining gap is closed with prompting + retrieval + retry, not
months of fine-tuning. (We tried the fine-tuning path in the
predecessor project, [Sigil](docs/02-from-sigil.md). It plateaued at
7/30 multi-step tasks. Denyx with **stock qwen-7B alone** (no cloud
orchestrator) reaches 36/36 on the current 36-task suite. Layered
with Sonnet/Opus orchestration on top of qwen+Denyx on the same
36-task suite: Sonnet 30/36, Opus 35/36 — the orchestrated misses
are model-side artifacts (Sonnet preemptively refuses some DENY
tasks; Opus paraphrases the literal `[REDACTED]` sentinel one
verify hook substring-matches on). The runtime denies and redacts
correctly in every case. See
[docs/09-local-executor.md](docs/09-local-executor.md) for the
per-failure breakdown.)

**"Extend only with what we need"** flips the security model inside
out. Default Python is *"everything works, lock it down by
subtraction"*; default Starlark is *"nothing works, opt in by
addition"*. Every effecting builtin — `fs.read`, `net.http_get`,
`subprocess.exec`, `env.read` — is a deliberate, named,
capability-typed addition the runtime can gate. Subtraction-based
security has a long history of CVE backlogs (every Python sandbox
that ever shipped). Addition-based security has a much smaller blast
radius when a corner case is wrong.

Combined: the agent writes code in something it already mostly knows,
inside a runtime where the only effects are the ones the operator
explicitly granted.

## Get started

On Linux, native install:

```sh
cargo build --release                     # builds denyx + denyx-mcp
denyx init --lang python                  # generates a starter policy
denyx run --policy denyx.toml my.star     # runs the script under it
```

On **macOS**, run inside a Lima VM (one-time `brew install lima` plus
[`examples/macos/denyx.lima.yaml`](examples/macos/denyx.lima.yaml)) —
full guide at [docs/macos-deployment.md](docs/macos-deployment.md).

On **Windows**, run inside WSL2 (one-time `wsl --install -d Ubuntu-24.04`)
— full guide at [docs/windows-deployment.md](docs/windows-deployment.md).

The same policy file, MCP surface, and audit-log shape work on all
three; only the bridge between your MCP host and `denyx-mcp` differs.

`denyx init` supports `python`, `node`, `ruby`, `rust`, `go`, with
language-appropriate toolchain allowlists and git-destructive denies
baked in.

If you skip `--policy`, Denyx falls back to the built-in
`secure-defaults` baseline (no allow lists, every effect denied) and
prints a banner explaining how to grant capabilities. Loud-and-safe.

For agentic hosts, `denyx-mcp` is an MCP server (stdio JSON-RPC 2.0)
that exposes the same enforcement to Claude Code, opencode, or any
MCP-aware orchestrator.

## Three deliverables

- **`denyx`** — CLI binary. `denyx run` evaluates a script under a
  policy. `denyx init` generates a starter policy.
- **`denyx-host`** — embeddable Rust crate. Anything that wants
  policy-gated Starlark in-process pulls this in.
- **`denyx-mcp`** — MCP server. Wires Denyx into Claude Code,
  opencode, Cursor, custom orchestrators.

## Documentation

The deep dive lives in [`docs/`](docs/) — start with the
[index](docs/README.md). Two kinds of docs, distinguishable by
filename:

- **Numbered (`NN-...md`)** are the reading path: read 01 → 10 in
  order to understand Denyx end-to-end.
- **Lowercase reference (`name.md`)** is looked up, not read in
  sequence: specifications, security writeups, historical artifacts.

### Reading path

| #  | Doc                                                | What's in it |
|----|----------------------------------------------------|--------------|
| 01 | [why-denyx](docs/01-why-denyx.md)                  | Problem statement and threat-model framing. |
| 02 | [from-sigil](docs/02-from-sigil.md)                | What the predecessor Sigil project taught us; why Denyx looks the way it does. |
| 03 | [architecture](docs/03-architecture.md)            | Capability typing, the three lines of defense, the crate layout. |
| 04 | [policy-file](docs/04-policy-file.md)              | **The most important read.** Every section, every option, with examples. The `denyx init` generator and the local-only-reads feature. |
| 05 | [install](docs/05-install.md)                      | Prerequisites: Rust, Ollama, Claude Code / opencode. |
| 06 | [quickstart](docs/06-quickstart.md)                | 5-minute walkthrough — generate, run, audit. |
| 07 | [claude-code](docs/07-claude-code.md)              | Wire `denyx-mcp` into Claude Code. |
| 08 | [opencode](docs/08-opencode.md)                    | Same for opencode. |
| 09 | [local-executor](docs/09-local-executor.md)        | The full agentic stack: cloud orchestrator → local 7B → Denyx. Includes evaluation results. |
| 10 | [running-examples](docs/10-running-examples.md)    | Reproduction guide for the three eval harnesses. |

### Reference

| Doc                                                       | What's in it |
|-----------------------------------------------------------|--------------|
| [agent-policy-spec](docs/agent-policy-spec.md)            | Portable policy format spec, **v1.0.0**. Tool-agnostic; implement in non-Denyx runtimes. |
| [security-threat-model](docs/security-threat-model.md)    | One-page review companion. What Denyx claims to defend; what it explicitly does *not*. Read first if you're auditing. |
| [security-audit](docs/security-audit.md)                  | The 16-surface bypass-assessment writeup. Findings + fixes. |
| [security-pentest-report](docs/security-pentest-report.md) | Round-1 AI-driven pentest report (Sonnet + Opus). 2 High findings, both remediated. |
| [macos-deployment](docs/macos-deployment.md)              | macOS deployment guide: Lima VM + bubblewrap. |
| [windows-deployment](docs/windows-deployment.md)          | Windows deployment guide: WSL2 + bubblewrap. |
| [conclusions](docs/conclusions.md)                        | Sigil retrospective notes (background for `02-from-sigil.md`). |
| [project-plan](docs/project-plan.md)                      | Initial design plan; historical artifact. |

## Why "Denyx"?

The name puts the project's load-bearing posture up front: **deny by
default**. Everything an agent can do has to be enumerated in the
policy file — what's not in the policy doesn't happen, and that's
not a matter of the model deciding to behave. The trailing `x` reads
as a sigil rather than a phonetic continuation; "Denyx" is a coined
wordmark, not an English word.

The project was originally called **Aegis**, after the protective
shield of Zeus and Athena in Greek mythology — Hephaestus-forged,
goatskin, occasionally bearing the head of the Gorgon Medusa to
ward off threats. The mythology framing was load-bearing for the
Aegis era. The rename to Denyx was a publishing decision (the
`aegis-*` crate names were partially taken on crates.io) but it
also gave the project a clearer signal of what it actually does:
the policy denies; the runtime enforces; the agent operates inside
exactly the surface that's been written down.

## Status

Pre-1.0. The runtime is solid; the eval harness reproduces stable
numbers (qwen 7B alone: **36/36** on the current 36-task suite, which
includes 5 feature-demo tasks pinning specific runtime layers;
Sonnet-orchestrated on the same suite: **30/36 / $1.37**;
Opus-orchestrated: **35/36 / $2.83**). The orchestrated gap is
model-side, not runtime-side — Denyx denies and redacts correctly
in every case; Sonnet sometimes preemptively refuses DENY tasks
it should attempt, and the single Opus miss is a verify-hook
substring strictness issue where the orchestrator paraphrased
the redaction outcome instead of preserving the literal
`[REDACTED]` sentinel. Per-failure breakdown in
[docs/09-local-executor.md](docs/09-local-executor.md).
The policy spec is portable and documented. APIs may still change.

## Roadmap to production-readiness

Denyx is a serious prototype with end-to-end functionality, but
**not yet hardened enough to be your default for unattended
agentic work**. These are the open items between today and "drop
this on three machines and standardize." Listed roughly by
priority — the security items (☐) gate daily-driver use; the
operational items (◇) gate easy adoption.

### Already shipped (this codebase)

- ✅ Subprocess env filtering (child only sees declared `allow_vars`)
- ✅ Wall-time deadline + call-stack cap (`[runtime].max_seconds`,
  `max_callstack_size`)
- ✅ Per-call approval escalation (`requires_approval = [...]` in
  the policy). The CLI prompts on stdin. The MCP server has four
  modes: `auto` (default; sends MCP `elicitation/create` to the
  client when it advertises elicitation capability, falls back to
  `auto-deny` otherwise), `elicit` (force elicitation), `auto-deny`
  (return `denyx_error_kind: "confirm_denied"` for the orchestrator
  to handle), `auto-allow` (tests and demos only). Bidirectional
  JSON-RPC dispatch is implemented and tested
  (`crates/mcp/tests/elicitation.rs`); whether a real user prompt
  appears depends on the client supporting elicitation. Empirical
  finding: Claude Code 2.1.x in `claude -p` mode does **not**
  advertise elicitation, so the dominant deployment shape today is
  "runtime denies the call, orchestrator surfaces the structured
  tag." See [docs/07-claude-code.md](docs/07-claude-code.md#empirical-findings-what-claude-code-actually-does).
- ✅ `denyx policy validate` + `denyx policy show` (CI lint and
  operator visibility)
- ✅ Per-call HTTP timeout (`[network].timeout_seconds`, default 30s)
- ✅ Self-writable guard (refuses policies that grant write/delete on
  themselves)
- ✅ Local-only visibility class (read OK, value never bubbles up):
  output-boundary scrub for the original value plus the documented
  transform set (reverse, hex lower/upper, XOR with each single-byte
  key, hex(XOR) compositions); subsequence-chunking detection on
  joined printed output; arg-side denial at every outbound effect
  (`fs.write`, `fs.delete`, `subprocess.exec` for non-local-only
  commands, `net.http_*` for non-local-only hosts) with the matched
  transform label included in the audit-event payload
- ✅ Subprocess argv path-policy gate
  (`subprocess.exec(["cat", "/etc/passwd"])` rejected — argv args
  that look like paths are checked against `[filesystem]` rules)
- ✅ Opt-in OS-level sandbox via `[subprocess].sandbox = "bwrap"`
  (Linux only; bubblewrap-backed namespaced bind-mount jail per
  call — paths outside the policy literally don't exist for the
  child, defeats every interpreter-side path-obfuscation trick)
- ✅ Symlink canonicalization in `fs.*` (a symlink at
  `<root>/src/x → /etc/passwd` no longer slips past the policy
  check)
- ✅ HTTP redirects no longer auto-followed (`net.http_*` returns a
  typed error on 3xx so the script must reissue against the new
  URL — gate fires)
- ✅ Taint-redaction now covers the error path (`fail(secret)`
  no longer leaks via `DenyxError::Display`)
- ✅ SHA-256-chained audit log + `denyx audit verify <path>`
  subcommand (in-place mutation, line removal, seq jumps all
  detectable)
- ✅ Audit-log protected-path guard (the agent cannot have
  read/write/delete on the audit log — same shape as the
  self-writable guard for the policy file)
- ✅ One-page security threat-model doc
  ([docs/security-threat-model.md](docs/security-threat-model.md))
  — what Denyx defends against, what it does *not*, the trust
  boundaries, the assumptions
- ✅ Adversarial exfiltration probe
  ([examples/local_executor/run_exfil.py](examples/local_executor/run_exfil.py))
  — 12 hand-written Starlark exfil techniques against
  `local_only_vars`. Current run: **0 LEAK / 3 WEAK_LEAK / 9
  REDACTED**. Every full-secret exfil shape in the probe (raw
  print, reverse, hex, XOR + hex, per-char chunking, fs.write
  to disk, subprocess argv, fail() with mutated form) is now
  caught — either at the output boundary (transform-aware
  scrub, chunking detection) or at the arg-side gate (refuse
  the call rather than scrub on the way out). The 3 remaining
  WEAK_LEAK are inherent non-byte-channels: `len(secret)`,
  single-char comparison oracle, and `"MNOP" in secret`-style
  substring guesses — these reveal at most O(log secret) bits
  per query and are documented honestly in the threat-model doc.
- ✅ AI-driven pentest harness
  ([examples/local_executor/run_pentest.py](examples/local_executor/run_pentest.py))
  — drives `claude-sonnet-4-6` and `claude-opus-4-7` as adversarial
  testers against `denyx-mcp`. Round 1 surfaced two **High** findings
  (custom base64 encoding and ROT-N — both bypassed the substring
  scrub independently in <15 turns from each model); both
  remediated by extending the transform set in
  `crates/host/src/taint.rs` (added `base64_std`, `base64_std_nopad`,
  `base64_urlsafe`, `base64_urlsafe_nopad`, `rot1`…`rot25`).
  Closure verified: re-classifying both transcripts against the
  patched runtime reports 0 DERIVED_LEAK. Full report at
  [docs/security-pentest-report.md](docs/security-pentest-report.md).
- ✅ Fuzz harnesses: three `cargo +nightly fuzz` targets for the
  verifier, the policy TOML deserializer + resolver, and the
  glob-pattern compiler / path matchers
  ([fuzz/](fuzz/README.md)); plus a stable-toolchain randomized
  regression sweep that runs in plain `cargo test` on every CI
  build (200 000 iterations across the same surfaces, no panics
  or non-idempotent decisions found).
- ✅ `denyx-mcp` surfaces `[tools.X]` routing hints
  (`denyx_tool_routing` MCP tool) so Claude Code calling
  `denyx_run` directly can read `backend_url` / capabilities /
  allowed flag without re-parsing the policy TOML

### Still open

#### Security gates (block daily-driver use)

- ☐ **External security review.** AI-generated security code is
  unaudited security code. The policy crate, the verifier, and the
  taint-redaction code in `crates/host/src/taint.rs` need a human
  security engineer reading them with hostile intent. **This is the
  single biggest gating item.** The threat-model doc, the
  bypass-assessment writeup, and the exfil probe's empirical
  findings are bundled to give the reviewer a clear scope.

#### Operational gates (block easy adoption)

- ◇ **Published binaries.** `cargo install`, Homebrew tap, or
  pre-built tarballs. Build-from-source is fine for evaluation, not
  for "ship to three machines and standardize."
- ◇ **Policy schema migration tool.** When the schema changes
  pre-1.0, existing policies are hand-edited. A `denyx policy
  migrate` would smooth this.

For today: use Denyx for experimental setups, in containers, on
machines where the cost of a Denyx bug is "I have to recover a VM"
not "my SSH key got exfiltrated." For default-on-everything use,
the external security review (the one ☐ item above) is the real
gating list — every byte-level bypass the exfil probe could
construct is now closed, and the regression sweeps run on every
CI build.

## Project layout

```
crates/
  policy/    types, matchers, presets, inheritance
  host/      Starlark embedding, builtins, audit, verifier, taint
  cli/       `denyx` binary (run + init)
  mcp/       `denyx-mcp` MCP server
docs/        documentation (links above)
examples/
  policies/        reference policies (FastAPI, Rails, ...)
  local_executor/  evaluation harness (Ollama + qwen + denyx-mcp)
```

## License

[MIT](LICENSE) © 2026 Spin42.
