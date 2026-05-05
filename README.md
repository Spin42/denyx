# Aegis

**A safe-by-design local tooling layer for agentic AI, with deliberate
control over permissions through a policy file.**

Aegis embeds Starlark (Python's safe subset), exposes a small set of
effecting builtins (`fs.read`, `net.http_get`, `subprocess.exec`,
`env.read`, ...), and enforces a TOML-declared policy at every call.
The runtime is default-deny end-to-end; what an agent can do is
exactly what the policy file permits, no more. Forbidden operations
fail at the **system layer** — in Rust, before or during evaluation —
not in a wrapper that asks the model nicely.

> ## ⚠ Status & honest disclosures
>
> - **Use at your own risk.** Aegis is **in active development** and
>   has not been hardened for production. There are no security audits,
>   no released versions on crates.io, and APIs may still change.
>   Don't run it against systems you can't afford to recover.
> - **AI-generated codebase.** Almost all of the code, tests, and
>   documentation in this repository was written by Claude (Anthropic)
>   under human direction. The human (project owner) decided the
>   architecture, design constraints, threat model, and load-bearing
>   tradeoffs; Claude wrote the implementation, the tests, and most of
>   the docs. This is disclosed because it materially affects how you
>   should evaluate the code: please **read the diffs before trusting
>   them**, especially anywhere security-critical (the policy crate,
>   the verifier, and the taint-redaction code in `crates/host/`).
> - **Threat-model scope.** The runtime defends against *prompt
>   engineering* — the policy is enforced in Rust and a malicious
>   prompt cannot bypass it by clever phrasing. It does NOT defend
>   against a determined adversary doing deliberate exfiltration via
>   obfuscation (XOR, base64, chunking) of tainted values. See
>   [docs/04-policy-file.md](docs/04-policy-file.md#how-local-only-works)
>   for the limits of the local-only scrubbing.
> - **No OS-level isolation.** Aegis is a *language-runtime*
>   gate, not a sandbox in the seccomp/namespace/VM sense. For full
>   isolation, run it inside a container.

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

## How Aegis solves it: safe by design

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

## Get started

```sh
cargo build --release                     # builds aegis + aegis-mcp
aegis init --lang python                  # generates a starter policy
aegis run --policy aegis.toml my.star     # runs the script under it
```

`aegis init` supports `python`, `node`, `ruby`, `rust`, `go`, with
language-appropriate toolchain allowlists and git-destructive denies
baked in.

If you skip `--policy`, Aegis falls back to the built-in
`secure-defaults` baseline (no allow lists, every effect denied) and
prints a banner explaining how to grant capabilities. Loud-and-safe.

For agentic hosts, `aegis-mcp` is an MCP server (stdio JSON-RPC 2.0)
that exposes the same enforcement to Claude Code, opencode, or any
MCP-aware orchestrator.

## Three deliverables

- **`aegis`** — CLI binary. `aegis run` evaluates a script under a
  policy. `aegis init` generates a starter policy.
- **`aegis-host`** — embeddable Rust crate. Anything that wants
  policy-gated Starlark in-process pulls this in.
- **`aegis-mcp`** — MCP server. Wires Aegis into Claude Code,
  opencode, Cursor, custom orchestrators.

## Documentation

The deep dive lives in [`docs/`](docs/):

| Doc                                                | What's in it                                                          |
|----------------------------------------------------|----------------------------------------------------------------------|
| [01-why-aegis.md](docs/01-why-aegis.md)             | The problem statement and threat model.                              |
| [02-from-sigil.md](docs/02-from-sigil.md)           | What the earlier Sigil project taught us; why Aegis looks the way it does. |
| [03-architecture.md](docs/03-architecture.md)       | Capability typing, the three lines of defense, the crate layout.     |
| [04-policy-file.md](docs/04-policy-file.md)         | **Policy file reference.** Every section, every option, with examples. Includes the `aegis init` generator and the local-only-reads feature. |
| [05-install.md](docs/05-install.md)                 | Prerequisites: Rust, Ollama, Claude Code / opencode.                 |
| [06-quickstart.md](docs/06-quickstart.md)           | A 5-minute walkthrough — generate, run, audit.                       |
| [07-claude-code.md](docs/07-claude-code.md)         | Wire `aegis-mcp` into Claude Code. Two integration shapes.           |
| [08-opencode.md](docs/08-opencode.md)               | Same for opencode.                                                    |
| [09-local-executor.md](docs/09-local-executor.md)   | The full agentic stack: cloud orchestrator → local 7B → Aegis. Includes evaluation results. |
| [AGENT_POLICY_SPEC.md](docs/AGENT_POLICY_SPEC.md)   | The portable spec — implement the policy format in non-Aegis runtimes. |
| [CONCLUSIONS.md](docs/CONCLUSIONS.md)               | Sigil retrospective notes (background reading for `02-from-sigil.md`). |
| [PROJECT_PLAN.md](docs/PROJECT_PLAN.md)             | Initial design plan; historical artifact.                            |

The single most important read is
[**docs/04-policy-file.md**](docs/04-policy-file.md). The policy file is
the whole product.

## Why "Aegis"?

The aegis (αἰγίς) is the protective shield of Zeus and Athena in Greek
mythology — Hephaestus-forged, sometimes described as a goatskin
breastplate, occasionally bearing the head of the Gorgon Medusa to
ward off threats. In English, "an aegis" still means a protective
covering, sponsorship, or guarantee of safety ("under the aegis of...").

That's the role this project plays for an agentic-AI workflow: a
protective layer that sits between the model's intent and the system
it can act on. The runtime is the shield; the policy file is what
determines which arrows it stops.

## Status

Pre-1.0. The runtime is solid; the eval harness reproduces stable
numbers (qwen 7B alone: 27-29/31 multi-step; Sonnet-orchestrated:
28/31; Opus-orchestrated: 31/31). The policy spec is portable and
documented. APIs may still change.

## Project layout

```
crates/
  policy/    types, matchers, presets, inheritance
  host/      Starlark embedding, builtins, audit, verifier, taint
  cli/       `aegis` binary (run + init)
  mcp/       `aegis-mcp` MCP server
docs/        documentation (links above)
examples/
  policies/        reference policies (FastAPI, Rails, ...)
  local_executor/  evaluation harness (Ollama + qwen + aegis-mcp)
```

## License

[MIT](LICENSE) © 2026 Marc Lainez.
