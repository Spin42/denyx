# Denyx Documentation

Denyx is a **safe-by-design local tooling layer for agentic AI** — a
Rust runtime that runs agent code under a TOML-declared policy that
the operator (not the model) controls. It embeds Starlark (Python's
safe subset), exposes a small namespaced standard library (`fs.read`,
`net.http_get`, `subprocess.exec`, `env.read`), and enforces the
policy at every effecting call. Default-deny everywhere: what's not
in the policy file doesn't happen. Forbidden operations fail at the
*system* layer, not in the agent's prompt.

It ships as three things: a CLI binary (`denyx`), an embeddable Rust
crate (`denyx-host`), and an MCP server (`denyx-mcp`) that any agentic
host (Claude Code, opencode, Cursor, custom orchestrators) can wire in.

## How this directory is organised

Two kinds of docs, distinguishable at a glance from the filename:

- **Numbered (`NN-...md`)** — the **reading path**. Read 01 → 10 in
  order to understand Denyx end-to-end. Each one builds on the
  previous and the sequence is curated.
- **Lowercase reference (`name.md`)** — **looked up, not read in
  sequence**. Specifications, security writeups, historical
  artifacts. Use the table of contents below or the link from
  whatever numbered doc points to them.

The index below lists everything in both groups in one place.

## Reading path (numbered)

| #  | Doc                                                | Purpose |
|----|----------------------------------------------------|---------|
| 01 | [why-denyx](01-why-denyx.md)                       | The problem statement and threat-model framing. Start here. |
| 02 | [from-sigil](02-from-sigil.md)                     | The predecessor Sigil project: what it tried, what it taught us, why Denyx looks the way it does. |
| 03 | [architecture](03-architecture.md)                 | Capability typing, the three lines of defense, the crate layout. |
| 04 | [policy-file](04-policy-file.md)                   | **The most important read.** Every section, every option, with worked examples. The `denyx init` generator and the local-only-reads feature. |
| 05 | [install](05-install.md)                           | Prerequisites: Rust toolchain, Ollama (for the local-executor flow), Claude Code / opencode (for the orchestrated flow). |
| 06 | [quickstart](06-quickstart.md)                     | A 5-minute walkthrough — generate a policy, run a script, watch the audit log. |
| 07 | [claude-code](07-claude-code.md)                   | Wire `denyx-mcp` into Claude Code. Two integration shapes. |
| 08 | [opencode](08-opencode.md)                         | Same for opencode. |
| 09 | [local-executor](09-local-executor.md)             | The full agentic stack: cloud orchestrator → local 7B executor → Denyx runtime. The architecture the eval harness measures. |
| 10 | [running-examples](10-running-examples.md)         | Reproduction guide for the three eval harnesses (single-step, 36-task multi-step, Sonnet/Opus orchestrated). Read this to confirm the headline numbers on your own machine. |

## Reference (lowercase)

| Doc                                                          | Purpose |
|--------------------------------------------------------------|---------|
| [denyx-for-teams](denyx-for-teams.md)                        | The team-deployment shape: one policy + one audit trail across many developers, via a central server. Philosophy, rollout stages, what a basic Denyx-capable server has to do. |
| [server-protocol](server-protocol.md)                        | The HTTP wire spec a policy/audit server must implement, **v1**. Two endpoints, bearer auth, status-code semantics, conformance test vectors. Read after `denyx-for-teams.md`. |
| [agent-policy-spec](agent-policy-spec.md)                    | Portable spec for the policy format, **v1.0.0**. Tool-agnostic — consumable by any agentic system. Use this if you're implementing the policy format in a non-Denyx runtime. |
| [security-threat-model](security-threat-model.md)            | One-page review companion. What Denyx claims to defend against, what it explicitly does *not* defend against, the trust boundaries, the assumptions. **Read first if you're auditing with hostile intent.** |
| [security-audit](security-audit.md)                          | The 16-surface bypass-assessment writeup that triggered the recent security work. Findings + fixes + verified-safe surfaces. |
| [security-pentest-report](security-pentest-report.md)        | AI-driven (Sonnet + Opus) penetration test against the local-only IFC layer. Findings categorised Critical/High/Medium/Low, mitigations, closure verification. |
| [mutation-testing](mutation-testing.md)                      | How `cargo-mutants` runs against the security-critical core (policy gate, IFC, verifier). Triage workflow, schedule, honest limits. |
| [conclusions](conclusions.md)                                | The Sigil retrospective notes Denyx was built from. Background reading for `02-from-sigil.md`. |
| [project-plan](project-plan.md)                              | Initial design plan, kept as a historical artifact. |
| [macos-deployment](macos-deployment.md)                      | Run `denyx-mcp` on macOS via Lima + bubblewrap inside a Linux VM. Setup, MCP wiring, verification, alternatives. |
| [windows-deployment](windows-deployment.md)                  | Run `denyx-mcp` on Windows via WSL2 + bubblewrap inside the Linux subsystem. Setup, MCP wiring, verification, alternatives. |

## Project layout

```
crates/
  policy/   — policy types, matchers, presets, inheritance
  host/     — Starlark embedding, capability builtins, audit, verifier
  cli/      — `denyx` binary (run + init subcommands)
  mcp/      — `denyx-mcp` MCP server (stdio JSON-RPC)
docs/       — this directory (numbered reading path + lowercase reference)
examples/
  policies/        — reference policies (FastAPI, Rails, ...)
  local_executor/  — evaluation harness + adversarial exfil probe + cloud-driven pentest harness
  macos/           — Lima VM template for the macOS deployment
```
