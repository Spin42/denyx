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

- **Numbered (`NN-...md`)** — the **reading path**. Read 01 → 13 in
  order to understand Denyx end-to-end. Each one builds on the
  previous and the sequence is curated.
- **Lowercase reference (`name.md`)** — **looked up, not read in
  sequence**. Specifications, security writeups, deployment
  guides, historical artifacts. Use the table of contents below
  or the link from whatever numbered doc points to them.

The index below lists everything in both groups in one place.

## Reading path (numbered)

| #  | Doc                                                                | Purpose |
|----|--------------------------------------------------------------------|---------|
| 01 | [why-denyx](01-why-denyx.md)                                       | The problem statement and threat-model framing. Start here. |
| 02 | [from-sigil](02-from-sigil.md)                                     | The Sigil → Aegis → Denyx lineage. What was tried, what was learned, why Denyx looks the way it does. |
| 03 | [architecture](03-architecture.md)                                 | Capability typing, the three lines of defense, the crate layout. |
| 04 | [security-threat-model](04-security-threat-model.md)               | What Denyx claims to defend against, what it explicitly does *not* defend against, the trust boundaries. **The contract Denyx commits to enforce.** |
| 05 | [owasp-agentic-coverage](05-owasp-agentic-coverage.md)             | Empirical scoring against the OWASP Agentic Top 10, with concrete tests. 2 strong / 4 partial / 4 out of scope, no claim table. |
| 06 | [policy-file](06-policy-file.md)                                   | **The most important read.** Every section, every option, with worked examples. The `denyx init` generator and the local-only-reads feature. |
| 07 | [install](07-install.md)                                           | Prerequisites: Rust toolchain, Ollama (for the local-executor flow), Claude Code / opencode (for the orchestrated flow). |
| 08 | [quickstart](08-quickstart.md)                                     | A 5-minute walkthrough — generate a policy, run a script, watch the audit log. |
| 09 | [claude-code](09-claude-code.md)                                   | Wire `denyx-mcp` into Claude Code. Two integration shapes. |
| 10 | [opencode](10-opencode.md)                                         | Same for opencode. |
| 11 | [denyx-for-teams](11-denyx-for-teams.md)                           | The team-deployment shape: one policy + one audit trail across many developers, via a central server. Philosophy, trade-offs of every shape, rollout stages. |
| 12 | [local-executor](12-local-executor.md)                             | The full agentic stack: cloud orchestrator → local 7B executor → Denyx runtime. The architecture the eval harness measures. |
| 13 | [running-examples](13-running-examples.md)                         | Reproduction guide for the three eval harnesses (single-step, 36-task multi-step, Sonnet/Opus orchestrated). Read this to confirm the headline numbers on your own machine. |
| 14 | [other-hosts](14-other-hosts.md)                                   | Setup guide for VSCode (GitHub Copilot agent mode, Continue, Cline) and Cursor. **Not thoroughly tested** — MCP wiring should work universally; the host-side lockdown varies and is incomplete for some hosts. |

## Reference (lowercase)

| Doc                                                          | Purpose |
|--------------------------------------------------------------|---------|
| [comparison](comparison.md)                                  | How Denyx differs from host built-ins, MCP gateways, LLM guardrail frameworks, IFC research, and audit-shape peers. Read this when evaluating Denyx vs alternatives. |
| [host-config](host-config.md)                                | Full flag reference for `denyx host-config`. Per-host wiring matrix, sandbox modes, merge-vs-replace semantics, team-mode flags, lockdown-only mode. |
| [doctor](doctor.md)                                          | Full flag reference for `denyx-mcp doctor` and `denyx-local-mcp doctor`. Scan vs targeted modes, exit codes, common findings table. |
| [agent-policy-spec](agent-policy-spec.md)                    | Portable spec for the policy format, **v1.0.0**. Tool-agnostic — consumable by any agentic system. Use this if you're implementing the policy format in a non-Denyx runtime. |
| [server-protocol](server-protocol.md)                        | The HTTP wire spec a policy/audit server must implement, **v1**. Two endpoints, bearer auth, status-code semantics, conformance test vectors. Read after `11-denyx-for-teams`. |
| [claude-code-permission-tests](claude-code-permission-tests.md) | Empirical test recipe verifying that Claude Code's built-in tools respect the project-local deny list, and that v2 additions (`Agent`, `Task*`, `Cron*`, …) inherit permissions rather than create independent bypass paths. Re-run after Claude Code version bumps. |
| [security-audit](security-audit.md)                          | The 16-surface bypass-assessment writeup that triggered the recent security work. Findings + fixes + verified-safe surfaces. |
| [security-pentest-report](security-pentest-report.md)        | Round 1 (2026-05-06): AI-driven (Sonnet + Opus) penetration test against the local-only IFC layer. Findings categorised Critical/High/Medium/Low, mitigations, closure verification. |
| [security-pentest-r2-tool-poisoning](security-pentest-r2-tool-poisoning.md) | Round 2 (2026-05-11): step-parameter injection on `delegate_to_local`, encoding-bypass attempt, deny-by-default audit, and a v3 follow-up that expanded the probe set to 47 across 12 categories and compared detection rates against llm-guard and NeMo Guardrails. |
| [mutation-testing](mutation-testing.md)                      | How `cargo-mutants` runs against the security-critical core (policy gate, IFC, verifier). Triage workflow, schedule, honest limits. |
| [macos-deployment](macos-deployment.md)                      | Run `denyx-mcp` on macOS via Lima + bubblewrap inside a Linux VM. Setup, MCP wiring, verification, alternatives. |
| [windows-deployment](windows-deployment.md)                  | Run `denyx-mcp` on Windows via WSL2 + bubblewrap inside the Linux subsystem. Setup, MCP wiring, verification, alternatives. |
| [conclusions](conclusions.md)                                | The Sigil retrospective notes Denyx was built from. Background reading for `02-from-sigil`. |
| [project-plan](project-plan.md)                              | Initial design plan, kept as a historical artifact. |

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
