# Denyx

**Lock down what your AI coding agent can read, write, fetch, and run on your machine — with one TOML policy.**

Bring your own policy. Plug into any MCP-aware coding host — [Claude Code](https://github.com/anthropics/claude-code), [opencode](https://opencode.ai), GitHub Copilot's agent mode, Cursor, [Continue](https://continue.dev), [Cline](https://cline.bot), and others — or run standalone. Adds what the hosts' built-in permissions can't: secret-aware redaction (values flagged `local_only` never bubble up to the chat), tamper-evident audit (SHA-256-chained, verifiable after the fact), and centralised team deployment (one policy and one audit endpoint across N developers).

[![CI](https://github.com/Spin42/denyx/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Spin42/denyx/actions/workflows/ci.yml)
[![Mutation testing (weekly)](https://github.com/Spin42/denyx/actions/workflows/mutants.yml/badge.svg?branch=main)](https://github.com/Spin42/denyx/actions/workflows/mutants.yml)
[![codecov](https://codecov.io/gh/Spin42/denyx/branch/main/graph/badge.svg)](https://codecov.io/gh/Spin42/denyx)

Denyx is a policy gate for [Claude Code](https://github.com/anthropics/claude-code),
[opencode](https://opencode.ai), and any other MCP-aware coding agent. You
declare what the agent is allowed to touch in a `denyx.toml`; the runtime
enforces it at the system layer in Rust. If the model tries something not in
the policy, the operation **fails** — no prompt-engineering bypass, no
"ignore previous instructions" trick.

> ⚠ **Pre-1.0, AI-generated codebase, no human security review yet.** Solid
> enough for experimental setups and personal projects; not yet hardened for
> unattended production work. [Full status →](#status--honest-disclosures)

## See the difference

Same Claude Code session, same two prompts ("show me my `.env` file" and
"check if `sigil` is in my GitHub repos via `gh`"), with and without
Denyx wired in:

| Without Denyx | With Denyx |
|:---:|:---:|
| [![Claude Code reading .env and running gh unchecked](assets/without_denyx.png)](assets/without_denyx.png) | [![Claude Code blocked from reading .env and running gh by Denyx policy](assets/with_denyx.png)](assets/with_denyx.png) |
| The agent reads `.env` and prints `API_KEY=dont_leak_me_please` straight into the chat, then runs `gh repo list` as a subprocess. Both happen because the host's built-in `Read` and `Bash` tools have no idea what's a secret or what's an unsanctioned command. | The agent tries the same operations and Denyx blocks both *by name*: `.env` is in the filesystem deny list, `gh` is not in `subprocess.allow_commands`, `api.github.com` is not in `network.http_get_allow`. The agent reports the blocks and asks the operator to widen the policy if needed. |

The block is not a prompt-level "please don't do that" — it's a Rust-enforced
denial at the capability gate. The model can't argue its way past it, and a
prompt-injected instruction in fetched content can't either.

## Why Denyx, if Claude Code and opencode already have permissions?

Both hosts ship deny lists. They're real and useful — Denyx wires into them
rather than replacing them (the setup prompt configures both). Where Denyx
adds something the host's permissions can't:

- **Capability-typed policy with three visibility levels.** *Forbidden* /
  *local-only* / *public*. `local_only_*` lets the agent **use** an API key
  or vendor response without that value bubbling up to the chat transcript.
  The host model is binary allow/deny; this is a structurally different
  kind of policy.
- **Output-boundary redaction (IFC).** Once a value is `local_only`, Denyx
  scrubs it from stdout, audit logs, and MCP tool results — including
  encoded forms (hex, base64, XOR, ROT-N, subsequence-chunking). A deny
  list cannot do this; the leak path is a `print()` inside an *allowed*
  tool call.
- **One TOML, every host.** `denyx host-config` translates a single
  `denyx.toml` into Claude Code's `settings.json` shape *and* opencode's
  `permission` block — the same source of truth for both, and any other
  MCP-aware host you choose to wire in.
- **Centralised policy + tamper-evident audit.** Optional team mode fetches
  the active policy from a URL at startup and POSTs every capability call
  to an audit endpoint. Audit lines are SHA-256-chained, so a tampered or
  missing event is detectable with `denyx audit verify`. Neither host has
  this; their settings are per-machine.
- **Standalone + local-executor patterns.** Use Denyx as a CLI gate in CI
  with no host at all, or run a small local model under the gate while a
  cloud model orchestrates — the eval at
  [docs/12-local-executor.md](docs/12-local-executor.md) measures both
  shapes against a 31-task suite.

If your threat model is "block specific bad commands," the hosts'
permissions are enough. If it's *"let the agent use credentials and vendor
responses without those values leaking back through the chat / logs / a
prompt-injected exfil request"* — that's the slice Denyx covers, and a
deny list architecturally can't.

## 60-second quickstart

**1. Install `denyx` and `denyx-mcp` on your `$PATH`:**

```sh
cargo install denyx-cli denyx-mcp
```

Both binaries land in `~/.cargo/bin/`, which is normally already on your
`$PATH`. This works natively on Linux, macOS, and Windows for the policy
gate, taint redaction, audit log, and host wiring. If you want the
optional Linux-only `bwrap` subprocess sandbox or to run Claude Code v2's
OS sandbox (also Linux/WSL2-side), install Denyx *inside* a Lima VM
(macOS) or WSL2 distro (Windows) — see [Prerequisites](#prerequisites)
and the deployment guides.

> **Building from source instead?** Use this if you need an unreleased
> feature or are contributing:
> ```sh
> git clone https://github.com/Spin42/denyx
> cd denyx
> cargo build --release
> export PATH="$PWD/target/release:$PATH"
> ```

**2. `cd` to the project you want to gate** (NOT the Denyx checkout — your
own codebase), open Claude Code or opencode in that directory, and paste
this as your first message:

> ```
> Fetch and follow https://raw.githubusercontent.com/Spin42/denyx/main/examples/denyx-setup-prompt.md
> ```

The agent will fetch the prompt over HTTPS, then walk through it: detect
your project's language, generate a starter `denyx.toml`, wire `denyx-mcp`
into your project-local MCP config, disable the host's built-in effecting
tools (`Bash`, `Read`, `Write`, `Edit`, `WebFetch`, …), and smoke-test the
setup. It asks five questions about what your project actually needs — answer
honestly, including "no" where applicable. Greenfield projects still get
policy-gated; the questions are about your *intent*, not the current code.

If you'd rather audit what the agent is about to do before pasting, the
prompt is plain markdown:
[`examples/denyx-setup-prompt.md`](examples/denyx-setup-prompt.md).

**3. Restart Claude Code or opencode.** After the restart, the model sees
Denyx's gated tools instead of the built-in ones. Every effecting operation
in this project is checked against `denyx.toml`, and every gated call —
allowed *and* denied — lands in `./.denyx/audit.jsonl` as a SHA-256-chained
JSON Lines record you can later verify with `denyx audit verify`.

## Prerequisites

**Required:** a **Rust toolchain 1.74+** for `cargo install denyx-cli denyx-mcp`
(or to build from source).

**One way to use Denyx — pick one or more:**

- [**Claude Code**](https://github.com/anthropics/claude-code) — Denyx wires
  in as an MCP server and locks down the built-in tools. See
  [docs/09-claude-code.md](docs/09-claude-code.md).
- [**opencode**](https://opencode.ai) — same shape; one `denyx.toml`, both
  hosts. See [docs/10-opencode.md](docs/10-opencode.md).
- **Other MCP-aware coding hosts** — GitHub Copilot's agent mode, Cursor,
  [Continue](https://continue.dev), [Cline](https://cline.bot), and others
  all consume MCP servers; the wiring pattern is the same as Claude Code's
  but each host has its own settings file. The MCP entry generated by
  `denyx host-config` is portable JSON; the lockdown layer is per-host.
- **Local-executor pattern** — Ollama running a small model under the gate
  while a cloud model orchestrates. Cheaper, stronger trust boundary, and
  hits 28-31/31 on the eval suite. See
  [docs/12-local-executor.md](docs/12-local-executor.md).
- **Standalone CLI** — `denyx run script.star --policy denyx.toml` for
  CI/cron/scripts with no host at all. See
  [docs/08-quickstart.md](docs/08-quickstart.md).

**Optional (Linux only):** `bubblewrap` for `[subprocess].sandbox = "bwrap"`
mode — wraps any subprocess spawned from your Starlark policy in a kernel
namespace jail. **Off by default**; install with `apt install bubblewrap`
if you want it. The rest of Denyx (the policy gate, taint redaction, audit
log, MCP wiring, host lockdown) works on every platform without it.

**Platform notes:** Denyx is platform-portable. The tested deployment shape
uses [Lima](https://lima-vm.io/) on macOS and WSL2 on Windows — not because
the language-level gate needs them, but because `bubblewrap` and Claude
Code v2's OS sandbox are Linux-side features. Native macOS and Windows
builds work for the policy gate (no platform-specific code paths, untested
in CI). See [docs/macos-deployment.md](docs/macos-deployment.md) and
[docs/windows-deployment.md](docs/windows-deployment.md) for the
recommended VM setups.

## What Denyx actually does

You write a `denyx.toml` that says exactly what the agent is allowed to do:

```toml
inherits = "secure-defaults"   # baseline denies for credentials,
                                # cloud-metadata IPs, dangerous commands,
                                # secret env vars

[filesystem]
read_allow      = ["src/**", "tests/**"]
local_only_read = ["~/.config/myapp/token"]    # readable, never bubbles up
write_allow     = ["src/**", "/tmp/**"]

[network]
http_get_allow   = ["api.github.com"]
local_only_hosts = ["api.openai.com"]          # response tainted at boundary
deny_ips         = ["169.254.0.0/16", "10.0.0.0/8"]   # CIDR-aware

[environment]
local_only_vars = ["OPENAI_API_KEY"]            # agent can use it; can't leak it

[subprocess]
allow_commands = ["git", "make", "python3"]

[subprocess.deny_args]
git = ["push --force", "reset --hard"]
```

The runtime enforces this with three layers, all in Rust — **none rely on
the model behaving**:

1. **Pre-execution verifier** rejects scripts referencing capabilities whose
   resource section is empty before evaluation starts.
2. **Capability gate at every call** re-checks the policy at runtime; a
   forbidden read / write / fetch / exec raises a typed error and the
   operation never happens.
3. **Output-boundary redaction** scrubs any `local_only_*` value from printed
   output, audit-log payloads, and MCP tool results — so a secret the agent
   reads cannot bubble up to your chat transcript even if the model puts it
   in a string. The transform set covers reverse, hex, single-byte XOR,
   base64 (std + url-safe), ROT-1..25, plus subsequence-chunking detection.

Three visibility levels per resource: **forbidden** / **local-only** /
**public**. Default-deny everywhere; deny wins over allow.

## Customising the policy

The setup prompt's starter `denyx.toml` covers the common stacks (Python,
Node, Rust, Ruby, Go) sensibly, but every real project will want tuning.
Useful entry points, in roughly the order you'll need them:

- **[docs/06-policy-file.md](docs/06-policy-file.md)** — every section,
  every option, worked examples. *Read this first when customising.*
- **[docs/04-security-threat-model.md](docs/04-security-threat-model.md)** —
  what Denyx does and does **not** defend against. Read this *before*
  relaxing any rule.
- **[examples/policies/](examples/policies/)** — reference policies for
  common project shapes (FastAPI, Rails, …).
- **[docs/11-denyx-for-teams.md](docs/11-denyx-for-teams.md)** — shared
  policy + centralised audit log across many developers, via a small HTTP
  server. The wire spec it has to implement is in
  [docs/server-protocol.md](docs/server-protocol.md) (two endpoints,
  bearer auth, conformance test vectors).

## Diagnosing your setup

Both Denyx binaries ship a `doctor` subcommand for read-only project
preflight. Run it after wiring a project, before relying on the gate
for non-trivial work, or when something looks off.

```sh
# Inspect the current project from denyx-mcp's perspective:
# policy file, host-config wiring, audit-dir, .gitignore, lockdown.
denyx-mcp doctor                     # cwd
denyx-mcp doctor --project-path /…   # explicit

# From denyx-local-mcp's perspective, additionally:
# scan for running local LLM servers, verify chat + embed model
# availability, on Ollama check `num_ctx` for the truncation pitfall.
denyx-local-mcp doctor                                       # scan + project (cwd)
denyx-local-mcp doctor --endpoint http://localhost:11434/v1  # targeted
denyx-local-mcp doctor --no-project                          # LLM-only
```

Both never auto-fix; they print copy-pasteable instructions for
anything that's off. Exit codes: `0` ok, `1` warnings, `2` failures.
Missing `denyx.toml` is reported as INFO with "runtime falls back to
secure-defaults baseline (safe by design)" — not a failure.

## Documentation

The deep dive lives in [`docs/`](docs/) — start with the
[index](docs/README.md). Numbered files (`NN-...md`) are the reading path
01 → 13; lowercase files (`name.md`) are reference, looked up not read.

Most-clicked entries:

| Doc | What's in it |
|---|---|
| [01-why-denyx](docs/01-why-denyx.md) | Problem statement and threat-model framing. Start here when evaluating Denyx. |
| [06-policy-file](docs/06-policy-file.md) | **The most important read.** Every policy section and option, with examples. |
| [08-quickstart](docs/08-quickstart.md) | 5-minute CLI walkthrough — generate, run, audit. The non-MCP version of the quickstart at the top of this README. |
| [09-claude-code](docs/09-claude-code.md) / [10-opencode](docs/10-opencode.md) | Host-specific wiring details, including v1/v2 differences and the built-in-tool lockdown. |
| [05-owasp-agentic-coverage](docs/05-owasp-agentic-coverage.md) | Empirical scoring against the OWASP Agentic Top 10 — 2 strong / 4 partial / 4 out-of-scope by design — with concrete tests behind every position. |

## Status & honest disclosures

Denyx is a serious prototype and a working policy gate, but **not yet
hardened enough to be your default for unattended agentic work**. Keep this
table in mind before deciding where to deploy it:

- **Pre-1.0.** The schema may shift in minor ways before v1.
- **AI-generated codebase.** Most code, tests, and docs were written by
  Claude (Anthropic) under human direction; the architecture and threat
  model are human, the implementation is not. Read diffs before trusting
  them — especially `crates/policy/`, the verifier, and
  `crates/host/src/taint.rs`.
- **No human security engineer has read the code with hostile intent yet.**
  That external review is the single biggest gating item between today and
  unattended production use. What *has* happened: a [16-surface bypass
  assessment](docs/security-audit.md), an [adversarial pentest with
  Sonnet + Opus](docs/security-pentest-report.md) (2 High findings, both
  closed), a [12-technique exfiltration probe](examples/local_executor/run_exfil.py)
  (0 LEAK / 3 WEAK_LEAK / 9 REDACTED), and [`cargo-fuzz` + a
  200 000-iteration regression sweep](fuzz/README.md). All empirical, none
  of which substitutes for a human reviewer.
- **OS isolation is opt-in.** Without `[subprocess].sandbox = "bwrap"`
  (Linux) or running inside the recommended VM (macOS / Windows), Denyx is
  the language-level gate only.
- **`requires_approval` is not always a real user prompt.** The CLI prompts
  on stdin. The MCP server's default `auto` mode sends an MCP elicitation
  when the host advertises the capability and falls back to `auto-deny`
  with a structured tag for the orchestrator otherwise. Most hosts
  (including Claude Code 2.1.x in `-p` mode) don't yet advertise
  elicitation. The runtime denies correctly either way; a real *prompt*
  only appears in the CLI or in elicitation-capable clients. See
  [docs/09-claude-code.md](docs/09-claude-code.md#empirical-findings-what-claude-code-actually-does).

**Recommended use today:** experimental setups, personal projects, and
contained environments where the cost of a Denyx bug is "I have to recover
a VM" — not "my SSH key got exfiltrated." For default-on use across a team
or against production credentials, wait for the external security review.

## License

[MIT](LICENSE) © 2026 Spin42.
