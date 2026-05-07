# Denyx

**Lock down what your AI coding agent can read, write, fetch, and run on your machine — with one TOML file.**

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

## 60-second quickstart

**1. Install `denyx` and `denyx-mcp` on your `$PATH`.** From source, on Linux:

```sh
git clone https://github.com/Spin42/denyx
cd denyx
cargo build --release
export PATH="$PWD/target/release:$PATH"   # or copy to ~/.local/bin
```

macOS and Windows users: the same `cargo build --release` works natively,
but kernel-level subprocess sandboxing (`bwrap`) is Linux-only — see
[Prerequisites](#prerequisites) for the trade-off and the Lima / WSL2
guides if you want sandboxing too. When the crates are published to
crates.io, Step 1 becomes a single
`cargo install denyx-cli denyx-mcp`.

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

The only universally-required dependency is a **Rust toolchain 1.74+** to
build the binaries (or, when crates land on crates.io,
`cargo install denyx-cli denyx-mcp`).

Kernel-level subprocess sandboxing (`[subprocess].sandbox = "bwrap"`) is
**opt-in and Linux-only** — `bubblewrap` relies on Linux user namespaces,
which don't exist on macOS or native Windows. On those platforms you have
two choices: run Denyx natively for the language-level gate only, or run
it inside a Linux VM (Lima on macOS, WSL2 on Windows) to also get bwrap.
Without bwrap, Denyx still enforces the full policy (filesystem / network /
env / subprocess allowlist + taint redaction + audit log) — the script
simply runs in the host's process namespace instead of a kernel-level jail.

| Platform | Required | For kernel-level sandbox (optional) |
|---|---|---|
| **Linux** | Rust toolchain | `apt install bubblewrap` (or your distro's equivalent), then add `sandbox = "bwrap"` under `[subprocess]` in your policy. |
| **macOS** | Rust toolchain — native build works for the language-level gate (untested in CI, but no platform-specific code paths). For the project's tested deployment shape, install [Lima](https://lima-vm.io/) (`brew install lima`) and follow [docs/macos-deployment.md](docs/macos-deployment.md). | `bubblewrap` inside a Lima VM. The macOS deployment guide sets up both. |
| **Windows** | Rust toolchain — native build works for the language-level gate (untested in CI). For the project's tested deployment shape, install WSL2 (`wsl --install -d Ubuntu-24.04`) and follow [docs/windows-deployment.md](docs/windows-deployment.md). | `bubblewrap` inside the WSL2 distro. The Windows deployment guide sets up both. |

You also need [Claude Code](https://github.com/anthropics/claude-code) or
[opencode](https://opencode.ai) installed and reachable. Denyx wires into
them; it does not replace them. To use Denyx standalone (without an MCP
host), the CLI is documented in [docs/08-quickstart.md](docs/08-quickstart.md).

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

- **Pre-1.0.** The schema may shift in minor ways before v1. No published
  crates yet — build from source.
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
