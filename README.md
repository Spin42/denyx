# Denyx

[![CI](https://github.com/Spin42/denyx/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Spin42/denyx/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Spin42/denyx/branch/main/graph/badge.svg)](https://codecov.io/gh/Spin42/denyx)

**A policy file that decides what your AI coding agent can touch.**

Denyx lets an AI coding agent work in your project while a policy you wrote
decides which files it may read or write, which websites it may contact,
which commands it may run and which environment variables it may see. Every
such action goes through Denyx, which checks it against the policy before
it happens. Anything the policy does not allow is refused, whatever the
model was told and whatever it believes.

It works with [Claude Code](https://github.com/anthropics/claude-code),
[opencode](https://opencode.ai) and other MCP-aware coding tools (GitHub
Copilot's agent mode, Cursor, [Continue](https://continue.dev),
[Cline](https://cline.bot)), or on its own from the command line.

> ⚠ **Pre-1.0, mostly AI-written, no human security review yet.** Five
> automated pentest rounds have found real bugs, including critical ones,
> and their reports list what was fixed and what is still open. Use it for
> personal projects and contained environments, not yet for unattended work
> against production credentials. [Full status →](#status--honest-disclosures)

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

## What you get

**Nothing is allowed unless you allow it.** A new policy starts from
`secure-defaults`: no file, website, command or variable is reachable until
you list it, and the baseline also blocks common secrets (`~/.ssh`,
`~/.aws`, `.env` files), cloud metadata addresses and private networks.
When something is both allowed and denied, the deny wins.

**Secrets the agent can use but not leak.** Mark an API key, a file or a
website as *local-only* and the agent can still use it, for example to make
an authenticated request. The value itself is removed from everything that
leaves the run: printed output, error messages, tool results and the audit
log, including common re-encodings such as base64, hex or reversed text.
The set of encodings is finite; a script that invents its own encryption
can get past it ([threat model](docs/04-security-threat-model.md)).

**Commands the agent runs stay confined (Linux).** When the policy lets the
agent run a program such as `python3` or `git`, Denyx starts it inside an
operating-system sandbox (Landlock plus a seccomp filter) that limits it to
the same files the policy allows and blocks the usual escape routes:
talking to other programs on your machine, creating namespaces, or using
the network when the policy grants none. If the sandbox cannot be set up,
the command does not run. On macOS and Windows, and on Linux kernels
without Landlock, commands run unconfined and Denyx prints a warning.
With any network permission the child's network is not filtered.

**Injected instructions cannot widen the policy.** A web page or README can
contain instructions aimed at the model, and the model may follow them.
Denyx does not try to spot those instructions; it checks what the agent
then tries to do. A request to upload your credentials is refused the same
way as any other request the policy does not cover.

**The agent cannot rewrite its own rules.** Denyx refuses to start if the
policy file or the audit log is writable by the agent, and the default
policy also protects the files a later session would trust: `.mcp.json`,
`.claude/` settings, `opencode.json` and git hooks. A misspelled key in your
policy stops the load instead of silently doing nothing.

**A record of every action.** Each request, allowed or refused, is written
to a log where every line is linked to the previous one by a SHA-256 hash.
`denyx audit verify` detects a line that was changed or removed. Deleting
the most recent lines is only detected if you also keep an external record
of how long the log was (`--min-seq`).

**One policy for every tool.** The same `denyx.toml` generates the settings
for Claude Code and opencode (`denyx host-config`), and the MCP entry it
produces works in other MCP hosts. It can also answer Claude Code's own
permission checks for its built-in tools (`denyx hook`); in that mode each
call is checked but local-only values are not hidden. And it runs scripts
directly from the command line or CI (`denyx run`). Teams can fetch the
policy from a server and send the audit log to one place
([docs/11-denyx-for-teams.md](docs/11-denyx-for-teams.md)).

**Tested in the open.** Five pentest rounds are published in
[`docs/`](docs/README.md), each with the findings, how they were fixed and
what remains open. The latest round found three critical bugs, all fixed
in 0.5.0 with a test for each. The repository also ships fuzz targets
([fuzz/](fuzz/README.md)), and mutation testing of the security-critical
code is run locally before releases.

---

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
  MCP-aware host you choose to wire in. Full flag reference at
  [docs/host-config.md](docs/host-config.md).
- **Centralised policy + tamper-evident audit.** Optional team mode fetches
  the active policy from a URL at startup and POSTs every capability call
  to an audit endpoint. Audit lines are SHA-256-chained, so in-place
  tampering or a mid-log deletion is detectable with `denyx audit verify`
  (tail truncation needs `--min-seq` plus an external record of the
  expected length — see [the threat model](docs/04-security-threat-model.md)).
  Neither host has this; their settings are per-machine.
- **MCP tool poisoning prevention.** In the local-executor architecture,
  third-party MCP tool descriptions never enter either model's context.
  The cloud model is offered exactly one tool (`delegate_to_local`); the
  local executor model receives tool routing hints only from the
  operator-controlled policy file. A poisoned description in any
  co-installed MCP server has no path to either model's reasoning —
  structurally excluded, not pattern-matched, **provided `denyx-local-mcp`
  isn't itself wired alongside another MCP server** in the same host
  config; `denyx doctor` checks for that specific misconfiguration.
- **Standalone + local-executor patterns.** Use Denyx as a CLI gate in CI
  with no host at all, or run a small local model under the gate while a
  cloud model orchestrates — the eval at
  [docs/12-local-executor.md](docs/12-local-executor.md) measures both
  shapes against a 36-task suite.

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
`$PATH`. This works natively on Linux, macOS, and Windows; no additional
system packages are required for the policy gate, taint redaction, audit
log, Wasm-sandboxed Starlark runner, or host wiring.

> **Building from source instead?** Use this if you need an unreleased
> feature or are contributing:
> ```sh
> git clone https://github.com/Spin42/denyx
> cd denyx
> cargo build --release
> export PATH="$PWD/target/release:$PATH"
>
> # One-time hook setup so `git commit` runs the same fmt + clippy
> # gates as CI locally. See scripts/precommit.sh for what it runs.
> git config core.hooksPath .githooks
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

**Required:** a **Rust toolchain 1.80+** for `cargo install denyx-cli denyx-mcp`
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
  while a cloud model orchestrates. On the project's 36-task suite the
  local model alone passed 36/36, and with a cloud orchestrator 30/36
  (Sonnet) and 35/36 (Opus); the misses are explained in
  [docs/12-local-executor.md](docs/12-local-executor.md).
- **Standalone CLI** — `denyx run script.star --policy denyx.toml` for
  CI/cron/scripts with no host at all. See
  [docs/08-quickstart.md](docs/08-quickstart.md).

**Platform notes:** the policy gate, taint redaction, audit log, Wasm
Starlark runner, and host wiring run natively on Linux, macOS, and
Windows. The operating-system sandbox for commands the agent runs is
Linux-only (Landlock, kernel 5.13+).

### Isolation model

Denyx enforces in three layers; none relies on the model behaving:

- **Policy gate (Rust).** Every `fs.*` / `net.*` / `subprocess.exec` /
  `env.read` call is checked against the parsed policy before any
  side effect. Default-deny; deny wins over allow. This is the
  primary enforcement.
- **Wasm-sandboxed Starlark interpreter.** The `starlark-rust`
  interpreter is compiled to `wasm32-wasip1` and executed inside
  `wasmtime`. The interpreter's memory and import surface are
  contained at the wasm boundary; a starlark-rust bug stays inside
  the guest, and a pure-CPU runaway in the script is preempted by
  wasmtime fuel. Default in v0.4.0+; pass `--no-wasm` to fall back
  to the in-process runner. Full parity table and the wasmtime
  attack surface added are in
  [docs/wasm-sandbox.md](docs/wasm-sandbox.md).

- **Subprocess sandbox (Linux).** A command the policy allows, such
  as `python3`, is started under Landlock plus a seccomp filter with
  `[subprocess].sandbox = "auto"`, the default. It can reach only the
  paths the policy grants (minus anything in `[filesystem].deny`),
  cannot open sockets to other programs on the machine, cannot create
  namespaces, and has no network unless the policy grants some. If the
  sandbox cannot be enforced the command does not run. On macOS,
  Windows and Linux kernels without Landlock the command runs
  unconfined, with a warning, and is bounded only by `allow_commands`,
  the argv path check and `subprocess.deny_args`. See
  [docs/landlock-evaluation.md](docs/landlock-evaluation.md).

Outside the scope of all three: a child process's network once the
policy grants any network, and the model's own reasoning. Denyx
checks what the script does, not what the model decides.

Empirical basis: five pentest rounds, white-box and AI-driven, each
with a small tester panel (single-shot per technique), so results
don't generalise past the panel. See "Security validation" below and
[docs/wasm-sandbox.md](docs/wasm-sandbox.md) for the wasm runner's
layer-by-layer accounting.

### Optional: Claude Code v2's OS sandbox

Claude Code v2 ships its own OS-level sandbox stanza (Seatbelt on
macOS, bubblewrap on Linux/WSL2). `denyx host-config --sandbox auto`
emits it derived from the policy's allow lists. This is Claude
Code's feature; Denyx wires its config, it doesn't enforce it. See
[docs/macos-deployment.md](docs/macos-deployment.md) and
[docs/windows-deployment.md](docs/windows-deployment.md) for VM-
hosted setups that exercise the Linux-side variant.

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

`denyx doctor` is the single entry point for "is my Denyx setup
right?". Run it after wiring a project, before relying on the gate
for non-trivial work, or when something looks off.

```sh
# Canonical: project-side checks + cross-cutting consistency
# (policy ↔ host-config ↔ launch-flag ↔ project state).
denyx doctor                     # cwd
denyx doctor --project-path /…   # explicit
denyx doctor --fix               # interactive auto-fix (mkdir audit
                                 # dir, append .gitignore, re-emit
                                 # stale sandbox stanza / deny list)

# Narrower variants for when only the MCP binary is on PATH (e.g.
# inside a Lima VM or WSL2 distro):
denyx-mcp doctor                                             # project-side only
denyx-local-mcp doctor                                       # + local-LLM scan
denyx-local-mcp doctor --endpoint http://localhost:11434/v1  # targeted
denyx-local-mcp doctor --no-project                          # LLM-only
```

`--fix` is interactive (asks `y/N`) and refuses when stdin isn't a
TTY, so CI invocations are safe even with `--fix` accidentally passed.
Decisions that require operator judgment (allow-list additions,
capability grants) are never auto-fixed — they remain in the report.
Exit codes: `0` ok, `1` warnings, `2` failures. Missing `denyx.toml`
is reported as INFO with "runtime falls back to secure-defaults
baseline (safe by design)" — not a failure. Full flag reference at
[docs/doctor.md](docs/doctor.md).

## Security validation

Five pentest rounds so far, all AI-driven, white-box and small-panel.
Each report states the sample size and what remains open:

| Round | Focus | Result |
|---|---|---|
| [1](docs/security-pentest-report.md) | Leaking local-only secrets | 2 High, fixed |
| [2](docs/security-pentest-r2-tool-poisoning.md) | Injected instructions, 4 local models | Every model followed the injections and prompt-side wrappers did not help; the runtime checks stopped every leak |
| [3](docs/security-pentest-r3-argv0-and-chunking.md) | Command execution, chunked leaks | 1 Critical, 3 High, fixed |
| [4](docs/security-pentest-r4-wasm-path-regressions.md) | The wasm runner against the native one | 2 High, 2 Medium, fixed |
| [5](docs/security-pentest-r5-wasm-rawpath-and-sandbox-parity.md) | Filesystem, network, subprocess sandbox, MCP | 3 Critical, 10 High, 11 Medium, 7 Low; all Critical, 9 High (1 partly) and 8 Medium fixed in 0.5.0, the rest open and listed |

Separately, the wasm runner was exercised in 5 LLM-driven runs (Opus
n=3, Sonnet n=2, 112 attempts) with no leak observed; that panel did
not find what Rounds 4 and 5 later found, which is the clearest
reason not to read any single round as proof.
[docs/wasm-sandbox.md](docs/wasm-sandbox.md) has the layer-by-layer
accounting.

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
| [07-wasm-sandbox](docs/wasm-sandbox.md) | The Wasm-sandboxed Starlark runner: default in v0.4.0+ (pass `--no-wasm` to opt out). Parity table vs the in-process runner, fuel-based preemption, threat-model deltas, pentest result. |
| [comparison](docs/comparison.md) | How Denyx compares to host built-ins, MCP gateways, LLM guardrails, IFC research, and audit-shape peers. Read when evaluating Denyx vs alternatives. |
| [host-config](docs/host-config.md) / [doctor](docs/doctor.md) | Reference pages for the two CLI commands you'll re-run most often: `denyx host-config` (cross-host wiring) and `denyx-mcp doctor` / `denyx-local-mcp doctor` (preflight). |

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
- **The Wasm-sandboxed Starlark runner is the default in v0.4.0+.**
  `denyx run` and `denyx-mcp` dispatch through the wasmtime runner unless
  `--no-wasm` is passed (which selects the legacy in-process path).
  An early 5-run, 112-attempt LLM-driven test found no leak; Rounds 4
  and 5 later found wasm-path bugs it had missed, all fixed. Full
  accounting in [docs/wasm-sandbox.md](docs/wasm-sandbox.md).
- **No human security engineer has read the code with hostile intent yet.**
  That external review is the single biggest gating item between today and
  unattended production use. What *has* happened: a [16-surface bypass
  assessment](docs/security-audit.md), the five pentest rounds in
  [Security validation](#security-validation), a
  [12-technique exfiltration probe](examples/local_executor/run_exfil.py)
  (0 LEAK / 2 WEAK_LEAK / 10 REDACTED, current as of the round-3 fixes),
  and [`cargo-fuzz` + a 200 000-iteration regression
  sweep](fuzz/README.md). All automated, none of which substitutes for a
  human reviewer — and each round has found something the previous one
  missed, which is itself a reason for caution, not reassurance.
- **Subprocess isolation is Linux-only and partial.** Since 0.5.0 a
  command the agent runs is confined by Landlock and seccomp on Linux
  (see [Isolation model](#isolation-model)). It is not confined on macOS,
  Windows or kernels without Landlock, its network is unfiltered once
  the policy grants any network, it has no time limit, and it can keep
  running after the script ends. If your threat model needs more, run
  Denyx inside a VM or container. `[subprocess].sandbox = "bwrap"` is
  still available but deprecated.
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
