# The Local-Executor Architecture

> ← [Back to docs README](README.md)

This document covers the agentic-setup shape Denyx was designed for: a
**cloud orchestrator** (Sonnet, Opus, or any other large model)
delegates atomic steps to a **local executor model** (a 7B running on
the user's machine via Ollama), which emits Starlark programs that
**Denyx** enforces against a project policy.

It's the architecture the project's evaluation harness measures, and
the one that makes the local-only-secrets feature
([06-policy-file.md](06-policy-file.md#how-local-only-works)) actually
useful — secrets stay on the local side, the cloud side never sees
them.

## The shape

```
   ┌──────────────────────────────────┐
   │   Cloud orchestrator             │   Sonnet / Opus / etc.
   │   (e.g. via `claude -p`)         │   sees ONE tool: delegate_to_local
   └──────────────────────────────────┘
                  │
                  │  delegate_to_local("read manifest, extract version")
                  ▼
   ┌──────────────────────────────────┐
   │   local_mcp.py                   │   MCP server you launch.
   │   (examples/local_executor/)     │   bridges orchestrator ↔ local model.
   └──────────────────────────────────┘
                  │
                  │  prompts qwen with system_prompt + step + RAG-retrieved examples
                  ▼
   ┌──────────────────────────────────┐
   │   qwen2.5-coder:7b (Ollama)      │   emits a Starlark program.
   │   on http://localhost:11434      │
   └──────────────────────────────────┘
                  │
                  │  Starlark source
                  ▼
   ┌──────────────────────────────────┐
   │   denyx-mcp                      │   subprocess of local_mcp.py.
   │   (subprocess of local_mcp.py)   │   enforces the project policy.
   └──────────────────────────────────┘
                  │
                  │  permitted side effects
                  ▼
   ┌──────────────────────────────────┐
   │   filesystem / network /         │
   │   subprocess / env               │
   └──────────────────────────────────┘
```

Three things to note:

- **The cloud orchestrator never directly emits Starlark.** It
  decomposes the task into a sequence of atomic steps and hands each
  step's *description* to `delegate_to_local`. The local model
  synthesizes the actual code.
- **Each delegate call is independent.** Inter-step state crosses only
  through what the local model writes to disk. The orchestrator
  composes the next step's description based on the previous step's
  summary text.
- **Denyx is the bottom of the stack.** Every side effect — every file
  read, network call, subprocess — runs through it under one policy.
  One audit log captures the whole run.

## What's in `examples/local_executor/`

| File                  | Role                                                                  |
|-----------------------|-----------------------------------------------------------------------|
| `run.py`              | Phase 1 harness: single-step tasks, local 7B alone, **no orchestrator**. |
| `run_multistep.py`    | Phase 1.5: 36 multi-step tasks, local 7B alone, **no orchestrator**. |
| `run_orchestrated.py` | Phase 2: same 36-task suite, with Sonnet/Opus on top via `claude -p`. |
| `local_mcp.py`        | The bridge MCP server: delegate_to_local → qwen → denyx-mcp.         |
| `rag.py`              | Embedding-based retrieval (nomic-embed-text + 19 worked examples).   |

## What's measured

> **Layer split.** Phase 1 and Phase 1.5 are `qwen2.5-coder:7b`
> doing 100% of the work — no cloud orchestrator, no `claude`
> binary, no Anthropic API call. Phase 2 layers Sonnet/Opus *on
> top* of the same qwen+Denyx stack, with the cloud model
> responsible only for task decomposition and step routing while
> qwen still writes every Starlark program. Each phase's numbers
> are independent measurements.

All numbers use `examples/policies/multistep_test.toml` as the
policy. The current task suite has 36 tasks (was 31): file
manipulation (6), HTTP+JSON (6), subprocess composition (5),
cross-capability flows (5), aggregation (4), deny-correct cases
(8), and feature-demo tasks (2 LOCAL_ONLY) — the 5 newest tasks
specifically pin the recent security fixes.

### Phase 1: single-step (`run.py`) — qwen alone

10/10 tasks pass at 270–960 ms each. 5 success cases (read
`/etc/hostname`, fetch `api.github.com/zen`, write `/tmp/denyx_demo`,
exec `git --version`, read `$USER`) and 5 deny cases (write
`~/.aws/credentials`, `rm -rf`, IMDS SSRF `169.254.169.254`,
`git push --force`, read `$AWS_SECRET_ACCESS_KEY`). Every denial fired
through the right rule.

### Phase 1.5: multi-step, local-only (`run_multistep.py`) — qwen alone

**Most recent fresh run: 36/36** with the 36-task expanded suite,
the embedding-based RAG, and one validator-in-loop retry. **No
cloud model involved at any step**: the harness has no `claude`
or API integration; qwen reads each task description, writes the
Starlark, hands it to `denyx-mcp`, and on a parser/policy error
gets to retry once with the error fed back as context.

The historical narrative on how the suite reached this number on
the original 31-task version:

- A vanilla "Starlark is a Python subset" prompt landed 21/31. The
  remaining 10 failures were all the same root cause: the 7B model
  wrote `import json` and f-strings — Python idioms Starlark doesn't
  support.
- **In-context RAG**: embed-retrieve the top-4 worked examples from a
  19-example library (`rag.py`) and include them in the system prompt.
  Lifted to ~26-27/31.
- **Validator-in-loop retry**: feed Denyx's parser/policy errors back
  to the model and let it re-emit. Max 1 retry. Final 28-29/31.
- After the security-fix work and refreshing some stale GitHub URLs:
  the suite is now stable at 36/36 (with the 5 new feature-demo
  tasks pinning specific runtime layers).

The runtime stayed strictly Starlark throughout. The methodology
finding — *"stay close to Starlark, don't bend it"* — is load-bearing:
every gap closed via prompting/RAG/retry rather than dialect
relaxation.

### Phase 2: orchestrated (`run_orchestrated.py`) — Sonnet/Opus + qwen

Sonnet or Opus runs as the orchestrator (via the `claude` CLI),
restricted to a single tool: `delegate_to_local`. The bridge
forwards each step description to qwen, which writes Starlark,
which `denyx-mcp` runs. **qwen still does all the code synthesis.**
The cloud model contributes task decomposition and step routing.

Most recent run, 36-task suite, both models, `--include-network`,
fresh GitHub rate-limit window:

| Orchestrator | Passed | Total cost | Avg turns |
|--------------|--------|-----------:|----------:|
| sonnet       | 30/36  | $1.373     | 2.3       |
| opus         | 35/36  | $2.825     | 2.4       |

The numbers need two pieces of context to read honestly:

1. **Sonnet's preemptive-refusal pattern.** 4 of Sonnet's 6 misses
   are on DENY tasks where the task description names a "scary"
   path (`/etc/passwd`, `AWS_SECRET_ACCESS_KEY`, `169.254.169.254`)
   and Sonnet refuses to delegate any step at all — preempting
   Denyx's policy enforcement. The runtime would have correctly
   denied if Sonnet had tried; instead Sonnet decided not to try.
   This was a documented architecture finding from the previous
   31-task orchestrated run; it reproduces here.
2. **Verify-hook substring strictness.** Three of the new
   feature-demo tasks check that the orchestrator's final summary
   contains specific substrings — `subprocess.exec` in the error
   reason, `[REDACTED]` in the redaction output. The runtime
   layers fired correctly in every case, but both models
   occasionally *paraphrase* qwen's literal output ("content was
   redacted by Denyx policy when printed") instead of preserving
   the exact sentinel. This accounts for 2 of Sonnet's misses and
   the single Opus miss (`LOCAL_ONLY_fs_redaction`). It's a
   harness limitation, not a security failure.

A third caveat applies to *back-to-back* runs but did not affect
the numbers above: the unauthenticated `api.github.com` quota is
60 req/hour, and the previous documented run had Opus running
second after Sonnet had drained most of the quota — that
swallowed 6 of Opus's tasks in HTTP 403s. With a fresh quota
(this run), Opus reaches 35/36. If you reproduce these locally
back-to-back, expect the second model to take a hit unless you
either wait an hour between runs or set `GH_TOKEN` for an
authenticated 5000/hour quota.

Adjusting for these — Sonnet effectively achieves 30/36 the runtime
honestly enforced, and Opus reaches 35/36 with the single miss
being a paraphrase issue rather than a runtime regression. The
local-only qwen Phase 1.5 number (36/36) remains the cleanest
measurement of "does the runtime do what it says"; the
orchestrated numbers measure
"does the runtime + a cloud orchestrator + GitHub's rate-limiter
all cooperate".

All 3 sonnet misses had the same shape: the task description named a
"scary string" (`AWS_SECRET_ACCESS_KEY`, `169.254.169.254`,
`/etc/passwd`), and Sonnet refused to delegate any step at all. Opus
attempted the legitimate prefix step, then delegated the offending step
which Denyx blocked — generating an audit trail.

That's an architecturally interesting result: defense-in-depth at the
*orchestrator* is real but reduces Denyx's audit visibility. For a
security tool that needs an evidentiary trail, you want the runtime to
be the layer that says no.

## Using it in your own project

The local-executor stack is not a single binary — `local_mcp.py` is a
Python bridge that lives in `examples/local_executor/`. Wiring it
into Claude Code or opencode for **your own work** (not just for
reproducing the eval) means pointing the host at that script in a
Denyx checkout and disabling the host's own built-in tools so the
model has no path to side effects except through the bridge.

### What changes vs. the standard Denyx wiring

If you've already wired `denyx-mcp` directly per
[08-quickstart.md](08-quickstart.md), here's the diff:

|                       | Direct (`denyx-mcp`)                  | Local-executor (`local_mcp.py`)                 |
|-----------------------|---------------------------------------|-------------------------------------------------|
| MCP `command`         | `denyx-mcp`                           | `python3`                                       |
| MCP `args`            | `--policy ./denyx.toml ...`           | `<path>/local_mcp.py --policy ./denyx.toml ...` |
| Tools the model sees  | Full `denyx_*` family                 | `delegate_to_local` only                        |
| Who writes Starlark   | The cloud model                       | The local 7B (qwen2.5-coder:7b)                 |
| Cloud-side context    | Every `fs.read` body, HTTP response, env value | Only the bridge's per-step result string |
| Per-call latency      | Pipe round-trip (~ms)                 | + qwen inference (1–4 s typical)                |
| Cost shape            | Cloud API tokens for every effect     | Cloud API for delegation only; local inference is free |

Step 1 (policy) and Step 4 (built-in lockdown) are identical to the
standard flow. Step 2 (MCP config) and Step 3 (Ollama) are what
differ.

### Step 0 — Prerequisites

| Component                   | Why                                                                                       | Install                                                  |
|-----------------------------|-------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Denyx **source checkout**   | `local_mcp.py` is a Python script; `cargo install` does not bundle it.                    | `git clone https://github.com/Spin42/denyx`              |
| `denyx-mcp` binary          | The bridge spawns it as a subprocess.                                                     | `cargo install denyx-cli denyx-mcp` (or source build)    |
| Ollama + `qwen2.5-coder:7b` | The local executor model. ~5 GB.                                                          | `ollama pull qwen2.5-coder:7b`                           |
| Ollama + `nomic-embed-text` | RAG retrieval. Without it the model writes worse Starlark. ~270 MB.                       | `ollama pull nomic-embed-text`                           |
| Python 3.11+                | `local_mcp.py` uses stdlib `tomllib`.                                                     | OS package manager                                       |
| Claude Code 2.x or opencode | The cloud orchestrator.                                                                   | See [09-claude-code.md](09-claude-code.md) / [10-opencode.md](10-opencode.md) |

`bubblewrap` is not required for this flow unless your `denyx.toml`
opts into the Linux kernel sandbox.

### Step 1 — Write your `denyx.toml`

Same as the standalone-MCP flow. From your own project's root:

```sh
cd ~/myproject
denyx init --lang python --output denyx.toml
# edit to allow the paths, hosts, env vars, and commands you actually
# need — see docs/08-quickstart.md for the full walkthrough.
```

Two policy entries earn their keep specifically in the local-executor
flow:

- `[environment].local_only_vars = ["OPENAI_API_KEY"]` — the local 7B
  can read the value; the cloud orchestrator never sees it. The
  bridge redacts at the boundary.
- A `[tools.WebSearch]` long-form entry with `backend_url`.
  `local_mcp.py` reads the routing hint and injects "for WebSearch,
  GET this URL" into the local model's prompt — see
  [URL choice and search-style tasks](#url-choice-and-search-style-tasks)
  below.

### Step 2 — Wire `local_mcp.py` into Claude Code or opencode

The MCP config now points at the Python bridge instead of `denyx-mcp`
directly.

**Claude Code** — write `./.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "local-executor": {
      "command": "python3",
      "args": [
        "/abs/path/to/denyx/examples/local_executor/local_mcp.py",
        "--policy", "./denyx.toml",
        "--audit-log", "./.denyx/audit.jsonl"
      ]
    }
  }
}
```

**opencode** — write `./opencode.json` in your project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "tools": {
    "bash": false, "read": false, "write": false, "edit": false,
    "glob": false, "grep": false, "webfetch": false, "websearch": false
  },
  "mcp": {
    "local-executor": {
      "type": "local",
      "command": [
        "python3",
        "/abs/path/to/denyx/examples/local_executor/local_mcp.py",
        "--policy", "./denyx.toml",
        "--audit-log", "./.denyx/audit.jsonl"
      ],
      "enabled": true
    }
  }
}
```

Two things to know about that path:

- **The path to `local_mcp.py` must be absolute.** Both hosts resolve
  relative paths from wherever they were launched (often `/`,
  sometimes `$HOME`), not your project directory. Hard-code the full
  path to your Denyx checkout.
- **`local_mcp.py` looks for `denyx-mcp` at
  `<denyx-checkout>/target/release/denyx-mcp` by default.** If
  you've installed via `cargo install denyx-cli denyx-mcp` and
  there's no `target/release/` next to `local_mcp.py`, pass the
  binary location explicitly:

  ```diff
    "args": [
      "/abs/path/to/denyx/examples/local_executor/local_mcp.py",
      "--policy", "./denyx.toml",
      "--audit-log", "./.denyx/audit.jsonl",
  +   "--mcp-bin", "/home/YOU/.cargo/bin/denyx-mcp"
    ]
  ```

  Use `which denyx-mcp` on the shell where the host runs to find the
  exact path.

Make sure `./.denyx/` exists and is gitignored before launching the
host:

```sh
mkdir -p ./.denyx
grep -q '^\.denyx/' ./.gitignore 2>/dev/null || echo '.denyx/' >> ./.gitignore
```

### Step 3 — Make sure Ollama is running

```sh
# Confirm Ollama responds:
curl -sf http://localhost:11434/api/tags | head -c 200

# Confirm both models are pulled:
ollama list | grep -E "qwen2.5-coder:7b|nomic-embed-text"
```

If Ollama is not running, the first `delegate_to_local` call returns
a connection error and the orchestrator surfaces it as a tool
failure. The fix is `ollama serve` (or restart whatever launches it
on your machine — systemd unit, brew service, etc.).

### Step 4 — Disable the host's built-in tools

**Critical step.** Without this, Claude Code uses its built-in
`Read`, `Bash`, `Edit`, `WebFetch` etc. — none of which go through
`local_mcp.py`. The whole point of the local-executor architecture
is keeping secrets off the cloud side, and a built-in `Read` defeats
it: the model just calls `Read("$HOME/.aws/credentials")` and the
file body lands in the cloud orchestrator's context, no Denyx, no
redaction.

**Claude Code** — write `./.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Bash", "Edit", "Write", "Read",
      "Glob", "Grep", "WebFetch", "WebSearch",
      "Monitor", "NotebookEdit"
    ]
  },
  "disableBypassPermissionsMode": "disable"
}
```

(`disableBypassPermissionsMode` is silently ignored on Claude Code
v1; including it unconditionally is safe.)

**opencode** — already handled by Step 2's `tools: false` block. No
extra file required.

After this step the only effecting tool the model can call is
`mcp__local-executor__delegate_to_local`. Every file read, HTTP
fetch, and subprocess in your session goes through the local 7B →
Denyx pipeline.

### Step 5 — Smoke test

Restart Claude Code (or opencode) in the project directory. Send a
one-step probe like:

> Use the local executor to print the first line of `README.md`.

Expected behaviour: the host calls `delegate_to_local` once, the
bridge spawns qwen (~10–30 s on the first call as the model loads
into VRAM, 1–4 s thereafter), qwen emits a Starlark program, Denyx
runs it under your policy, and the printed first line flows back to
the chat. Tail `./.denyx/audit.jsonl` while you test — every gated
call lands as one JSON line.

Common failure shapes:

| Symptom | Likely cause |
|---|---|
| Host calls `Read` / `Bash` directly instead of `delegate_to_local` | Step 4 did not take. Re-check `.claude/settings.json` (Claude Code) or the `tools` block in `opencode.json` (opencode). On Claude Code v2, also confirm `disableBypassPermissionsMode: "disable"` is set. |
| `local_mcp.py: cannot connect to ollama` | Ollama isn't running on `:11434`. `ollama serve` or restart the daemon. |
| `Denyx: parser error` after a `delegate_to_local` call | Local 7B emitted invalid Starlark. The bridge auto-retries once with the error fed back; if it still fails, the model genuinely can't write that program — try a simpler step description or add `[tools.X]` routing hints. |
| First `delegate_to_local` takes 30+ seconds | Normal cold-start (qwen loading into VRAM). Subsequent calls are seconds. |
| `cannot find local_mcp.py` at startup | Path isn't absolute or your Denyx checkout has moved. |

## Reproducing the eval numbers

The headline numbers — qwen alone **36/36**, Sonnet-orchestrated
**30/36** ($1.37), Opus-orchestrated **35/36** ($2.83) — are
reproduced by `python3 examples/local_executor/run_orchestrated.py
--models sonnet opus --all`. Full guide with per-task expectations,
flags, and budget caps in [13-running-examples.md](13-running-examples.md).

## How `local_mcp.py` works

`local_mcp.py` is an MCP server that exposes a single tool:

```
delegate_to_local(step: string, [files: list[string]]) -> string
```

When the orchestrator calls it, `local_mcp.py`:

1. Builds a system prompt that explains the Starlark dialect
   constraints (no f-strings, no top-level for/if, no imports), the
   namespaced builtins (`fs.read`, `net.http_get`, ...), and includes
   the top-4 RAG-retrieved worked examples.
2. Sends the step description + system prompt to `qwen2.5-coder:7b`
   via Ollama's `/api/chat`.
3. Extracts the Starlark program from the response.
4. Spawns `denyx-mcp` as a subprocess (or reuses one), and calls
   `denyx_run` with the program and the policy already configured at
   server startup.
5. Returns a response containing:
   - A `[local-executor model=qwen2.5-coder:7b retries=N duration=Nms]`
     header
   - The Starlark program
   - Denyx's result (printed lines, or the policy-violation reason on
     failure)

If Denyx rejects the program with a parser or policy error,
`local_mcp.py` re-prompts qwen with the error message attached and
retries (max 1 retry). This is the "validator-in-loop" mechanic —
it's what bridges the gap between "qwen emits something almost-right"
and "Denyx accepts it".

## Why this stack matters

A pure cloud-only agent shape (orchestrator → tools) leaks
everything: every file, every API key, every command shows up in the
orchestrator's context. With this stack:

- The cloud orchestrator sees one *result string* per delegated step.
  Source files, env vars, HTTP responses — none of it directly enters
  the orchestrator's context.
- Tainted values (`local_only_*` policy entries) get scrubbed at the
  Denyx boundary before the result string crosses to the orchestrator.
  The cloud side literally cannot see your `OPENAI_API_KEY`.
- One policy file governs the entire run. The audit log is one file.
- The local model can be cheap (qwen 7B at ~7 GB on disk, ~30 s/task on
  a modern laptop). The cloud model only handles task decomposition,
  which is what large models are best at.

## URL choice and search-style tasks

A natural follow-up question: when the orchestrator sends
`delegate_to_local("search the web for X")`, how does the local 7B
know which search backend to hit? The policy file lists allowed
hosts in `[network].http_get_allow`, but a list of permitted hosts
isn't a routing instruction.

The answer is the long-form `[tools.X]` entry, which carries a
`backend_url` routing hint alongside the required capabilities:

```toml
[tools.WebSearch]
capabilities   = ["net.http_get"]
backend_url    = "https://api.duckduckgo.com/?format=json&no_html=1&skip_disambig=1&q="
backend_method = "GET"
description    = "DuckDuckGo Instant Answer API (public, non-tracking, JSON)."

[network]
http_get_allow = ["api.duckduckgo.com"]
```

A bridge like `local_mcp.py` can read `backend_url` and inject
"for WebSearch, GET this URL" into the system prompt — the model
no longer guesses. The default DuckDuckGo Instant Answer URL is
public, non-tracking, no-auth, returns JSON, and verified end-to-end
in this repo. Note: it returns abstracts and definitions for
famous-entity queries, not full web search — for broader coverage
swap for a self-hosted SearxNG (`docker run -p 8888:8080
searxng/searxng`), Brave Search, Tavily, etc. by changing one line
in the policy.

In all cases, Denyx is the enforcement layer: whatever URL the
model picks, it must match `[network].http_get_allow` /
`http_post_allow` or the call fails with a clear deny error, and
validator-in-loop retry can re-prompt the model. The routing hint
is a UX nudge, not a security boundary. See
[06-policy-file.md](06-policy-file.md#tools) for the full schema.

## Tradeoffs

The good:

- Strong locality of secrets and source.
- Strong audit story: one log, one policy.
- Cost-effective — the orchestrator only sees compact step
  descriptions, not raw context.

The not-so-good:

- Two-hop latency per step. Each `delegate_to_local` call is a 5-15 s
  round-trip (qwen inference + Denyx run).
- Orchestrator sometimes refuses preemptively (the Sonnet pattern
  above). Treat it as "defense at two layers" — annoying when your
  task description happens to mention `/etc/passwd`, useful when the
  task is actually trying to read it.
- Local-only enforcement covers the documented set of practical
  transforms (reverse, hex, single-byte XOR, hex(XOR), chunking)
  plus arg-side denial at every outbound effect — the exfil probe
  reports 0 LEAK / 3 WEAK_LEAK / 9 REDACTED. A determined adversary
  bringing their own crypto (AES with a script-generated key) still
  escapes; defeating that would require real value-level taint
  propagation through the Starlark evaluator. See
  [04-security-threat-model.md](04-security-threat-model.md) for the
  honest scope.

## Where next

- [06-policy-file.md](06-policy-file.md#how-local-only-works) — the
  local-only feature in detail.
- [09-claude-code.md](09-claude-code.md) — Claude Code integration.
- [10-opencode.md](10-opencode.md) — opencode integration.
- [02-from-sigil.md](02-from-sigil.md) — design history; in particular,
  why the local executor uses stock Starlark + a stock 7B rather than
  Sigil's bespoke-DSL + fine-tuned-model approach.
