# The Local-Executor Architecture

> ← [Back to docs README](README.md)

This document covers the agentic-setup shape Aegis was designed for: a
**cloud orchestrator** (Sonnet, Opus, or any other large model)
delegates atomic steps to a **local executor model** (a 7B running on
the user's machine via Ollama), which emits Starlark programs that
**Aegis** enforces against a project policy.

It's the architecture the project's evaluation harness measures, and
the one that makes the local-only-secrets feature
([04-policy-file.md](04-policy-file.md#how-local-only-works)) actually
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
   │   aegis-mcp                      │   subprocess of local_mcp.py.
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
- **Aegis is the bottom of the stack.** Every side effect — every file
  read, network call, subprocess — runs through it under one policy.
  One audit log captures the whole run.

## What's in `examples/local_executor/`

| File                  | Role                                                                  |
|-----------------------|-----------------------------------------------------------------------|
| `run.py`              | Phase 1 harness: single-step tasks, local 7B alone, no orchestrator. |
| `run_multistep.py`    | Phase 1.5: 31 multi-step tasks, local 7B alone, no orchestrator.     |
| `run_orchestrated.py` | Phase 2: same 31 tasks, with Sonnet/Opus on top via `claude -p`.     |
| `local_mcp.py`        | The bridge MCP server: delegate_to_local → qwen → aegis-mcp.         |
| `rag.py`              | Embedding-based retrieval (nomic-embed-text + 19 worked examples).   |

## What's measured

All numbers from running `qwen2.5-coder:7b` as the local executor and
`examples/policies/multistep_test.toml` as the policy. The 31-task
suite covers file manipulation (6), HTTP+JSON (6), subprocess
composition (5), cross-capability flows (5), aggregation (4), and
deny-correct cases (5).

### Phase 1: single-step (`run.py`)

10/10 tasks pass at 270–960 ms each. 5 success cases (read
`/etc/hostname`, fetch `api.github.com/zen`, write `/tmp/aegis_demo`,
exec `git --version`, read `$USER`) and 5 deny cases (write
`~/.aws/credentials`, `rm -rf`, IMDS SSRF `169.254.169.254`,
`git push --force`, read `$AWS_SECRET_ACCESS_KEY`). Every denial fired
through the right rule.

### Phase 1.5: multi-step, local-only (`run_multistep.py`)

A vanilla "Starlark is a Python subset" prompt landed 21/31. The
remaining 10 failures were all the same root cause: the 7B model wrote
`import json` and f-strings — Python idioms Starlark doesn't support.

Two non-runtime levers closed the gap:

- **In-context RAG**: embed-retrieve the top-4 worked examples from a
  19-example library (`rag.py`) and include them in the system prompt.
  Lifted to ~26-27/31.
- **Validator-in-loop retry**: feed Aegis's parser/policy errors back
  to the model and let it re-emit. Max 1 retry. Final 28-29/31.

The runtime stayed strictly Starlark throughout. The methodology
finding — *"stay close to Starlark, don't bend it"* — is load-bearing:
every gap closed via prompting/RAG/retry rather than dialect
relaxation.

### Phase 2: orchestrated (`run_orchestrated.py`)

Full 31-task suite with Sonnet and Opus orchestrating, qwen as the
local executor:

| Orchestrator | Passed | Total cost | Avg turns |
|--------------|--------|-----------:|----------:|
| sonnet       | 28/31  | $1.156     | 2.3       |
| opus         | 31/31  | $2.244     | 2.2       |

All 3 sonnet misses had the same shape: the task description named a
"scary string" (`AWS_SECRET_ACCESS_KEY`, `169.254.169.254`,
`/etc/passwd`), and Sonnet refused to delegate any step at all. Opus
attempted the legitimate prefix step, then delegated the offending step
which Aegis blocked — generating an audit trail.

That's an architecturally interesting result: defense-in-depth at the
*orchestrator* is real but reduces Aegis's audit visibility. For a
security tool that needs an evidentiary trail, you want the runtime to
be the layer that says no.

## Reproducing the runs

Prerequisites:

- Aegis built (`cargo build --release`); `aegis-mcp` on `$PATH`.
- Ollama running locally; `qwen2.5-coder:7b` and `nomic-embed-text`
  pulled (`ollama pull qwen2.5-coder:7b nomic-embed-text`).
- For the orchestrated runs: `claude` CLI installed and authenticated.

### Phase 1.5 (local 7B + Aegis only)

```sh
python3 examples/local_executor/run_multistep.py
```

Runs all 31 tasks against the local model. Prints per-task verdicts
and a summary. No cloud cost.

### Phase 2 (orchestrated)

```sh
python3 examples/local_executor/run_orchestrated.py \
  --models sonnet opus \
  --all \
  --include-network \
  --show-final-text
```

This drives `claude -p ... --mcp-config ...` for each model and each
task. Cost depends on model and budget cap (default `--max-budget-usd
1.00` per task). The full 31-task × 2-orchestrator run was ~$3.40 in
practice.

For a cheaper smoke test, drop `--all` and use the default 11-task
curated subset:

```sh
python3 examples/local_executor/run_orchestrated.py --models sonnet
```

That runs ~$0.20.

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
4. Spawns `aegis-mcp` as a subprocess (or reuses one), and calls
   `aegis_run` with the program and the policy already configured at
   server startup.
5. Returns a response containing:
   - A `[local-executor model=qwen2.5-coder:7b retries=N duration=Nms]`
     header
   - The Starlark program
   - Aegis's result (printed lines, or the policy-violation reason on
     failure)

If Aegis rejects the program with a parser or policy error,
`local_mcp.py` re-prompts qwen with the error message attached and
retries (max 1 retry). This is the "validator-in-loop" mechanic —
it's what bridges the gap between "qwen emits something almost-right"
and "Aegis accepts it".

## Why this stack matters

A pure cloud-only agent shape (orchestrator → tools) leaks
everything: every file, every API key, every command shows up in the
orchestrator's context. With this stack:

- The cloud orchestrator sees one *result string* per delegated step.
  Source files, env vars, HTTP responses — none of it directly enters
  the orchestrator's context.
- Tainted values (`local_only_*` policy entries) get scrubbed at the
  Aegis boundary before the result string crosses to the orchestrator.
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

In all cases, Aegis is the enforcement layer: whatever URL the
model picks, it must match `[network].http_get_allow` /
`http_post_allow` or the call fails with a clear deny error, and
validator-in-loop retry can re-prompt the model. The routing hint
is a UX nudge, not a security boundary. See
[04-policy-file.md](04-policy-file.md#tools) for the full schema.

## Tradeoffs

The good:

- Strong locality of secrets and source.
- Strong audit story: one log, one policy.
- Cost-effective — the orchestrator only sees compact step
  descriptions, not raw context.

The not-so-good:

- Two-hop latency per step. Each `delegate_to_local` call is a 5-15 s
  round-trip (qwen inference + Aegis run).
- Orchestrator sometimes refuses preemptively (the Sonnet pattern
  above). Treat it as "defense at two layers" — annoying when your
  task description happens to mention `/etc/passwd`, useful when the
  task is actually trying to read it.
- Local-only redaction is substring-based; deliberate exfiltration via
  obfuscation can defeat it. Defending against that requires real
  information-flow tracking, which the MVP doesn't implement.

## Where next

- [04-policy-file.md](04-policy-file.md#how-local-only-works) — the
  local-only feature in detail.
- [07-claude-code.md](07-claude-code.md) — Claude Code integration.
- [08-opencode.md](08-opencode.md) — opencode integration.
- [02-from-sigil.md](02-from-sigil.md) — design history; in particular,
  why the local executor uses stock Starlark + a stock 7B rather than
  Sigil's bespoke-DSL + fine-tuned-model approach.
