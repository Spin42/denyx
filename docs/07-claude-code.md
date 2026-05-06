# Using Denyx with Claude Code

> ← [Back to docs README](README.md)

[Claude Code](https://claude.com/claude-code) is Anthropic's official CLI
for Claude. It supports MCP — the [Model Context Protocol](https://modelcontextprotocol.io)
— which is exactly the integration shape Denyx is designed for. This
guide covers the two ways to wire Denyx in:

1. **As a policy-gated tool surface** — Claude Code calls Denyx tools
   through an MCP server, and only Denyx-permitted operations succeed.
2. **As a remote-orchestrator → local-executor relay** — Sonnet/Opus in
   Claude Code delegates tasks to a local 7B model that runs the actual
   code through Denyx. This is the architecture the project's evaluation
   harness measures (see [09-local-executor.md](09-local-executor.md)).

## Prerequisites

- `denyx` and `denyx-mcp` built and on `$PATH` (see
  [05-install.md](05-install.md)).
- `claude` CLI installed and authenticated.
- A policy file. `denyx init --lang <lang>` is the fastest start — see
  [04-policy-file.md](04-policy-file.md#the-denyx-init-generator).

## Approach 1: Denyx as a policy-gated tool surface

Wire `denyx-mcp` into Claude Code as a project-level MCP server.

### Quick start: paste the setup prompt

For the project you want to gate, the fastest path is to paste the
contents of [`examples/denyx-setup-prompt.md`](../examples/denyx-setup-prompt.md)
as your first message in Claude Code from the project's root
directory. The assistant will detect your stack, generate
`denyx.toml`, write a project-local `.mcp.json`, and smoke-test the
result. Project-specific by design — nothing is written outside the
current working directory.

The rest of this section walks through the same setup manually, in
case you want to understand each step or do it without the prompt.

### Configure the MCP server

Claude Code reads MCP server configuration from your settings (per-user
or per-project; see Claude Code's docs for the exact location on your
platform). Add an `denyx` server entry:

```json
{
  "mcpServers": {
    "denyx": {
      "command": "denyx-mcp",
      "args": ["--policy", "/absolute/path/to/your/denyx.toml"]
    }
  }
}
```

Use absolute paths — the MCP server's working directory may not match
your project root.

### Available tools

Once configured, Claude Code sees these tools (all prefixed
`mcp__denyx__` by Claude Code's MCP namespacing):

- `mcp__denyx__denyx_run` — primary surface. Pass a Starlark program;
  the server runs it under the policy. Result is the printed lines,
  already taint-scrubbed.
- `mcp__denyx__denyx_fs_read`, `mcp__denyx__denyx_fs_write`,
  `mcp__denyx__denyx_fs_delete` — sugar tools that synthesize a
  one-statement Starlark program. Useful for hosts that prefer one
  call per action.
- `mcp__denyx__denyx_subprocess_exec` — same.
- `mcp__denyx__denyx_net_http_get`, `mcp__denyx__denyx_net_http_post`
  — same.
- `mcp__denyx__denyx_env_read` — same.

### Restrict Claude Code to only the Denyx tools

If you want a hardened setup where Claude Code can *only* affect the
system through Denyx (no built-in `Bash`, no built-in `Edit`), launch it
with `--tools` cleared and `--allowedTools` restricted:

```sh
claude \
  --mcp-config '{"mcpServers":{"denyx":{"command":"denyx-mcp","args":["--policy","/path/to/denyx.toml"]}}}' \
  --tools "" \
  --allowedTools "mcp__denyx__denyx_run,mcp__denyx__denyx_fs_read,mcp__denyx__denyx_fs_write,mcp__denyx__denyx_subprocess_exec,mcp__denyx__denyx_net_http_get,mcp__denyx__denyx_env_read"
```

Now Claude Code's *only* path to side-effects is through Denyx. Every
fs/net/subprocess/env call goes through the policy gate and lands in the
audit log.

### Audit log

To collect audit events to a file:

```json
{
  "mcpServers": {
    "denyx": {
      "command": "denyx-mcp",
      "args": [
        "--policy", "/path/to/denyx.toml",
        "--audit-log", "/path/to/audit.jsonl"
      ]
    }
  }
}
```

Each tool call produces one JSON Lines record per effecting action.

### Approval-gated capabilities (`requires_approval`)

If your policy has
`requires_approval = ["fs.delete", "subprocess.exec"]`, those
capabilities escalate to the caller on every call. The MCP server's
`--confirm-mode` flag picks how the escalation behaves:

- **`--confirm-mode auto`** (default, recommended) — negotiate
  per-client. If the client advertises the MCP `elicitation`
  capability at handshake time, the server sends a real
  `elicitation/create` request to the client and blocks for the
  user's reply. If the client doesn't advertise elicitation, the
  server falls back to `auto-deny` so the orchestrator can render
  its own UX from the structured tag.
- **`--confirm-mode elicit`** — force elicitation regardless of
  capability advertisement. If the client doesn't actually
  implement elicitation, the request times out (300 s) and denies
  safely.
- **`--confirm-mode auto-deny`** — every approval-required call
  fails with `isError: true`, `denyx_error_kind: "confirm_denied"`,
  naming the capability. The orchestrator (Sonnet/Opus) can read
  that error and surface its own out-of-band prompt before
  retrying. This is the most broadly-deployed shape today (see the
  empirical note below).
- **`--confirm-mode auto-allow`** — every approval-required call
  passes silently. **Use only for tests and demos** — this defeats
  the purpose of `requires_approval`.

```json
{
  "mcpServers": {
    "denyx": {
      "command": "denyx-mcp",
      "args": [
        "--policy", "/path/to/denyx.toml",
        "--confirm-mode", "auto"
      ]
    }
  }
}
```

#### Empirical findings: what Claude Code actually does

We drove a real `claude -p ... --permission-mode auto` session
against `denyx-mcp --confirm-mode auto`, with a policy declaring
`requires_approval = ["fs.delete"]` and a script that calls
`fs.delete("/tmp/.../target.txt")`. The transcript shows:

- Claude Code (2.1.x) **does not advertise the `elicitation`
  capability** in its MCP `initialize` handshake.
- denyx-mcp's `auto` mode therefore correctly falls back to
  `auto-deny`, returning `isError: true`,
  `denyx_error_kind: "confirm_denied"`,
  `text: "confirm hook denied capability fs.delete"`.
- The agent surfaced that text in its response.
- The runtime correctly enforced the deny — `target.txt` was not
  removed.

This is the expected behaviour. **It also means: there is no
human-in-the-loop prompt on the Claude-Code-`-p` path today, even
with `requires_approval` set and `--confirm-mode auto`.** What you
get is a guaranteed deny + a structured tag the orchestrator can
react to. That's a meaningful enforcement layer (the runtime
absolutely refused the call) but it is *not* a per-call user
prompt.

If you need a real prompt, today the deployment options are:

1. **Use the CLI** (`denyx run`) when there's a human at the
   terminal. The CLI prompts on stdin and the user actually sees
   the question.
2. **Use `--confirm-mode auto-deny` and let the orchestrator's UX
   render the approval flow.** This is what auto already
   degrades to. Some MCP hosts (interactive Claude Code, opencode
   in some modes) catch the `confirm_denied` tag and surface a
   "the agent wanted to do X — allow?" UI of their own; the user
   then either edits the policy or re-issues from a sibling tool.
3. **Use a client that supports MCP elicitation.** As of mid-2026
   that's a small set; verify your specific client advertises
   `capabilities.elicitation` at handshake. The denyx-mcp side of
   the protocol is implemented and tested (see
   `crates/mcp/tests/elicitation.rs`); the gap is the client.

The protocol round-trip works end-to-end against any spec-
compliant client that advertises elicitation. We don't ship a
shim that pretends a non-elicitation-capable client supports it,
because pretending in this direction means silently auto-allowing
calls the user never approved.

### What "policy-gated" actually buys you

A few examples of what Claude Code can no longer do, when wired this
way, regardless of how the model is prompted:

- Read `~/.aws/credentials` — `secure-defaults` blocks the path.
- Run `git push --force` — generated policies put it in
  `[subprocess.deny_args].git`.
- Curl an internal IP — `[network].deny_ips` includes RFC1918 + cloud
  metadata, applied after DNS resolution.
- Read `OPENAI_API_KEY` and ship it back in chat — if marked
  `local_only_vars`, the key bytes are scrubbed before crossing the MCP
  boundary.

## Approach 2: Sonnet → local-executor → Denyx

This is the architecture from
[09-local-executor.md](09-local-executor.md). It's worth a quick
overview here because it's the stack the project evaluation actually
measures.

The shape:

```
   Sonnet/Opus (in Claude Code, via `claude -p`)
        │  delegate_to_local("step description")
        ▼
   examples/local_executor/local_mcp.py  (an MCP server you launch)
        │  prompts the local 7B model
        ▼
   qwen2.5-coder:7b  (via Ollama)
        │  emits a Starlark program
        ▼
   denyx-mcp  (subprocess of local_mcp.py)
        │  runs the program under your policy
        ▼
   The actual side effects (fs/net/subprocess/env)
```

The bridge piece — `local_mcp.py` — is in `examples/local_executor/`. It
exposes a single MCP tool, `delegate_to_local(step)`. The cloud
orchestrator decomposes the task into atomic steps and delegates each
one; the local executor synthesizes Starlark for that step and runs it
through `denyx-mcp`.

To launch this from Claude Code:

```sh
claude -p "Refactor src/foo.py to remove duplication" \
  --model sonnet \
  --mcp-config '{
    "mcpServers": {
      "local-executor": {
        "command": "python3",
        "args": [
          "/path/to/denyx/examples/local_executor/local_mcp.py",
          "--policy", "/path/to/denyx.toml"
        ]
      }
    }
  }' \
  --tools "" \
  --allowedTools "mcp__local-executor__delegate_to_local" \
  --append-system-prompt "$(cat ORCHESTRATOR_PROMPT.txt)"
```

Sonnet sees only one tool: `delegate_to_local`. It cannot directly
write files, run shells, or fetch URLs — every side effect has to flow
through the local model and Denyx.

The `examples/local_executor/run_orchestrated.py` harness automates this
pattern across a 36-task evaluation suite, so you can reproduce the
project's measurement runs with `python3 run_orchestrated.py --models
sonnet opus --all`.

### Why this shape

- **The cloud orchestrator never sees raw secrets.** The local model
  reads the user's `OPENAI_API_KEY` (marked `local_only_vars`); Denyx
  scrubs it before the MCP response reaches Sonnet.
- **The cloud orchestrator never sees the file contents.** Whatever the
  local model does with `fs.read` results stays local; only the
  printed summary it composes (and its taint-scrubbed bytes) travels
  back.
- **The audit log is one file.** Every action across every step lands in
  `denyx-mcp`'s audit log, regardless of which orchestrator, which
  local model, which task — one source of truth.

## Trying it locally

If you just want to confirm Denyx is wired correctly without the full
local-executor flow, a one-shot test:

```sh
echo 'print("hello from denyx")' > /tmp/hello.star
claude --mcp-config '{
  "mcpServers": {
    "denyx": {
      "command": "denyx-mcp",
      "args": ["--policy", "/path/to/denyx.toml"]
    }
  }
}' "Run mcp__denyx__denyx_run with this Starlark: $(cat /tmp/hello.star)"
```

You should see Sonnet acknowledge the tool result containing `"hello
from denyx"`.

## Troubleshooting

**`denyx-mcp: no --policy provided` banner showing up:** you forgot to
pass `--policy` in `args`. The fallback is the deny-everything
`secure-defaults` baseline; every tool call will fail. Add the path.

**Claude Code shows the tool but every call fails with `Verifier
rejected`:** the resource section the capability is derived from is
empty. For example, calls to `fs.read` need at least one entry in
`[filesystem].read_allow` (or `local_only_read`). Open the policy
file, populate the matching section, and restart Claude Code (it
caches MCP tool listings). The full mapping is in
[04-policy-file.md](04-policy-file.md#capabilities-are-derived-not-declared).

**A tool call reports `not in [filesystem].read_allow`:** the path you
asked for isn't covered by `read_allow`. Either add the path to
`read_allow` or use a more permissive pattern. Refresher in
[04-policy-file.md](04-policy-file.md#filesystem).

## Where next

- [08-opencode.md](08-opencode.md) — same setup for opencode.
- [09-local-executor.md](09-local-executor.md) — the local-executor
  architecture in depth, including the evaluation results.
- [04-policy-file.md](04-policy-file.md) — for tightening the policy
  once you know what your agent actually needs.
