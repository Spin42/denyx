# Using Aegis with opencode

> ← [Back to docs README](README.md)

[opencode](https://opencode.ai/) is an open-source agentic IDE with an
MCP-aware tool surface. The Aegis integration shape is the same as
Claude Code's: launch `aegis-mcp` as a project-level MCP server and
either let opencode keep its built-in tools (Aegis is *one of* its
tools) or restrict it so Aegis is the *only* path to side-effects.

Most of what's in [07-claude-code.md](07-claude-code.md) applies here.
This doc covers the opencode-specific configuration.

## Prerequisites

- `aegis` and `aegis-mcp` built and on `$PATH` (see
  [05-install.md](05-install.md)).
- opencode installed. See [opencode.ai](https://opencode.ai/) for
  current install instructions.
- A policy file. `aegis init --lang <lang>` is the fastest start.

## Configure the MCP server

opencode reads MCP server configuration from its workspace settings.
Add an `aegis` server (consult opencode's current docs for the exact
file path; older versions used `~/.config/opencode/config.json`,
recent versions use a project-local `opencode.json` or similar):

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis-mcp",
      "args": [
        "--policy", "/absolute/path/to/your/aegis.toml",
        "--audit-log", "/absolute/path/to/audit.jsonl"
      ]
    }
  }
}
```

Restart opencode. The server's tools should appear in the tool list,
typically prefixed `aegis__` or similar (opencode's exact namespacing
may differ from Claude Code's).

## Available tools

Same as the Claude Code integration — see
[07-claude-code.md#available-tools](07-claude-code.md#available-tools)
for the list. The only naming difference is the host's namespace
prefix.

## Restricting opencode to Aegis-only

opencode has a notion of allowed tools per workspace. To force every
side effect through Aegis, disable opencode's built-in `Bash`, `Read`,
`Write`, `Edit` and similar tools and explicitly allow only the Aegis
tools. The exact configuration syntax depends on the opencode version
— check its `tools` or `allowedTools` settings.

The principle: opencode must not have a path to side-effects that
bypasses `aegis-mcp`. If it has a built-in `Bash` tool, that tool is
not policy-gated, and the model can call it directly.

## Local-executor relay (the agentic stack)

The same `local_mcp.py` from `examples/local_executor/` works with
opencode. Configure it as an MCP server:

```json
{
  "mcpServers": {
    "local-executor": {
      "command": "python3",
      "args": [
        "/path/to/aegis/examples/local_executor/local_mcp.py",
        "--policy", "/path/to/aegis.toml"
      ]
    }
  }
}
```

opencode's reasoning model (whatever you've configured it to use) now
sees one tool: `delegate_to_local`. It decomposes a task into atomic
steps and delegates each to the local 7B; the local model emits a
Starlark program that Aegis enforces.

See [09-local-executor.md](09-local-executor.md) for what this
architecture looks like end-to-end and the evaluation results.

## Troubleshooting

opencode's MCP integration shape is similar to Claude Code's. The
common issues from
[07-claude-code.md#troubleshooting](07-claude-code.md#troubleshooting)
apply here too:

- `aegis-mcp: no --policy provided` banner → you forgot the
  `--policy` arg.
- Every tool call fails with `Verifier rejected` → the resource
  section that derives that capability is empty (e.g. `fs.read`
  needs `[filesystem].read_allow` or `local_only_read` populated).
- `not in [filesystem].read_allow` → extend `read_allow` (refresher in
  [04-policy-file.md](04-policy-file.md#filesystem)).

opencode-specific gotchas:

- **Tool listings are cached.** If you change the policy file, restart
  opencode (or trigger a tool-listing refresh) so it sees the updated
  capability set.
- **Working directory.** `aegis-mcp` resolves relative paths in the
  policy against its CWD at startup. opencode may launch the MCP server
  from the workspace root, but if you see "path not in read_allow" for a
  path you expected to match, double-check the relative-path anchoring.
  Use absolute paths in `--policy` and in `read_allow` patterns when
  in doubt.

## Where next

- [09-local-executor.md](09-local-executor.md) — the full agentic
  architecture, including the evaluation harness and results.
- [04-policy-file.md](04-policy-file.md) — for tuning the policy.
