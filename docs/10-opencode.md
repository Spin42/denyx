# Using Denyx with opencode

> ← [Back to docs README](README.md)

[opencode](https://opencode.ai/) is an open-source agentic IDE with an
MCP-aware tool surface. The Denyx integration shape is the same as
Claude Code's: launch `denyx-mcp` as a project-level MCP server and
either let opencode keep its built-in tools (Denyx is *one of* its
tools) or restrict it so Denyx is the *only* path to side-effects.

Most of what's in [09-claude-code.md](09-claude-code.md) applies here.
This doc covers the opencode-specific configuration.

## Prerequisites

- `denyx` and `denyx-mcp` built and on `$PATH` (see
  [07-install.md](07-install.md)).
- opencode installed. See [opencode.ai](https://opencode.ai/) for
  current install instructions.
- A policy file. `denyx init --lang <lang>` is the fastest start.

## Quick start: paste the setup prompt

For the project you want to gate, the fastest path is to paste the
contents of [`examples/denyx-setup-prompt.md`](../examples/denyx-setup-prompt.md)
as your first message in opencode from the project's root
directory. The assistant will detect your stack, generate
`denyx.toml`, wire a project-local opencode MCP config, and smoke-
test the result. Project-specific by design — nothing is written
outside the current working directory.

The rest of this section walks through the same setup manually, in
case you want to understand each step or do it without the prompt.

## Configure the MCP server

opencode reads MCP server configuration from a project-local
`./opencode.json` (or the user-global
`~/.config/opencode/opencode.json` if you want machine-wide
enablement). Project-local is what you almost always want — it
keeps Denyx scoped to the project you're gating, instead of
opting every project on the machine in.

The opencode config shape is **different from Claude Code's**.
Specifically:

- Top-level key is **`mcp`**, not `mcpServers` (Claude Code's name).
- Each server entry has a **`type`** field — `"local"` for stdio
  servers like `denyx-mcp`.
- **`command`** is a single ARRAY that contains the binary AND
  its arguments together; there is no separate `args` field.
- An **`enabled`** boolean lets you toggle servers without
  removing them.

So a working `opencode.json` looks like:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "denyx": {
      "type": "local",
      "command": [
        "denyx-mcp",
        "--policy", "/absolute/path/to/your/denyx.toml",
        "--audit-log", "/absolute/path/to/audit.jsonl"
      ],
      "enabled": true
    }
  }
}
```

If you copy-pasted the Claude Code shape (`mcpServers` + separate
`command`/`args`) into `opencode.json`, opencode rejects the
config at startup with `Configuration is invalid ... Unrecognized
key: mcpServers`. The fix is purely shape: rewrite to the form
above.

Restart opencode. The server's tools should appear in the tool list,
typically prefixed `denyx__` or similar (opencode's exact namespacing
may differ from Claude Code's).

## Available tools

Same as the Claude Code integration — see
[09-claude-code.md#available-tools](09-claude-code.md#available-tools)
for the list. The only naming difference is the host's namespace
prefix.

## Restricting opencode to Denyx-only

opencode has a notion of allowed tools per workspace. To force every
side effect through Denyx, disable opencode's built-in `Bash`, `Read`,
`Write`, `Edit` and similar tools and explicitly allow only the Denyx
tools. The exact configuration syntax depends on the opencode version
— check its `tools` or `allowedTools` settings.

The principle: opencode must not have a path to side-effects that
bypasses `denyx-mcp`. If it has a built-in `Bash` tool, that tool is
not policy-gated, and the model can call it directly.

## Local-executor relay (the agentic stack)

The same `local_mcp.py` from `examples/local_executor/` works with
opencode. Configure it as an MCP server:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "local-executor": {
      "type": "local",
      "command": [
        "python3",
        "/path/to/denyx/examples/local_executor/local_mcp.py",
        "--policy", "/path/to/denyx.toml"
      ],
      "enabled": true
    }
  }
}
```

opencode's reasoning model (whatever you've configured it to use) now
sees one tool: `delegate_to_local`. It decomposes a task into atomic
steps and delegates each to the local 7B; the local model emits a
Starlark program that Denyx enforces.

See [12-local-executor.md](12-local-executor.md) for what this
architecture looks like end-to-end and the evaluation results.

## Troubleshooting

opencode's MCP integration shape is similar to Claude Code's. The
common issues from
[09-claude-code.md#troubleshooting](09-claude-code.md#troubleshooting)
apply here too:

- `denyx-mcp: no --policy provided` banner → you forgot the
  `--policy` arg.
- Every tool call fails with `Verifier rejected` → the resource
  section that derives that capability is empty (e.g. `fs.read`
  needs `[filesystem].read_allow` or `local_only_read` populated).
- `not in [filesystem].read_allow` → extend `read_allow` (refresher in
  [06-policy-file.md](06-policy-file.md#filesystem)).

opencode-specific gotchas:

- **Tool listings are cached.** If you change the policy file, restart
  opencode (or trigger a tool-listing refresh) so it sees the updated
  capability set.
- **Working directory.** `denyx-mcp` resolves relative paths in the
  policy against its CWD at startup. opencode may launch the MCP server
  from the workspace root, but if you see "path not in read_allow" for a
  path you expected to match, double-check the relative-path anchoring.
  Use absolute paths in `--policy` and in `read_allow` patterns when
  in doubt.

## Where next

- [12-local-executor.md](12-local-executor.md) — the full agentic
  architecture, including the evaluation harness and results.
- [06-policy-file.md](06-policy-file.md) — for tuning the policy.
