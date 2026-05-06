# denyx-mcp

The MCP server for [Denyx](https://github.com/Spin42/denyx), a
default-deny capability layer for AI-agent runtimes.

`denyx-mcp` exposes the policy-gated Starlark host over stdio
JSON-RPC, so an MCP-aware client (Claude Code, opencode, custom
clients) can ask the agent to perform filesystem, network,
subprocess, and environment operations — and have those operations
re-checked against a TOML policy before they happen.

## Install

```sh
cargo install denyx-mcp
```

## Wire it into Claude Code

```json
{
  "mcpServers": {
    "denyx": {
      "command": "denyx-mcp",
      "args": ["--policy", "./denyx.toml", "--confirm-mode", "auto"]
    }
  }
}
```

For opencode, server-mode (centralised policy + audit), and
platform-specific notes (macOS Lima, Windows WSL2), see the
[main README](https://github.com/Spin42/denyx) and the
[Claude Code](https://github.com/Spin42/denyx/blob/main/docs/09-claude-code.md)
/ [opencode](https://github.com/Spin42/denyx/blob/main/docs/10-opencode.md)
guides.

## Server mode (centralised policy + audit)

Set `DENYX_POLICY_URL` and `DENYX_AUDIT_URL` (with optional
`DENYX_AUTH_TOKEN`) to fetch a corporate-managed policy at startup
and POST every audit event to a remote sink. The reserved env-var
list (`DENYX_AUTH_TOKEN`, `DENYX_TOKEN`, `DENYX_SERVER_TOKEN`,
`DENYX_JWT`, `DENYX_API_KEY`) is hard-coded as never-readable by
the agent — no policy override is honoured.

## Status

Pre-1.0. Read the [main README](https://github.com/Spin42/denyx)
disclosure block — in particular, the `requires_approval` mode
falls back to `auto-deny` when the MCP client doesn't advertise
elicitation support, which most clients don't yet (including Claude
Code 2.1.x in `-p` mode).

## License

MIT. See [LICENSE](LICENSE).
