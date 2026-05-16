# `denyx host-config` reference

> ← [Back to docs README](README.md)

`denyx host-config` translates a single `denyx.toml` into the right
config files for every supported coding-agent host: MCP server entry,
built-in-tool deny list, optional OS-sandbox stanza, audit-dir setup
and `.gitignore` exclusion. One source of truth, N hosts.

This page is the full flag reference. The host-specific narrative
(why each lockdown is needed, what gets disabled) lives in
[09-claude-code.md](09-claude-code.md), [10-opencode.md](10-opencode.md),
and [14-other-hosts.md](14-other-hosts.md). Read those for context;
read this for "what does flag X actually do."

## Quickest invocations

```sh
# Auto-detect the host from the environment (default):
denyx host-config --policy ./denyx.toml

# Single host:
denyx host-config --policy ./denyx.toml --host claude

# Multiple hosts in one run:
denyx host-config --policy ./denyx.toml --host claude,opencode,cursor

# Preview without writing:
denyx host-config --policy ./denyx.toml --dry-run

# Replace existing config files instead of merging:
denyx host-config --policy ./denyx.toml --existing replace
```

## Flag reference

| Flag | Default | Purpose |
|---|---|---|
| `--policy <PATH>` | *(required)* | Path to the policy TOML. Used both to wire `denyx-mcp --policy` and to derive the OS-sandbox stanza's `allowedDomains` / `allowWrite` from the policy's network and filesystem sections. |
| `--host <LIST>` | `auto` | Comma-separated list of hosts to wire. See [hosts](#supported-hosts). Aliases: `auto` (env + cwd detection), `all` (every supported host), `both` (legacy: `claude,opencode`). |
| `--output-dir <PATH>` | `.` | Project root to write into. Use this when running host-config from outside the project. |
| `--platform <MODE>` | `native` | How `denyx-mcp` is launched. See [platforms](#platforms). Values: `native`, `lima`, `wsl`. |
| `--denyx-mcp-binary <PATH>` | `denyx-mcp` | Resolved path to `denyx-mcp` *as the host (or VM/distro) sees it*. The default works when `denyx-mcp` is on `$PATH` (e.g. via `cargo install denyx-mcp`). Override when the binary lives in a non-standard location, or when running with `--platform lima`/`wsl` and the VM/distro path differs from the host path. |
| `--lima-vm <NAME>` | `denyx` | Lima VM name. Only consulted when `--platform lima`. |
| `--wsl-distro <NAME>` | *(none)* | WSL2 distro name. **Required** when `--platform wsl`. |
| `--audit-log <PATH>` | `./.denyx/audit.jsonl` | Where `denyx-mcp` writes the audit log. For `--platform lima`/`wsl`, pass an absolute path the VM/distro can write to. |
| `--policy-url <URL>` | *(none)* | **Team mode.** Bake `--policy-url <URL>` into the MCP entry instead of `--policy <path>`. The local `--policy` file is still required (the OS-sandbox stanza is derived from it); at runtime `denyx-mcp` fetches the URL and ignores the local file. Pair with `DENYX_AUTH_TOKEN` distributed via your secrets tool. See [11-denyx-for-teams.md](11-denyx-for-teams.md). |
| `--audit-url <URL>` | *(none)* | **Team mode.** Bake `--audit-url <URL>` into the MCP entry instead of `--audit-log <path>`. Audit events POST with the same auth token. May be combined with `--policy-url` (full team mode) or used alone (centralised audit, local policy). |
| `--sandbox <MODE>` | `auto` | OS-level sandbox emission. See [sandbox modes](#sandbox-modes). Values: `auto`, `required`, `off`. |
| `--windows` | *off* | Add `PowerShell` to the Claude Code deny list. Set on Windows hosts; harmless elsewhere. |
| `--existing <MODE>` | `merge` | How to handle existing config files. See [merge vs replace](#merge-vs-replace). Values: `merge`, `replace`. |
| `--dry-run` | *off* | Print the generated configs to stdout instead of writing to disk. Combine with `--existing replace` to see what a from-scratch write would produce. |
| `--no-mcp` | *off* | Skip the MCP wiring; write **only** the lockdown layer (`.claude/settings.json` deny + `opencode.json` `tools`/`permission` + sandbox stanza). Use when the project's MCP server is something other than `denyx-mcp` — e.g. the [local-executor flow](12-local-executor.md) wires `local_mcp.py` manually and uses Denyx for the lockdown only. |

## Supported hosts

`--host` accepts a comma-separated list. Recognised values:

| Value | Targets | File written |
|---|---|---|
| `claude` | Claude Code (CLI + IDE) | `./.claude/settings.json`, `./.mcp.json` |
| `opencode` | sst's opencode | `./opencode.json` |
| `cursor` | Cursor IDE | `./.cursor/mcp.json` |
| `copilot` | VSCode + GitHub Copilot agent mode | `./.vscode/settings.json` |
| `continue` | VSCode + Continue | `./.continue/config.json` |
| `cline` | VSCode + Cline / Roo Code | *(none — JSON snippet to stderr)* |

Convenience aliases:

- `auto` *(default)* — detect from environment variables and cwd files.
- `all` — every supported host above. Useful when shipping a project to
  developers using mixed hosts.
- `both` — legacy alias for `claude,opencode`. Predates the multi-host
  expansion; preserved for compatibility.

### Auto-detection rules

`--host auto` reads, in order:

- Env: `TERM_PROGRAM=cursor` → Cursor
- Env: `TERM_PROGRAM=vscode` → Copilot agent mode (most common AI extension)
- Env: `CLAUDECODE` / `CLAUDE_CODE_ENTRYPOINT` → Claude Code
- Env: `OPENCODE` → opencode
- File in cwd: `.mcp.json` / `opencode.json` / `.cursor/mcp.json` /
  `.vscode/settings.json` / `.continue/config.json` → corresponding host

If detection finds nothing, `host-config` falls back to
`claude,opencode` with a stderr warning. Pass `--host` explicitly to
override.

### Per-host wiring matrix

What `host-config` writes for each host (see
[14-other-hosts.md](14-other-hosts.md) for the lockdown discussion):

| Host | MCP server entry | Built-in deny | OS sandbox stanza | Lockdown completeness |
|---|---|---|---|---|
| `claude` | `mcpServers.denyx` in `.mcp.json` | `permissions.deny` array in `.claude/settings.json` | Yes (Claude Code v2 stanza) | **Strong** — deny precedence + `disableBypassPermissionsMode` |
| `opencode` | `mcp.denyx` in `opencode.json` | `tools` block + `permission: "*": "deny" + "denyx*": "allow"` | — | **Strong** — whitelist semantics |
| `cursor` | `mcpServers.denyx` in `.cursor/mcp.json` | UI toggles only | — | **Partial** — additive gate |
| `copilot` | `chat.mcp.servers.denyx` in `.vscode/settings.json` | per-call user approval | — | **Partial** — additive gate |
| `continue` | `mcpServers[]` entry in `.continue/config.json` | `tools: []` empty allowlist | — | **Strong** — whitelist semantics |
| `cline` | snippet to stderr (paste into UI) | per-call user approval | — | **Partial** — additive gate |

**Strong** means the host has a project-local mechanism Denyx can use
to disable built-in effecting tools. **Partial** means Denyx-routed
calls are policy-checked but the host's own tools remain available in
parallel. If your threat model treats the lockdown as load-bearing,
prefer Claude Code, opencode, or Continue.

## Platforms

`--platform` controls how `denyx-mcp` is launched in the generated
MCP entry.

### `native` (default)

The MCP entry calls `denyx-mcp` directly:

```json
{ "command": "denyx-mcp", "args": ["--policy", "./denyx.toml", ...] }
```

Use on Linux, or on macOS/Windows when running the MCP server natively
without a VM.

### `lima`

For macOS via [Lima](https://lima-vm.io/). The MCP entry wraps the
command in `limactl shell`:

```json
{
  "command": "limactl",
  "args": ["shell", "denyx", "--", "denyx-mcp",
           "--policy", "/abs/path/denyx.toml",
           "--audit-log", "/abs/path/.denyx/audit.jsonl", ...]
}
```

Pair with `--lima-vm <name>` (default `denyx`). On macOS also pass
**absolute paths** to `--policy` and `--audit-log` — Lima mirrors the
host's `$HOME` so absolute paths under `$HOME` usually work as-is. See
[macos-deployment.md](macos-deployment.md).

### `wsl`

For Windows via WSL2. The MCP entry wraps the command in `wsl.exe`:

```json
{
  "command": "wsl.exe",
  "args": ["-d", "<distro>", "-e", "denyx-mcp",
           "--policy", "/abs/path/denyx.toml", ...]
}
```

`--wsl-distro <name>` is **required** in this mode (no default).
`--windows` should also be set. See
[windows-deployment.md](windows-deployment.md).

## Sandbox modes

`--sandbox` controls Claude Code v2's OS-level sandbox stanza in
`.claude/settings.json`. Only applies when `claude` is in the
`--host` list.

| Mode | Behavior | When to use |
|---|---|---|
| `auto` *(default)* | Emit the stanza with `failIfUnavailable: false`. Hosts without bubblewrap warn and fall back to non-sandboxed. | Most setups. Defense-in-depth without breaking dev environments that lack bwrap. |
| `required` | Emit with `failIfUnavailable: true`. The host **refuses to start** unless the OS sandbox can come up. | Managed deployments where sandboxing is a security gate. |
| `off` | Omit the sandbox stanza entirely. Denyx still gates capabilities; you lose the OS-layer defense-in-depth. | Hosts that don't support the v2 sandbox; environments where the OS sandbox conflicts with required tools. |

The stanza's `allowedDomains` is derived from the union of the
policy's `[network].http_*_allow` arrays. `allowWrite` is derived from
absolute or `~`-relative paths in `[filesystem].write_allow`.

## Merge vs replace

`--existing` controls behavior when a config file already exists.

### `merge` (default)

- **Unrelated keys preserved.** If `.claude/settings.json` has
  `model`, `theme`, custom hooks — they stay.
- **Deny lists are unioned, no duplicates.** A user's existing
  `permissions.deny` rules merge with Denyx's lockdown set.
- **The Denyx MCP entry replaces** any prior version of itself
  (matched by name `denyx`).
- **Sandbox arrays are deep-merged.** `allowedDomains` and `allowWrite`
  union; first-write semantics for scalar fields.
- **opencode `tools` block: `false` overrides `true`** with a stderr
  warning (security wins; user's accidental enable doesn't survive).

### `replace`

Write the generated config as if no file existed. **Destroys**
unrelated keys. Use when the existing file is known-stale or
generated by a previous `host-config` run you want to fully overwrite.

Combine with `--dry-run` to see what a clean write would produce
without losing anything:

```sh
denyx host-config --policy ./denyx.toml --existing replace --dry-run
```

## Team mode

Two flags shift the MCP entry from local to centralised:

- `--policy-url <URL>` — fetch the policy from a server at startup.
- `--audit-url <URL>` — POST audit events to a server.

```sh
denyx host-config \
    --policy ./denyx.toml \
    --policy-url https://policy.internal/team-a \
    --audit-url https://audit.internal/team-a
```

The local `--policy` file is **still required** even with
`--policy-url`: `host-config` reads it to derive the sandbox stanza.
At runtime `denyx-mcp` fetches the URL and ignores the local file.

Both URLs share an auth token via the `DENYX_AUTH_TOKEN` env var,
which you distribute through `direnv` / your secrets tool. The wire
spec the server has to implement is documented at
[server-protocol.md](server-protocol.md). The full team-deployment
narrative is at [11-denyx-for-teams.md](11-denyx-for-teams.md).

## Lockdown-only mode (`--no-mcp`)

`--no-mcp` writes **only** the host-side deny lists and OS sandbox
stanza, skipping the MCP server entry. Use when your project's MCP
server is something other than `denyx-mcp` — most commonly the
[local-executor flow](12-local-executor.md) where `local_mcp.py`
fronts a small local model and Denyx is responsible for the lockdown
of the host's built-ins.

```sh
denyx host-config --policy ./denyx.toml --no-mcp
```

After this, wire your custom MCP server manually in
`.mcp.json` / `opencode.json` / etc.

## Dry-run

`--dry-run` prints what would be written, to stdout, without touching
disk. Useful for:

- **CI checks** — `denyx host-config --policy ./denyx.toml --dry-run | jq .`
  to assert config shape.
- **Inspecting merges** — see what merge would produce before
  committing.
- **Comparing modes** — diff `--existing merge --dry-run` against
  `--existing replace --dry-run` to know what merge is actually
  preserving.

## Self-protection

`host-config` enforces a small but important invariant: it refuses to
write a config that would let the agent rewrite the policy that
controls it. Specifically:

- The Claude Code deny list always includes the rules that block the
  agent from writing `./.claude/settings.json`, `./.mcp.json`, and
  `./denyx.toml` themselves.
- The opencode `tools` / `permission` blocks deny by default, so
  writing those files requires they be explicitly allow-listed (and
  they aren't).
- The runtime separately refuses to load any policy whose
  `write_allow` or `delete_allow` matches the policy file path. See
  [04-security-threat-model.md](04-security-threat-model.md).

You don't need to know about these to use `host-config`; they're
just on. Don't add `denyx.toml`, `./.claude/settings.json`,
`./.mcp.json`, or `./opencode.json` to your policy's `write_allow`
or you'll either trip the runtime guard or hand the agent a way to
disable the gate.

There's also a **runtime check on every MCP server startup** that
catches the inverse failure: a policy update without a matching
`host-config` re-run. If `denyx-mcp` finds Critical-severity
inconsistency between the loaded policy and the project's
host-config files, it refuses to advertise its capability tools and
instead surfaces a single `denyx_blocked` tool whose description
tells the agent to alert the user. Run `denyx doctor --fix` and
restart the host to recover. Full mechanism at
[doctor.md — Startup blocking](doctor.md#startup-blocking--the-mcp-servers-refuse-to-serve-when-inconsistent).

## Diagnosing the result

After running `host-config`, run [`denyx doctor`](doctor.md) to
verify the wiring took:

```sh
denyx doctor          # canonical: project + cross-cutting consistency
denyx doctor --fix    # apply mechanical fixes interactively
```

`denyx doctor` is the canonical entry point — it adds cross-cutting
checks the binary-specific variants can't see (policy ↔ host-config
↔ launch-flag consistency, sandbox-stanza-derivation freshness). Use
`denyx-mcp doctor` or `denyx-local-mcp doctor` only when the full
`denyx` CLI isn't on `$PATH` (e.g. inside a Lima VM that only
deploys the MCP binary). See [doctor.md](doctor.md).

## See also

- [09-claude-code.md](09-claude-code.md) — Claude Code wiring narrative
  and lockdown rationale.
- [10-opencode.md](10-opencode.md) — opencode wiring narrative.
- [14-other-hosts.md](14-other-hosts.md) — Cursor, Copilot, Continue,
  Cline.
- [11-denyx-for-teams.md](11-denyx-for-teams.md) — team-deployment
  shape, including `--policy-url` / `--audit-url`.
- [doctor.md](doctor.md) — preflight verification.
- [comparison.md](comparison.md) — how the cross-host translation
  compares to the rest of the field.
