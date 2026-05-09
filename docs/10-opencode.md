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

## Configure with `denyx host-config`

The recommended path is to let `denyx host-config` write
`./opencode.json` (and optionally `.claude/settings.json` /
`.mcp.json`) from your policy in one go. Full flag reference at
[host-config.md](host-config.md); the opencode-specific narrative
is below.

```sh
cd /path/to/your/project
denyx host-config \
    --policy ./denyx.toml \
    --host opencode \
    --platform native \
    --sandbox auto
```

This single command:

- creates `./.denyx/` and adds it to `./.gitignore` (audit-log dir),
- writes `./opencode.json` with `mcp.denyx` wired (using the
  opencode-specific shape — `type: "local"`, `command` as a single
  array, `enabled: true`), the `tools` block disabling every
  built-in effecting tool (`bash`, `read`, `write`, `edit`,
  `glob`, `grep`, `webfetch`, `websearch`), and a `permission`
  block with `"*": "deny"` + `"denyx*": "allow"` as
  defense-in-depth.

If `./opencode.json` already exists, `host-config` **merges**:
unrelated keys are preserved, the `tools` block has `false`
override `true` (with a stderr warning), and the `mcp.denyx`
entry replaces any prior version.

> **macOS / Windows:** Pass `--platform lima --lima-vm <vm>` (macOS)
> or `--platform wsl --wsl-distro <distro>` (Windows) so the
> generated `command` array uses the right wrapper. On those
> platforms also pass `--policy <absolute-path>` and
> `--audit-log <absolute-path>`.

> **`--audit-log` defaults to `./.denyx/audit.jsonl`.** Without an
> audit-log path, `denyx-mcp` writes events to stderr, which
> opencode buries in its own MCP-server log directory.
> `host-config` always passes `--audit-log` explicitly so events
> land somewhere you can `tail -f` and `jq` against:
>
> ```sh
> tail -f .denyx/audit.jsonl
> jq -c 'select(.status == "denied")' .denyx/audit.jsonl
> ```

opencode's MCP config shape is **different from Claude Code's**:
top-level key `mcp` (not `mcpServers`), each server has a `type`
field (`"local"` for stdio), `command` is a single array
containing both the binary and its args (no separate `args`
field), and `enabled: true` toggles the server. `host-config`
emits the right shape automatically — you don't have to remember
these quirks.

Restart opencode. The server's tools should appear in the tool
list, typically prefixed `denyx__` or similar (opencode's exact
namespacing may differ from Claude Code's).

## Available tools

Same as the Claude Code integration — see
[09-claude-code.md#available-tools](09-claude-code.md#available-tools)
for the list. The only naming difference is the host's namespace
prefix.

## Why disabling opencode's built-in tools is required

`denyx host-config` writes the lockdown automatically; this
section explains *why* it's non-negotiable.

opencode ships with built-in `bash`, `read`, `write`, `edit`,
`glob`, `grep`, `webfetch`, `websearch` tools that touch the
filesystem, network, and shell **directly** — they do NOT go
through any MCP server. If only `denyx-mcp` is wired and the
built-ins remain enabled, the model sees two paths to read a
file (`read` vs. `denyx__denyx_fs_read`) and picks the cheaper,
ungated one. Result: placebo sandbox.

`host-config` writes (or merges into) `./opencode.json`:

- A `tools` block with every built-in effecting tool set to
  `false`. `tools: false` removes the built-in entirely — the
  model never sees it in its tool list.
- A `permission` block with `"*": "deny"` and `"denyx*": "allow"`.
  This is opencode's **deny-by-default whitelist**: every tool
  denied unless explicitly allowed. The `tools: false` denies
  cover the built-ins opencode ships *today*; the
  `permission: "*": "deny"` whitelist also catches:
  - Future opencode versions adding new built-in tools.
  - Other MCP servers exposing equivalent capabilities (e.g. a
    `filesystem-mcp` with a `read_file` tool, or `shell-mcp`
    with `run_command`).
  This is the strongest shape: Denyx is the only path the model
  has to side-effects, period. New tools are denied by default
  until you explicitly allow them.

The lockdown is project-local: `./opencode.json` only affects
sessions started in that directory. Restart opencode after
running `host-config` so it picks up the new file.

### Allowing additional servers alongside Denyx

If you want to also use a *different* MCP server alongside Denyx
(e.g. a read-only documentation lookup that doesn't side-effect
anything), edit the generated `./opencode.json` and add its
tool-name prefix to `permission`:

```json
"permission": {
  "*": "deny",
  "denyx*": "allow",
  "docs-lookup*": "allow"
}
```

A subsequent `host-config` run preserves the addition (merge
mode keeps existing `permission` entries). Adding a new MCP
server is then a deliberate decision — exactly the property you
want for a security-critical setup.

## Add opencode's memory files to the policy

Disabling `read`/`write`/`edit` blocks the model's natural way of
updating its own memory (`./AGENTS.md`). Once the lockdown is in
place, the model has to use Denyx's `denyx_fs_*` tools for memory
updates — which means those paths must be in the policy's
`read_allow`/`write_allow`. Append to `[filesystem]` in
`denyx.toml`:

```toml
[filesystem]
# ... existing read_allow / write_allow ...
read_allow  = [..., "./AGENTS.md"]
write_allow = [..., "./AGENTS.md"]
```

Memory updates now go through the policy gate and land in the
audit log alongside every other operation. **Don't** add
`./opencode.json` or `./denyx.toml` itself to `write_allow` —
those files control whether the lockdown is in effect, and an
agent that can rewrite them can disable Denyx mid-session. The
runtime's self-writable guard catches `denyx.toml`; `opencode.json`
stays write-blocked because the host-level `tools: { write: false }`
is the only path to it, and that path is closed.

## Why this works (and why the alternative doesn't)

The critical property: the model's tool-selection isn't
adversarial, it's *opportunistic*. Given two paths to read a
file, it picks the one that looks more like the work it
remembers from training data. `read` is far more familiar than
`denyx__denyx_fs_read`, so without `tools: { read: false }` the
model will reach for `read` every time. Disabling the built-in
removes the choice; from there the model uses Denyx's tools
because they're the only ones available.

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
