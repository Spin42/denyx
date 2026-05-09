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
   harness measures (see [12-local-executor.md](12-local-executor.md)).

## Prerequisites

- `denyx` and `denyx-mcp` built and on `$PATH` (see
  [07-install.md](07-install.md)).
- `claude` CLI installed and authenticated.
- A policy file. `denyx init --lang <lang>` is the fastest start — see
  [06-policy-file.md](06-policy-file.md#the-denyx-init-generator).

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

### Configure with `denyx host-config`

The recommended path is to let `denyx host-config` write every
configuration file from your policy in one go. Full flag reference at
[host-config.md](host-config.md); the Claude-Code-specific narrative
is below.

```sh
cd /path/to/your/project
denyx host-config \
    --policy ./denyx.toml \
    --host claude \
    --platform native \
    --sandbox auto
```

This single command:

- creates `./.denyx/` and adds it to `./.gitignore` (audit-log dir),
- writes `./.mcp.json` wiring `denyx-mcp` as a project-local MCP
  server (with `--audit-log ./.denyx/audit.jsonl` and
  `--confirm-mode auto` baked in),
- writes `./.claude/settings.json` denying every built-in
  effecting tool (`Bash`, `Edit`, `Write`, `Read`, `Glob`, `Grep`,
  `WebFetch`, `WebSearch`, `Monitor`, `NotebookEdit`, plus
  `PowerShell` when `--windows` is set), and setting
  `disableBypassPermissionsMode: "disable"` and
  `disableAutoMode: "disable"`,
- emits Claude Code v2's native sandbox stanza, with
  `allowedDomains` derived from your policy's `http_*_allow`
  union and `allowWrite` from any absolute / home-relative
  paths in `[filesystem].write_allow`.

If any of those files already exists, `host-config` **merges**:
unrelated keys are preserved, deny lists are unioned (no
duplicates), the sandbox stanza is deep-merged. To overwrite
instead, pass `--existing replace`. To preview without writing,
pass `--dry-run`.

> **macOS / Windows:** Pass `--platform lima --lima-vm <vm>` (macOS)
> or `--platform wsl --wsl-distro <distro> --windows` (Windows) so
> the generated MCP `command`/`args` shape uses the right wrapper
> (`limactl shell ...` or `wsl.exe -d <distro> -e ...`). On those
> platforms also pass `--policy <absolute-path>` and
> `--audit-log <absolute-path>` — both must be reachable inside the
> VM/distro. See [docs/macos-deployment.md](macos-deployment.md)
> and [docs/windows-deployment.md](windows-deployment.md).

> **`--audit-log` defaults to `./.denyx/audit.jsonl`.** Without an
> audit-log path, `denyx-mcp` writes events to stderr, which
> Claude Code buries in its own MCP-server log directory — making
> the audit feature look broken. `host-config` always passes
> `--audit-log` explicitly so events land somewhere `tail -f` /
> `jq`-able. Override with `--audit-log <path>`.

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

### Why disabling Claude Code's built-in tools is required

`denyx host-config` writes the deny list automatically; this
section explains *why* the lockdown is non-negotiable.

Claude Code ships with built-in `Bash`, `Read`, `Write`, `Edit`,
`Glob`, `Grep`, `WebFetch`, `WebSearch` (and `Monitor`,
`NotebookEdit`, `PowerShell`) tools that touch the filesystem,
network, and shell **directly** — they do NOT go through any MCP
server. If only `denyx-mcp` is wired and the built-ins remain
enabled, the model sees two paths to read a file (`Read` vs.
`mcp__denyx__denyx_fs_read`) and picks the cheaper, ungated one.
Result: Denyx is installed but the gate never fires. Placebo
sandbox.

`host-config` writes (or merges into) `./.claude/settings.json`:

- A `permissions.deny` array with every built-in effecting tool
  name. Claude Code's deny rules always win over allow rules,
  so this is hard-deny. The list is the same for Claude Code v1
  and v2 — the v2 additions (`Agent`/`Task*`/`Cron*`/`Skill`/
  `EnterWorktree`/`SendMessage`/`Team*`) all inherit the parent
  session's `.claude/settings.json` rather than create
  independent bypass paths (verified empirically — see the
  [permission-test recipe](claude-code-permission-tests.md)).
- `disableBypassPermissionsMode: "disable"` to lock out v2's
  `bypassPermissions` mode, which would otherwise skip the deny
  list entirely. (Silently ignored on v1.)
- `disableAutoMode: "disable"` to require explicit user approval
  on every operation, including Denyx-permitted ones. (Drop
  this manually from the generated file if you'd rather trust
  the policy gate as the safety boundary and skip the per-call
  prompt.)
- (With `--sandbox auto`) a `sandbox` stanza enabling Claude
  Code v2's OS-level isolation — Seatbelt on macOS, bubblewrap
  on Linux/WSL2 — with `allowedDomains` and `allowWrite`
  derived from the Denyx policy. Defense-in-depth at the kernel
  layer in case any built-in slips through.

The lockdown is project-local: `./.claude/settings.json` only
affects sessions started in that directory. Restart Claude Code
after running `host-config` so it picks up the new file.

### Add Claude Code's memory files to the policy

Disabling `Read`/`Write`/`Edit` blocks the model's natural way of
updating its own memory (`./CLAUDE.md`, `./.claude/CLAUDE.md`).
Once the lockdown is in place, the model has to use Denyx's
`denyx_fs_*` tools for memory updates — which means those paths
must be in the policy's `read_allow`/`write_allow`. Append to
`[filesystem]` in `denyx.toml`:

```toml
[filesystem]
# ... existing read_allow / write_allow ...
read_allow  = [..., "./CLAUDE.md", "./.claude/CLAUDE.md"]
write_allow = [..., "./CLAUDE.md", "./.claude/CLAUDE.md"]
```

Memory updates now go through the policy gate and land in the
audit log alongside every other operation. **Don't** add
`./.claude/settings.json`, `./.mcp.json`, or `./denyx.toml`
itself to `write_allow` — those files control whether the
lockdown is in effect, and an agent that can rewrite them can
disable Denyx mid-session. The runtime's self-writable guard
catches `denyx.toml`; the others stay write-blocked because the
host-level deny is the only path to them, and the deny blocks.

For Claude Code's auto-memory at
`~/.claude/projects/<encoded-project>/memory/`: that's outside
the project tree. If you want it gated, add the specific
encoded-project path under that directory to
`read_allow`/`write_allow`. Avoid the broad `~/.claude/projects/**`
glob — it lets one project's agent overwrite another project's
memory.

### Why this works (and why the alternative doesn't)

The critical property: the model's tool-selection isn't
adversarial, it's *opportunistic*. Given two paths to read a
file, it picks the one that looks more like the work it
remembers from training data. `Read` is far more familiar to
Claude than `mcp__denyx__denyx_fs_read`, so without a deny rule
the model will reach for `Read` every time. The deny rule
removes the choice; from there the model uses Denyx's tools
because they're the only ones available.

The earlier `--tools ""` + `--allowedTools` CLI-flag approach
also works for one-off launches but doesn't persist into a
project — every `claude` invocation needs the same flags.
`.claude/settings.json` is the project-local equivalent and the
shape Claude Code reads on every session start in that directory.

### What this lockdown can't catch: other MCP servers

The deny list above blocks Claude Code's **own** built-in tools
(`Bash`, `Read`, etc.). It does **not** block tools exposed by
other MCP servers. If you have a separate MCP server configured
that exposes equivalent capabilities — e.g. an
`mcp__filesystem__read_file` tool from a generic-filesystem MCP
server, or `mcp__shell__run_command` from a shell-runner — the
model can use those and bypass Denyx the same way the built-ins
were bypassing it before the lockdown.

Claude Code's permission system is **deny-list-shaped** in v1: it
doesn't support a clean "deny everything except `mcp__denyx__*`"
whitelist (deny rules always win, so `"deny": ["*"]` would block
Denyx's tools too). What you can do:

1. **Audit `.mcp.json` before locking down.** If the project has
   other MCP servers configured, decide for each: is this server
   trusted enough that you're willing to accept the path it
   creates around Denyx? If yes, leave it; if no, remove it from
   `.mcp.json`.

2. **Explicitly deny known competing servers** by adding their
   tool-name patterns to the deny list. After running
   `host-config`, edit `./.claude/settings.json` and append to
   `permissions.deny`:

   ```json
   {
     "permissions": {
       "deny": [
         "Bash", "Edit", "Write", "Read", "Glob", "Grep",
         "WebFetch", "WebSearch", "Monitor", "NotebookEdit",
         "mcp__filesystem__*",
         "mcp__shell__*",
         "mcp__github__create_or_update_file"
       ]
     }
   }
   ```

   Each `mcp__<server>__*` line denies all tools from that
   server. This requires knowing the names of the servers the
   project might add, which is a real maintenance burden. A
   subsequent `host-config` run will preserve the additions
   (merge mode unions the deny list).

3. **Treat adding a new MCP server as a security review event.**
   When a developer wants to add a new `mcpServers` entry,
   require them to either (a) accept that the server creates an
   ungated path and document that in the project README, or
   (b) add the server's tool-name pattern to the deny list.

The honest framing: **Claude Code doesn't currently expose a
mechanism for "Denyx is the only MCP server this project trusts;
anything else is denied by default."** If that property is
load-bearing for your threat model, opencode's `permission:
{ "*": "deny", "denyx*": "allow" }` shape (see
[10-opencode.md](10-opencode.md)) gets you closer — opencode
supports the whitelist semantics Claude Code currently doesn't.

### Audit log

`--audit-log` is already in the recommended config above. Each
tool call produces one JSON Lines record per effecting action,
written to the path you specified. Useful queries:

```sh
# Tail the audit live as the agent works:
tail -f /absolute/path/to/your/project/.denyx/audit.jsonl

# Extract every denied operation:
jq -c 'select(.status == "denied")' .denyx/audit.jsonl

# Hash-chain integrity check (catches in-place modification,
# insertion, or deletion of any line):
denyx audit verify .denyx/audit.jsonl
```

The audit log path should NOT be in your policy's `write_allow`
— `denyx-mcp` writes the log directly via its own filesystem
access, not through the policy gate. Keeping it out of
`write_allow` means the agent can't `fs.write` over its own
audit trail to tamper with the record.

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

`host-config` always writes `--confirm-mode auto` into the MCP
args. To switch modes, edit `./.mcp.json` after generation (the
`mcpServers.denyx.args` array) — `host-config` won't overwrite
that change on the next run as long as you stay in default
`--existing merge` mode.

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
[12-local-executor.md](12-local-executor.md). It's worth a quick
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
[06-policy-file.md](06-policy-file.md#capabilities-are-derived-not-declared).

**A tool call reports `not in [filesystem].read_allow`:** the path you
asked for isn't covered by `read_allow`. Either add the path to
`read_allow` or use a more permissive pattern. Refresher in
[06-policy-file.md](06-policy-file.md#filesystem).

## Where next

- [10-opencode.md](10-opencode.md) — same setup for opencode.
- [12-local-executor.md](12-local-executor.md) — the local-executor
  architecture in depth, including the evaluation results.
- [06-policy-file.md](06-policy-file.md) — for tightening the policy
  once you know what your agent actually needs.
