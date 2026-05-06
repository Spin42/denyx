# Denyx project-setup prompt

Paste **the contents of the fenced block below** as your first message in
Claude Code or opencode, from the **project root directory** of the
project you want to gate. The assistant will detect your stack, generate
a `denyx.toml`, wire `denyx-mcp` into a project-local MCP config, and
smoke-test it.

The prompt is project-specific by design: every file it writes lands in
the current working directory. Nothing is installed system-wide; nothing
in `~/.config/...` is touched.

> **Prerequisite.** Either:
>
> - **Recommended:** install the published crates with
>   `cargo install denyx-cli denyx-mcp`. This puts a `denyx` and a
>   `denyx-mcp` binary into `~/.cargo/bin/`, which should already be
>   on your `$PATH`.
> - **From source:** clone `Spin42/denyx`, run `cargo build --release`,
>   and the prompt will pick up
>   `<repo>/target/release/{denyx,denyx-mcp}`. Use this if you need
>   features not yet on crates.io, or are contributing.
>
> On **macOS** the binaries must be installed inside a Lima VM (see
> [docs/macos-deployment.md](../docs/macos-deployment.md)). On
> **Windows** they go inside WSL2 (see
> [docs/windows-deployment.md](../docs/windows-deployment.md)). On
> **Linux** they install as host binaries.

---

````
You are setting up Denyx for the user's CURRENT PROJECT (the directory
you're running in). Denyx is a Rust runtime that gates an agent's
filesystem / network / subprocess / env access through a TOML policy
the operator (not the model) controls.

Goal: a working `denyx.toml` plus TWO project-local config
changes — wiring `denyx-mcp` as an MCP server (Step 4a) AND
disabling the host's built-in effecting tools so the model has no
path to side-effects except through `denyx-mcp` (Step 4b). Both
are required; wiring MCP without disabling built-ins gives the
user a placebo sandbox the model will route around.
**Project-specific. Don't write to $HOME or anywhere outside the
cwd.**

Use Edit/Write/Bash/Read freely. Ask the user every question called
out below — don't guess.

== Step 0: Pre-flight ==

1. Detect host. If `.mcp.json` is the natural project-local MCP
   config and you have access to the `Bash`/`Read`/`Edit`/`Write`
   tools, you're in Claude Code. If `opencode.json` is the project-
   local config, you're in opencode. If unsure, ask.

2. Detect OS via `uname -s` (Linux / Darwin) or `$OS` (Windows).
   Branch:
     - Linux native: `denyx-mcp` runs as a host binary.
     - macOS: `denyx-mcp` runs inside a Lima VM. The MCP config will
       use `limactl shell denyx denyx-mcp ...`. If `limactl --version`
       fails, stop and tell the user to follow
       docs/macos-deployment.md, then restart this prompt.
     - Windows: `denyx-mcp` runs inside WSL2. The MCP config will
       use `wsl.exe -d <distro> -e denyx-mcp ...`. If WSL isn't set
       up, stop and tell the user to follow
       docs/windows-deployment.md, then restart this prompt.

3. Find the denyx binaries. Try the recommended path first, then
   fall back to source-built:

   a. **Published install** — run `denyx --version` and
      `denyx-mcp --version` (on Linux, on the host shell; on macOS,
      inside `limactl shell denyx ...`; on Windows, inside
      `wsl.exe -d <distro> -e ...`). If both succeed, use bare
      `denyx` and `denyx-mcp` (they're on $PATH inside `~/.cargo/bin/`).
      Set `<denyx>` and `<denyx-mcp>` to those bare command names
      for the rest of this prompt.

   b. **Source build** — if either command isn't found, ask the user:
      "Where is your Denyx checkout? (The directory containing
      `Cargo.toml` for the `denyx-*` workspace.)"
      Then verify `<repo>/target/release/denyx` and `denyx-mcp`
      exist. Set `<denyx>` and `<denyx-mcp>` to those absolute paths.
      If the binaries don't exist, stop and tell the user to either
      run `cargo install denyx-cli denyx-mcp` (preferred) or
      `cargo build --release` in their checkout.

== Step 1: Detect the project's language ==

Look at the cwd for canonical files:
  - `pyproject.toml` / `setup.py` / `requirements.txt` → python
  - `package.json` → node
  - `Cargo.toml` → rust
  - `Gemfile` → ruby
  - `go.mod` → go
  - none of the above → ask the user

If multiple candidates, ask which is the primary language (a Python
project that ships a small npm bundle should set `--lang python`).

== Step 2: Generate the starter policy ==

Run from cwd:

    <denyx> init --lang <detected> --output ./denyx.toml

(where `<denyx>` is whatever you resolved in Step 0.3 — bare
`denyx` if installed via cargo, or
`<repo>/target/release/denyx` if built from source).

If `denyx.toml` already exists, ASK FIRST before clobbering. Offer
to write `denyx.toml.new` instead and diff against the existing one.

Show the user the generated file. Briefly explain what's in it (it
inherits `secure-defaults`, allows the typical toolchain commands,
denies destructive git operations, leaves `[network]` empty so any
HTTP target is an explicit opt-in).

**Add the host's memory files to the policy.** Because Step 4b
will disable the host's built-in `Read`/`Write`/`Edit` tools, the
model has to use Denyx's `denyx_fs_*` MCP tools for everything,
including updating its own memory. Those calls go through the
policy gate, so the memory paths must be listed in `read_allow`
and `write_allow`. Append the following to `[filesystem]` in
`./denyx.toml` (only the paths relevant to the host you detected
in Step 0; both is fine for a project that gets used from either):

```toml
[filesystem]
# ... existing read_allow / write_allow entries from `denyx init` ...
read_allow  = [..., "./CLAUDE.md", "./AGENTS.md", "./.claude/CLAUDE.md"]
write_allow = [..., "./CLAUDE.md", "./AGENTS.md", "./.claude/CLAUDE.md"]
```

Do NOT add `./.claude/settings.json`, `./opencode.json`,
`./.mcp.json`, or `./denyx.toml` itself to `write_allow` — those
files control whether the lockdown is in effect, and an agent
that can rewrite them can disable Denyx. They remain
write-blocked by the runtime's self-writable guard.

For Claude Code's auto-memory at `~/.claude/projects/<encoded>/memory/`
(outside the project tree): if you want to allow it, add the
specific path under that directory to `read_allow`/`write_allow`.
Allowing the broad `~/.claude/projects/**` lets one project's
agent overwrite another project's memory, so prefer the
specific-encoded-project path the user can show you. **If unsure,
ask the user; don't auto-add ~/.claude paths.**

== Step 3: Customize for this project ==

Walk through these four questions. Edit `./denyx.toml` after each
answer; show the user the diff before moving on.

Q1. **Filesystem read/write.**
    "Beyond the project tree, are there any directories or files
    this project legitimately needs to read or write? (e.g.,
    /tmp/my-app/, a sibling repo, a config file in your home dir.)"
    → Add to `[filesystem].read_allow` / `write_allow` /
      `delete_allow`.
    → If anything looks credentials-shaped (`~/.config/foo/token`,
      `~/.netrc`, etc.), put it in `local_only_read` instead and
      explain why.

Q2. **Network.**
    "Does this project make HTTP calls to specific hosts? List
    them, or say 'no'."
    → Add hostnames to `[network].http_get_allow`. For POST/PUT/
      PATCH/DELETE, ask which verb each host needs and add to the
      matching list. Hosts that return secrets (OpenAI, Anthropic,
      vendor APIs) should ALSO go in `local_only_hosts`.

Q3. **Environment.**
    "Are there environment variables this project needs to read?
    For each: is its value (a) public (PATH, USER, NODE_ENV),
    (b) a credential the agent uses to call a service but which
    must never bubble up to the orchestrator (OPENAI_API_KEY,
    ANTHROPIC_API_KEY), or (c) so secret the agent shouldn't see
    it at all (AWS_SECRET_ACCESS_KEY)?"
    → (a) → `[environment].allow_vars`
    → (b) → `[environment].local_only_vars`
    → (c) → `[environment].deny_vars` (already in secure-defaults
      for AWS / OpenAI / GitHub-token names; add project-specific
      ones here)

Q4. **Subprocess.**
    "Beyond the toolchain commands the template already allows,
    are there any binaries this project needs to run? (e.g.,
    docker, kubectl, terraform, custom build scripts.)"
    → Add to `[subprocess].allow_commands`.
    → If anything is a shell evaluator (bash, sh, zsh, python -c,
      node -e, ruby -e, ...), STOP and warn the user: those bypass
      the path gate because the runtime can't reason about a
      computed argv. Ask if they really want it; if yes, add a
      `[subprocess.deny_args]` entry blocking the inline-exec flag.

Q5. **Approval gates.**
    "Should any operations require explicit per-call approval?
    secure-defaults already lists `fs.delete` and `subprocess.exec`
    in `requires_approval`. Do you want to add anything else?"
    → Add to top-level `requires_approval = [...]` if so.

== Step 4: Wire the project-local MCP config ==

First, create the audit-log directory and gitignore it:

    mkdir -p ./.denyx
    grep -q '^\.denyx/' ./.gitignore 2>/dev/null || echo '.denyx/' >> ./.gitignore

The audit log captures every gated capability call (allowed AND
denied) as one JSON Lines record. Without `--audit-log <path>` in
the args below, denyx-mcp silently writes audit events to stderr,
which the host (Claude Code / opencode) buries in its own MCP-
server log directory — making the events hard to find and
defeating the audit feature for most users. **Always pass
`--audit-log` explicitly.**

Build the MCP `command`/`args` based on the OS branch from Step 0
and which install path resolved in 0.3. `<denyx-mcp>` below is
either the bare command name (`denyx-mcp`, when installed via
`cargo install denyx-mcp`) or the absolute path
(`<repo>/target/release/denyx-mcp`, when built from source).

  - Linux native:
      command: <denyx-mcp>
      args:    ["--policy",       "./denyx.toml",
                "--audit-log",    "./.denyx/audit.jsonl",
                "--confirm-mode", "auto"]

  - macOS (Lima):
      command: limactl
      args:    ["shell", "denyx", "<denyx-mcp>",
                "--policy",       "<absolute-policy-path>",
                "--audit-log",    "<absolute-audit-log-path>",
                "--confirm-mode", "auto"]
      (Lima mirrors the host's $HOME at the same absolute path
      inside the VM, so use the host's absolute path for both the
      policy and the audit log. The `<denyx-mcp>` here is whatever
      resolved inside the VM in Step 0.3 — usually bare `denyx-mcp`
      since you'd `cargo install` inside the VM.)

  - Windows (WSL2):
      command: wsl.exe
      args:    ["-d", "<distro>", "-e", "<denyx-mcp>",
                "--policy",       "<wsl-side-policy-path>",
                "--audit-log",    "<wsl-side-audit-log-path>",
                "--confirm-mode", "auto"]
      (Ask the user which WSL distro hosts the denyx install. Both
      paths are WSL-side; if the project lives on a Windows drive,
      use `/mnt/c/...`. `<denyx-mcp>` is whatever resolved inside
      WSL in Step 0.3 — usually bare `denyx-mcp`.)

**Don't** add `./.denyx/audit.jsonl` to the policy's `write_allow`.
denyx-mcp writes the audit log directly via its own filesystem
access; it doesn't need to be in the policy. Keeping the audit
log OUT of `write_allow` means the agent can't `fs.write` over
its own audit trail to tamper with the record — defence-in-depth
on top of the SHA-256 hash chain that denyx-mcp embeds in each
audit line.

Now write the config:

  - **Claude Code**: `./.mcp.json` in the project root.
      {
        "mcpServers": {
          "denyx": {
            "command": "<command>",
            "args": [...the args you built above...]
          }
        }
      }

  - **opencode**: `./opencode.json` (or create it). The opencode
    config shape is **different** from Claude Code's — don't
    copy-paste the Claude Code shape into opencode.json or
    opencode rejects it at startup with "Unrecognized key:
    mcpServers".
      {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
          "denyx": {
            "type": "local",
            "command": ["<command>", ...the args you built above...],
            "enabled": true
          }
        }
      }
    Three opencode-specific quirks vs Claude Code:
      * Top-level key is `mcp`, not `mcpServers`.
      * Each server entry has `"type": "local"` (use `"remote"`
        if you ever wire opencode at an HTTP-transport MCP
        server; for `denyx-mcp` over stdio, it's `"local"`).
      * `command` is a single ARRAY that contains the binary
        AND its arguments — there is no separate `args` field.
      * `"enabled": true` so opencode actually loads it.

If a config already exists, MERGE — don't clobber. Add the `denyx`
server alongside whatever else is there.

== Step 4b: Disable the host's built-in effecting tools ==

**Critical step. Don't skip this.**

Both Claude Code and opencode ship with built-in tools (`Bash`,
`Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch`, `WebSearch`,
plus host-specific ones like `Monitor`/`NotebookEdit` for Claude
Code) that touch the filesystem, network, and subprocess
**directly** — they do NOT go through any MCP server. If you only
wire `denyx-mcp` and leave the built-ins enabled, the model
ignores `denyx-mcp` and uses the cheaper built-in path. Result:
Denyx is installed, but the policy gate never fires. The user
believes they have a sandbox; they actually have a placebo.

To actually enforce the policy, you have to disable the built-in
effecting tools so the model has no path to side-effects except
via `denyx-mcp`. This is a different config file from Step 4a.

  - **Claude Code** (v1 and v2 both — see version note below):
    write `./.claude/settings.json`:
      {
        "permissions": {
          "deny": [
            "Bash", "Edit", "Write", "Read",
            "Glob", "Grep", "WebFetch", "WebSearch",
            "Monitor", "NotebookEdit"
          ]
        }
      }
    Add `"PowerShell"` on Windows. The bare string form
    (`"Bash"` not `"Bash(*)"`) means "block all invocations of
    this tool." Deny rules always win against allow rules, so
    this is hard-deny.

    **For Claude Code v2** (run `claude --version` to check),
    add ONE more field that prevents the user (or a tricked
    user) from entering `bypassPermissions` mode, which would
    skip the deny list entirely:
      "disableBypassPermissionsMode": "disable"
    The field is silently ignored on v1, so including it
    unconditionally is safe.

    The v2 tools that *aren't* on the deny list — `Agent` (sub-
    agents), `Task*`, `Cron*`, `Skill`, `EnterWorktree`,
    `SendMessage`, `Team*` — were verified empirically to inherit
    the parent session's `.claude/settings.json` rather than
    create independent bypass paths. A sub-agent hits the same
    deny list; a cron-scheduled prompt re-fires through the same
    deny list; etc. They don't need to be in the deny list. See
    `docs/claude-code-permission-tests.md` for the test recipe
    that confirmed this; re-run it after a Claude Code version
    bump to verify nothing changed.

    If `./.claude/settings.json` already exists with other
    permissions, MERGE the deny array — don't clobber existing
    keys. Existing entries in `permissions.deny` are kept;
    Denyx's entries are added.

  - **opencode**: ADD a `tools` block to the same
    `./opencode.json` you wrote in Step 4a:
      {
        "$schema": "https://opencode.ai/config.json",
        "tools": {
          "bash": false,
          "read": false,
          "write": false,
          "edit": false,
          "glob": false,
          "grep": false,
          "webfetch": false,
          "websearch": false
        },
        "mcp": {
          "denyx": { ...the entry from Step 4a... }
        }
      }
    `tools: false` removes the built-in entirely so it doesn't
    appear in the model's tool list. opencode also accepts a
    `permission` block with `"*": "deny"` + `"denyx*": "allow"`
    as a defence-in-depth wildcard, but the `tools` block is the
    primary mechanism — don't skip it.

After writing both configs, briefly tell the user what just
happened: "I disabled the host's built-in `Bash` / `Read` /
`Write` / `Edit` / `Glob` / `Grep` / `WebFetch` / `WebSearch`
tools. Every effecting operation in this project now goes
through Denyx's MCP tools and is gated by `denyx.toml`. The
agent's own memory files (`CLAUDE.md`, `AGENTS.md`,
`.claude/CLAUDE.md`) are listed in `denyx.toml`'s
`read_allow`/`write_allow` from Step 2, so memory updates still
work — they just go through the policy gate now. If the model
later complains it can't read or write something it needs, the
choice is: widen `denyx.toml` to allow the operation (preferred
— keeps the policy under git review), or re-enable a specific
built-in in `.claude/settings.json` / `opencode.json` (faster but
breaks the gate for that operation)."

== Step 5: Smoke test ==

After the config is in place, run a manual sanity check yourself
(no need to ask the user to restart the host):

  1. From cwd, spawn `<denyx-mcp>` directly with the same flags
     the config uses, send an `initialize` JSON-RPC, then
     `tools/call` `denyx_run` with a one-line script like
     `print(fs.read("README.md")[:80])`.
     - If it errors with "policy violation", confirm `README.md`
       is actually in `read_allow` (the template usually allows
       it). Adjust if not.
     - If it errors with "no such tool" or fails to spawn, debug
       the command path.
  2. Try a deliberately denied call: `print(fs.read("/etc/passwd"))`.
     This MUST return a policy violation — that's how you know the
     gate is live.

If the smoke test passes, tell the user:

  - The host (Claude Code or opencode) picks up the new
    project-local config at the next session start. Tell them to
    restart their host process.
  - After the restart, the model sees the `denyx-mcp` tools but
    NOT the host's built-in `Bash`/`Read`/`Write`/`Edit`/`Glob`/
    `Grep`/`WebFetch`/`WebSearch` tools — those were disabled in
    Step 4b. Every effecting operation in this project now goes
    through Denyx and is gated by `denyx.toml`.
  - If the model complains it can't read or run something it
    needs, that's the policy doing its job. Either widen
    `denyx.toml` to allow the operation through Denyx, or
    re-enable a specific built-in in the host config — the user
    decides; don't auto-loosen.

== Step 6: What to commit, what not to ==

Tell the user:

  - **Commit `./denyx.toml`.** It's the policy contract for the
    project — everyone working on this codebase should see it,
    review it, and propose changes via PR.
  - **Whether to commit `./.mcp.json` / `./opencode.json` /
    `./.claude/settings.json` depends on which install path you
    used:**
      * If the MCP config invokes bare `denyx-mcp` (cargo-
        installed path), it's portable across contributors who
        have also run `cargo install denyx-mcp`. Safe to commit
        — and recommended, so contributors don't each have to
        re-run this prompt. The `.claude/settings.json` deny
        list and the `tools` block in `opencode.json` are also
        portable; commit them.
      * If the MCP config embeds an absolute path to a local
        checkout (`<repo>/target/release/denyx-mcp`), that path
        differs per machine. Either gitignore the MCP-config
        file and have each contributor run this prompt, or commit
        a templated version (e.g. `.mcp.json.example`) with
        `${DENYX_MCP_BIN}` and document the env var in the project
        README. Note: `.claude/settings.json` is still safe to
        commit because it doesn't reference the binary path.
  - For Linux operators who want OS-level isolation: edit
    `denyx.toml` and add `sandbox = "bwrap"` under
    `[subprocess]` (after installing bubblewrap with
    `apt install bubblewrap` or equivalent). For macOS/Windows
    operators, the Lima/WSL2 setup already provides the kernel-
    level boundary.
  - Audit logs go to stderr by default. To capture them, add
    `--audit-log /var/log/denyx/audit.jsonl` (or any path NOT in
    write_allow) to the MCP server's args and `chattr +a` the file
    so it's append-only.

Stop after Step 6. Don't proceed to other tasks unless the user asks.
````
