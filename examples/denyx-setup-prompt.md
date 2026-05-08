# Denyx project-setup prompt

Paste **the contents of the fenced block below** as your first message in
Claude Code or opencode, from the **project root directory** of the
project you want to gate. The assistant will detect your stack, generate
a `denyx.toml`, wire `denyx-mcp` into a project-local MCP config, and
smoke-test it.

The prompt is project-specific by design: every file it writes lands in
the current working directory. Nothing is installed system-wide; nothing
in `~/.config/...` is touched.

> **Prerequisite — install Denyx first.** The default install is:
>
> ```sh
> cargo install denyx-cli denyx-mcp
> ```
>
> Both binaries land in `~/.cargo/bin/` and should already be on your
> `$PATH`. Build-from-source is a fallback for unreleased features or
> contributors: clone `Spin42/denyx`, run `cargo build --release`, and
> the prompt will pick up `<repo>/target/release/{denyx,denyx-mcp}`.
>
> On **macOS** the binaries are installed inside a Lima VM (see
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

Goal: a working `denyx.toml` plus a single `denyx host-config`
invocation (Step 4) that writes both the MCP server wiring AND
the lockdown of the host's built-in effecting tools. Wiring MCP
without disabling built-ins gives the user a placebo sandbox the
model will route around — `host-config` does both at once, so
this can't be skipped by accident.
**Project-specific. Don't write to $HOME or anywhere outside the
cwd.**

Use Edit/Write/Bash/Read freely. Ask the user every question called
out below — **don't guess, and don't skip**. The questions in Step 3
are about the operator's *intent* (what this project is going to do),
not what the current code already does. An empty project, a greenfield
checkout, or a minimal scaffold is **not** grounds to skip them — the
user knows they're going to call OpenAI / hit a database / run docker
even if no code does so yet, and the policy has to be written for that
intent. Asking five questions and confirming "no" five times is the
correct outcome, not a sign you should have stayed silent.

== Step 0: Pre-flight ==

1. Detect host. The well-tested hosts are:
   - **Claude Code** — natural project-local MCP config is `.mcp.json`;
     access to `Bash`/`Read`/`Edit`/`Write` tools.
   - **opencode** — project-local config is `opencode.json`.

   Other MCP-capable hosts also work (Cursor, VSCode + GitHub
   Copilot agent mode, Continue, Cline / Roo Code) but their
   integrations are **not yet thoroughly tested** — read
   [`docs/14-other-hosts.md`](../docs/14-other-hosts.md) before
   proceeding and tell the user explicitly which lockdown gaps to
   expect on their host. If unsure which host you're in, ask.

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

3. Find the denyx binaries. Default path first, then fall back to
   source-built:

   a. **Default (cargo install)** — run `denyx --version` and
      `denyx-mcp --version` (on Linux, on the host shell; on macOS,
      inside `limactl shell denyx ...`; on Windows, inside
      `wsl.exe -d <distro> -e ...`). If both succeed, use bare
      `denyx` and `denyx-mcp` (they're on $PATH inside `~/.cargo/bin/`).
      Set `<denyx>` and `<denyx-mcp>` to those bare command names
      for the rest of this prompt.

   b. **Source build (fallback)** — if either command isn't found,
      first ask the user whether they want you to install via
      `cargo install denyx-cli denyx-mcp` (the default — works for
      most users) or to point at an existing source checkout. If
      they want the source path, ask: "Where is your Denyx checkout?
      (The directory containing `Cargo.toml` for the `denyx-*`
      workspace.)" Then verify `<repo>/target/release/denyx` and
      `denyx-mcp` exist; set `<denyx>` and `<denyx-mcp>` to those
      absolute paths. If neither exists and the user can't run
      `cargo install`, stop and explain why.

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
`denyx` if installed via `cargo install`, or
`<repo>/target/release/denyx` on the source-build fallback).

If `denyx.toml` already exists, ASK FIRST before clobbering. Offer
to write `denyx.toml.new` instead and diff against the existing one.

Show the user the generated file. Briefly explain what's in it (it
inherits `secure-defaults`, allows the typical toolchain commands,
denies destructive git operations, leaves `[network]` empty so any
HTTP target is an explicit opt-in).

**Add the host's memory files to the policy.** Because Step 4
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

Walk through **all five** questions below, in order. Ask each one as
a real question to the user — do not pre-answer "no" on their behalf
because the project looks empty or you can't see code that needs the
capability. Greenfield projects still have intent: the user knows
what they're about to build. Edit `./denyx.toml` after each answer
and show the user the diff before moving on to the next question.

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

== Step 4: Wire the host config (one command) ==

The `denyx host-config` subcommand writes everything in one go:

  - creates `./.denyx/` and adds it to `./.gitignore` (audit-log dir)
  - writes/merges `./.mcp.json` (Claude Code) — wires `denyx-mcp`
  - writes/merges `./.claude/settings.json` (Claude Code) — denies
    every built-in effecting tool (`Bash`, `Read`, `Edit`, `Write`,
    `Glob`, `Grep`, `WebFetch`, `WebSearch`, `Monitor`,
    `NotebookEdit`, plus `PowerShell` on Windows), sets
    `disableBypassPermissionsMode: "disable"` and
    `disableAutoMode: "disable"`, and (with `--sandbox auto`)
    emits the OS-level sandbox stanza derived from the policy
    (Claude Code v2's bubblewrap/Seatbelt sandbox; allowedDomains
    = the policy's `http_*_allow` union).
  - writes/merges `./opencode.json` (opencode) — disables the same
    built-ins via the `tools` block, adds the `permission` deny
    wildcard, and includes the MCP server entry.

If any of these files already exists, host-config **merges**:
unrelated keys are preserved, deny lists are unioned (no
duplicates), the sandbox stanza is deep-merged. Pass
`--existing replace` to overwrite instead of merge.

If the project is gated by a centralised policy/audit server
rather than a local TOML file, **also see Step 4b below** —
add `--policy-url` / `--audit-url` to bake the team endpoints
into the generated MCP entry.

**Host selection.** The default `--host auto` reads `TERM_PROGRAM`,
`CLAUDECODE`, `OPENCODE`, and existing config files in cwd to figure
out which host(s) to wire. Since you (the assistant) already know
which host you're running in from Step 0.1, you can either pass it
explicitly (more deterministic) or rely on auto-detect.

Recognised `--host` values: `claude`, `opencode`, `cursor`, `copilot`
(VSCode + GitHub Copilot agent mode), `continue`, `cline`. Pass
multiple comma-separated. Aliases: `both` = `claude,opencode`,
`all` = every host, `auto` = detect.

Pick the right invocation based on the platform you detected in
Step 0 and the binary location resolved in Step 0.3:

  - Linux native:
      <denyx> host-config \
          --policy ./denyx.toml \
          --host <claude|opencode|cursor|copilot|continue|cline|comma-list|auto> \
          --platform native \
          --denyx-mcp-binary <denyx-mcp> \
          --sandbox auto

  - macOS (Lima): policy and audit-log paths must be ABSOLUTE
    (Lima mirrors the host's `$HOME` inside the VM at the same
    absolute path).
      <denyx> host-config \
          --policy <absolute-policy-path> \
          --audit-log <absolute-audit-log-path> \
          --host <as above> \
          --platform lima \
          --lima-vm denyx \
          --denyx-mcp-binary denyx-mcp \
          --sandbox auto

  - Windows (WSL2): policy and audit-log paths are WSL-side
    (e.g. `/mnt/c/Users/<you>/proj/denyx.toml` if the project
    lives on a Windows drive). Ask the user which WSL distro
    hosts the denyx install.
      <denyx> host-config \
          --policy <wsl-side-policy-path> \
          --audit-log <wsl-side-audit-log-path> \
          --host <as above> \
          --platform wsl \
          --wsl-distro <distro> \
          --denyx-mcp-binary denyx-mcp \
          --windows \
          --sandbox auto

**For Cursor / Copilot / Continue / Cline: read
[`docs/14-other-hosts.md`](../docs/14-other-hosts.md) first.** Those
integrations are not yet thoroughly tested. The MCP wiring should
work; the host-side lockdown layer varies and is incomplete for
some hosts (Cursor and Copilot in particular have only UI-level
tool toggles, not file-based deny lists). Tell the user that
explicitly when wiring those.

After running, show the user `denyx host-config`'s stderr summary
of what changed (it prints `+ wrote <path>` for each file). Then
briefly explain: "I disabled the host's built-in effecting tools
(`Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch`,
`WebSearch`, plus `Monitor`/`NotebookEdit` on Claude Code). Every
effecting operation in this project now goes through Denyx's
MCP tools and is gated by `denyx.toml`. The agent's own memory
files (`CLAUDE.md`, `AGENTS.md`, `.claude/CLAUDE.md`) are listed
in `denyx.toml`'s `read_allow`/`write_allow` from Step 2, so
memory updates still work — they just go through the policy
gate now. If the model later complains it can't read or run
something it needs, the choice is: widen `denyx.toml` to allow
the operation through Denyx (preferred — keeps the policy under
git review), or re-enable a specific built-in in
`.claude/settings.json` / `opencode.json` (faster but breaks the
gate for that operation)."

== Step 4b: Team mode (skip if standalone) ==

Ask the user once: "Is this project gated by a centralised Denyx
policy/audit server, or is the policy a local file in the repo?"
If **local file**, skip this step. If **centralised**, the team
operator already has:
  - a policy URL (e.g. `https://denyx.internal.example.com/policy`)
  - optionally an audit URL (same host, `/audit` path)
  - a per-developer auth token

Re-run host-config with the URL flags:

    <denyx> host-config \
        --policy ./denyx.toml \
        --policy-url <https://...policy> \
        --audit-url <https://...audit> \
        --host <claude|opencode|both> \
        --platform <native|lima|wsl> \
        [--lima-vm denyx | --wsl-distro <distro>] \
        --sandbox auto \
        --existing replace

The local `--policy ./denyx.toml` is still required — host-config
reads it to derive the OS-sandbox `allowedDomains` / `allowWrite`
stanza. At runtime, `denyx-mcp` fetches the URL policy and ignores
the local file. The local file should mirror the URL policy
closely enough that the sandbox stanza isn't a tighter gate than
the URL policy. Re-run host-config after each policy change to
refresh the sandbox layer.

The auth token is **not** baked into the config. Tell the user to
distribute `DENYX_AUTH_TOKEN` via direnv / 1Password CLI / their
secrets tool — never via shell rc files committed to git. See
docs/11-denyx-for-teams.md for the team adoption walkthrough.

A note on `--sandbox`:
  - `auto` (default): emit the sandbox stanza with
    `failIfUnavailable: false`. If the host is missing
    bubblewrap/socat (Linux/WSL2 prereq), it warns at startup and
    runs without sandboxing — defense-in-depth degrades
    gracefully.
  - `required`: emit with `failIfUnavailable: true`. Use for
    managed deployments where sandboxing is a gate.
  - `off`: omit the stanza. The Denyx policy gate is still in
    effect; you lose the OS-level layer.

A note on the audit log: `denyx-mcp` writes it directly via its
own filesystem access; it does NOT need to be in the policy's
`write_allow`. Keeping the audit log OUT of `write_allow` means
the agent can't `fs.write` over its own audit trail to tamper
with the record — defense-in-depth on top of the SHA-256 hash
chain that denyx-mcp embeds in each audit line.

The v2 Claude Code tools that *aren't* on the deny list — `Agent`
(sub-agents), `Task*`, `Cron*`, `Skill`, `EnterWorktree`,
`SendMessage`, `Team*` — were verified empirically to inherit the
parent session's `.claude/settings.json` rather than create
independent bypass paths. A sub-agent hits the same deny list; a
cron-scheduled prompt re-fires through the same deny list; etc.
See `docs/claude-code-permission-tests.md` for the test recipe
that confirmed this; re-run it after a Claude Code version bump
to verify nothing changed.

== Step 5: Verify with `doctor` ==

Run the doctor commands to verify the setup is consistent. **You
can run these now via Bash even though Step 4 just wrote a deny
list — the deny list is loaded by the host on its next session
start, so your current session still has Bash. After the user
restarts the host (Step 6), they'll re-run doctor from a regular
terminal, outside the agent.**

  1. `<denyx> doctor` — operator-facing comprehensive check.
     Inspects denyx.toml, host-config wiring, audit-dir, .gitignore,
     plus cross-cutting consistency (e.g., does any [tools.X]
     backend_url point at a host that's not in network.http_*_allow?
     does the launch shape bypass requires_approval?). Exit 0 = OK,
     1 = warnings, 2 = failures. Show the user the output. If it
     reports anything beyond [INFO], walk back through Steps 2-4
     and apply the suggested fixes.

  2. `<denyx-mcp> doctor` — gate's perspective on the project.
     Treats wiring `denyx-mcp` as the canonical OK shape, INFO on
     `denyx-local-mcp` (local-executor flow), warns when the
     built-in deny list is incomplete.

  3. (Local-executor flow only) `<denyx-local-mcp> doctor` —
     additionally scans for a running local LLM server, checks
     the configured chat + embed models are served, and on Ollama
     reads `num_ctx` (warns when < 8192 since our system prompt
     needs more context).

== Step 5b: Manual smoke test (optional) ==

If `denyx doctor` reported all-OK and you want to see the gate
fire end-to-end before declaring victory:

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
  - After the restart, doctor commands are no longer reachable
    from the agent (Bash is denied). To re-verify the setup at
    any time, run `denyx doctor` (or `denyx-mcp doctor` /
    `denyx-local-mcp doctor`) **from a regular terminal in this
    project's directory**. Doctor is operator-facing and lives
    outside the gated agent session by design — it's read-only
    and never modifies the policy.
  - After the restart, the model sees the `denyx-mcp` tools but
    NOT the host's built-in `Bash`/`Read`/`Write`/`Edit`/`Glob`/
    `Grep`/`WebFetch`/`WebSearch` tools — those were disabled in
    Step 4. Every effecting operation in this project now goes
    through Denyx and is gated by `denyx.toml`.
  - With `--sandbox auto` (the default), Claude Code's own
    OS-level sandbox stanza is also wired in — bubblewrap on
    Linux/WSL2, Seatbelt on macOS. This is defense-in-depth at
    the kernel layer for any built-in tool that might slip
    through.
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
      * If the MCP config invokes bare `denyx-mcp` (the default,
        `cargo install`-based path), it's portable across
        contributors who have also run
        `cargo install denyx-cli denyx-mcp`. Safe to commit —
        and recommended, so contributors don't each have to
        re-run this prompt. The `.claude/settings.json` deny
        list and the `tools` block in `opencode.json` are also
        portable; commit them.
      * If the MCP config embeds an absolute path to a local
        checkout (`<repo>/target/release/denyx-mcp`, the
        source-build fallback), that path differs per machine.
        Either gitignore the MCP-config file and have each
        contributor re-run this prompt, or commit a templated
        version (e.g. `.mcp.json.example`) with `${DENYX_MCP_BIN}`
        and document the env var in the project README. Note:
        `.claude/settings.json` is still safe to commit because it
        doesn't reference the binary path.
  - **Two sandbox layers, separately configurable.** With
    `--sandbox auto` you already opted into Claude Code's own
    OS-level sandbox (covers all built-in tools and any
    subprocess they spawn). On top of that, Denyx has its own
    `subprocess.sandbox = "bwrap"` mode that wraps every
    `subprocess.exec` call from inside Starlark in a fresh
    namespaced jail. They're complementary; running both at
    once on Linux requires nested user namespaces, which is
    fragile — pick one. For most workflows the Claude Code
    sandbox is enough; reserve Denyx's bwrap mode for cases
    where you want fine-grained per-call isolation of subprocess
    invocations the agent makes from Starlark.
  - Audit logs default to `./.denyx/audit.jsonl` (set by
    host-config) and stay out of the policy's `write_allow`,
    so the agent can't tamper with the record. To rotate to
    a long-lived path like `/var/log/denyx/audit.jsonl`, edit
    the `--audit-log` arg in the MCP config and `chattr +a` the
    file so it's append-only.

Stop after Step 6. Don't proceed to other tasks unless the user asks.
````
