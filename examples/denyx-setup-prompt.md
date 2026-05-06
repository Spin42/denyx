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

Goal: a working `denyx.toml` plus a project-local MCP config wiring
`denyx-mcp` to this project, so future runs of Claude Code or
opencode in this directory have every effecting tool call
policy-gated. **Project-specific. Don't write to $HOME or anywhere
outside the cwd.**

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

Build the MCP `command`/`args` based on the OS branch from Step 0
and which install path resolved in 0.3. `<denyx-mcp>` below is
either the bare command name (`denyx-mcp`, when installed via
`cargo install denyx-mcp`) or the absolute path
(`<repo>/target/release/denyx-mcp`, when built from source).

  - Linux native:
      command: <denyx-mcp>
      args:    ["--policy", "./denyx.toml", "--confirm-mode", "auto"]

  - macOS (Lima):
      command: limactl
      args:    ["shell", "denyx", "<denyx-mcp>",
                "--policy", "<absolute-policy-path>", "--confirm-mode", "auto"]
      (Lima mirrors the host's $HOME at the same absolute path
      inside the VM, so use the host's absolute path for the policy
      file. The `<denyx-mcp>` here is whatever resolved inside the
      VM in Step 0.3 — usually bare `denyx-mcp` since you'd
      `cargo install` inside the VM.)

  - Windows (WSL2):
      command: wsl.exe
      args:    ["-d", "<distro>", "-e", "<denyx-mcp>",
                "--policy", "<wsl-side-policy-path>", "--confirm-mode", "auto"]
      (Ask the user which WSL distro hosts the denyx install. The
      policy path is the WSL-side path; if the policy lives on a
      Windows drive, use `/mnt/c/...`. `<denyx-mcp>` is whatever
      resolved inside WSL in Step 0.3 — usually bare `denyx-mcp`.)

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

  - The host (Claude Code or opencode) usually picks up a new
    project-local MCP config at the next session start. Tell them
    to restart their host process.
  - From there, every agent action that goes through `denyx_run`
    or the per-capability sugar tools is policy-gated. Built-in
    tools (Bash, Read, Write, …) bypass denyx-mcp; if those exist
    in your host, the user has to disable them or rely on the host
    to prefer the MCP-provided alternatives.

== Step 6: What to commit, what not to ==

Tell the user:

  - **Commit `./denyx.toml`.** It's the policy contract for the
    project — everyone working on this codebase should see it,
    review it, and propose changes via PR.
  - **Whether to commit `./.mcp.json` (or `./opencode.json`)
    depends on which install path you used:**
      * If the config invokes bare `denyx-mcp` (cargo-installed
        path), it's portable across contributors who have also run
        `cargo install denyx-mcp`. Safe to commit — and recommended,
        so contributors don't each have to re-run this prompt.
      * If the config embeds an absolute path to a local checkout
        (`<repo>/target/release/denyx-mcp`), that path differs per
        machine. Either gitignore it and have each contributor run
        this prompt, or commit a templated version (e.g.
        `.mcp.json.example`) with `${DENYX_MCP_BIN}` and document
        the env var in the project README.
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
