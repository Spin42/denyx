# Aegis project-setup prompt

Paste **the contents of the fenced block below** as your first message in
Claude Code or opencode, from the **project root directory** of the
project you want to gate. The assistant will detect your stack, generate
an `aegis.toml`, wire `aegis-mcp` into a project-local MCP config, and
smoke-test it.

The prompt is project-specific by design: every file it writes lands in
the current working directory. Nothing is installed system-wide; nothing
in `~/.config/...` is touched.

> **Prerequisite.** You must have already built `aegis` and `aegis-mcp`
> from source (see [docs/05-install.md](../docs/05-install.md) on Linux,
> [docs/macos-deployment.md](../docs/macos-deployment.md) on macOS,
> [docs/windows-deployment.md](../docs/windows-deployment.md) on Windows).
> The prompt assumes the binaries exist somewhere reachable; it doesn't
> walk you through building.

---

````
You are setting up Aegis for the user's CURRENT PROJECT (the directory
you're running in). Aegis is a Rust runtime that gates an agent's
filesystem / network / subprocess / env access through a TOML policy
the operator (not the model) controls.

Goal: a working `aegis.toml` plus a project-local MCP config wiring
`aegis-mcp` to this project, so future runs of Claude Code or
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
     - Linux native: `aegis-mcp` runs as a host binary.
     - macOS: `aegis-mcp` runs inside a Lima VM. The MCP config will
       use `limactl shell aegis <path-to-aegis-mcp> ...`. If
       `limactl --version` fails, stop and tell the user to follow
       docs/macos-deployment.md, then restart this prompt.
     - Windows: `aegis-mcp` runs inside WSL2. The MCP config will
       use `wsl.exe -d <distro> -e <path-to-aegis-mcp> ...`. If WSL
       isn't set up, stop and tell the user to follow
       docs/windows-deployment.md, then restart this prompt.

3. Find the aegis binaries. Ask the user:
   "Where is your Aegis repo (the post-sigil clone)?"
   Then verify `<repo>/target/release/aegis` and `aegis-mcp` exist.
   On macOS/Windows, the path is the *Linux-side* path inside the
   VM/WSL — it's the same as the host path because of the Lima/WSL
   mount conventions, but verify with the OS-appropriate shell.
   If the binaries don't exist, stop and tell the user to run
   `cargo build --release` in the aegis repo first.

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

    <repo>/target/release/aegis init --lang <detected> --output ./aegis.toml

If `aegis.toml` already exists, ASK FIRST before clobbering. Offer
to write `aegis.toml.new` instead and diff against the existing one.

Show the user the generated file. Briefly explain what's in it (it
inherits `secure-defaults`, allows the typical toolchain commands,
denies destructive git operations, leaves `[network]` empty so any
HTTP target is an explicit opt-in).

== Step 3: Customize for this project ==

Walk through these four questions. Edit `./aegis.toml` after each
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

Build the MCP `command`/`args` based on the OS branch from Step 0:

  - Linux native:
      command: <repo>/target/release/aegis-mcp
      args:    ["--policy", "./aegis.toml", "--confirm-mode", "auto"]

  - macOS (Lima):
      command: limactl
      args:    ["shell", "aegis", "<repo>/target/release/aegis-mcp",
                "--policy", "<absolute-policy-path>", "--confirm-mode", "auto"]
      (Lima mirrors the host's $HOME at the same absolute path
      inside the VM, so use the host's absolute path for the policy
      file.)

  - Windows (WSL2):
      command: wsl.exe
      args:    ["-d", "<distro>", "-e",
                "<repo>/target/release/aegis-mcp",
                "--policy", "<wsl-side-policy-path>", "--confirm-mode", "auto"]
      (Ask the user which WSL distro hosts the aegis build. The
      policy path is the WSL-side path; if the policy lives on a
      Windows drive, use `/mnt/c/...`.)

Now write the config:

  - Claude Code: `./.mcp.json` in the project root:
      {
        "mcpServers": {
          "aegis": {
            "command": "<command>",
            "args": [...]
          }
        }
      }

  - opencode: edit `./opencode.json` (or create it). Add an
    `"mcp"` (or `"mcpServers"`, depending on opencode version)
    block with the same shape. If unsure of the key name, ask the
    user to share their opencode version and either look it up or
    drop in both shapes for the user to prune.

If a config already exists, MERGE — don't clobber. Add the `aegis`
server alongside whatever else is there.

== Step 5: Smoke test ==

After the config is in place, run a manual sanity check yourself
(no need to ask the user to restart the host):

  1. From cwd, spawn `aegis-mcp` directly with the same flags the
     config uses, send an `initialize` JSON-RPC, then `tools/call`
     `aegis_run` with a one-line script like
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
  - From there, every agent action that goes through `aegis_run`
    or the per-capability sugar tools is policy-gated. Built-in
    tools (Bash, Read, Write, …) bypass aegis-mcp; if those exist
    in your host, the user has to disable them or rely on the host
    to prefer the MCP-provided alternatives.

== Step 6: What to commit, what not to ==

Tell the user:

  - **Commit `./aegis.toml`.** It's the policy contract for the
    project — everyone working on this codebase should see it,
    review it, and propose changes via PR.
  - **Don't commit `./.mcp.json` (or `./opencode.json`) as-is** if
    it embeds an absolute path to the user's local aegis-mcp
    binary — that path differs per machine. Either:
      * gitignore it and have each contributor run this prompt; OR
      * commit a templated version (e.g. `.mcp.json.example`) where
        the path is `${AEGIS_MCP_BIN}` or similar, and document the
        env var in the project README.
  - For Linux operators who want OS-level isolation: edit
    `aegis.toml` and add `sandbox = "bwrap"` under
    `[subprocess]` (after installing bubblewrap with
    `apt install bubblewrap` or equivalent). For macOS/Windows
    operators, the Lima/WSL2 setup already provides the kernel-
    level boundary.
  - Audit logs go to stderr by default. To capture them, add
    `--audit-log /var/log/aegis/audit.jsonl` (or any path NOT in
    write_allow) to the MCP server's args and `chattr +a` the file
    so it's append-only.

Stop after Step 6. Don't proceed to other tasks unless the user asks.
````
