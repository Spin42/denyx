# Denyx on Windows

> ← [Back to docs README](README.md) · [Install](07-install.md) · [Architecture](03-architecture.md)

> ⚠️ **Not yet exhaustively tested — feedback wanted.** Denyx's CI runs
> on Linux only. The WSL2 path below is the project's recommended
> approach for getting bubblewrap on Windows, but it has not been
> validated across many Windows builds, WSL kernel versions, or
> distros. If something doesn't work, please
> [open an issue](https://github.com/Spin42/denyx/issues) or send a
> PR — feedback from real Windows users is exactly what hardens this
> path. Native (no-WSL) Windows builds also compile but are similarly
> untested; see the [README's Prerequisites table](../README.md#prerequisites)
> for the trade-off.

This is the supported Windows deployment shape: **run `denyx-mcp`
inside WSL2 (Windows Subsystem for Linux) and let your host's MCP
client talk to it through `wsl.exe -e`.** Windows ships a real Linux
kernel via WSL2; bubblewrap and namespaces work exactly as they do
on bare-metal Linux. No native Windows code, no untested FFI, no
AppContainer ceremony.

If you'd rather skip the rationale, the
[four-command quickstart](#quickstart) below gets you running.

## Why this shape

Native Windows sandboxing equivalent to bubblewrap means **AppContainer
+ Restricted Token + Job Object** — Chromium-sandbox territory:
thousands of lines of platform-specific code, signed-binary
requirements, capability-SID registration, and edge cases that need
real testing on Windows hardware. Shipping a half-implementation
would be security theater.

WSL2 sidesteps all of this by being a real Linux kernel running
under Hyper-V, integrated as a Windows feature with first-class
Microsoft support and no deprecation pressure. The wider ecosystem
already uses it for "Linux-shaped tooling on Windows": the
GitHub-Actions runner, Docker Desktop, Bun, Deno, the entire
JetBrains line on Windows. Denyx is not special.

The cost is a one-time `wsl --install` on the Windows side. The
benefit is that **the Windows deployment behaves identically to a
Linux deployment**: bubblewrap real, namespaces real, audit log on a
real ext4 filesystem, no platform-specific code paths to maintain.

## Quickstart

In an elevated PowerShell on a fresh Windows machine:

```powershell
wsl --install -d Ubuntu-24.04
# (reboot, log in to the new Ubuntu shell, set a Linux username/password)
```

In the resulting Ubuntu shell:

```sh
sudo apt-get update -y
sudo apt-get install -y bubblewrap build-essential pkg-config libssl-dev curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"

git clone https://github.com/<owner>/post-sigil denyx
cd denyx
cargo build --release
```

Then back on Windows, add this to your Claude Code (or other MCP
host) configuration:

```jsonc
{
  "mcpServers": {
    "denyx": {
      "command": "wsl.exe",
      "args": [
        "-d", "Ubuntu-24.04",
        "-e",
        "/home/YOU/denyx/target/release/denyx-mcp",
        "--policy", "/mnt/c/Users/YOU/projects/myapp/denyx.toml"
      ]
    }
  }
}
```

Replace `YOU` with your usernames (the WSL Linux user, and the
Windows account name). The agent calls `denyx_run` from the host;
the call traverses `wsl.exe -e` (stdio JSON-RPC), lands in the
WSL2 distro, the script runs under bubblewrap, the printed output
flows back up the pipe.

## Prerequisites

| Component         | Why                                              | Link                                                   |
|-------------------|--------------------------------------------------|--------------------------------------------------------|
| Windows 10 21H2+ or Windows 11 | WSL2 baseline.                       | <https://learn.microsoft.com/windows/wsl/install>      |
| WSL2 + Ubuntu     | The Linux kernel + userland Denyx runs on.       | (installed by `wsl --install`).                        |
| Denyx             | The thing being sandboxed (built inside WSL).    | This repo.                                             |

Hardware: any 64-bit machine with virtualization extensions enabled
in the BIOS/UEFI (most x86-64 machines from the past decade; ARM
machines via Windows on ARM also work). WSL2 uses Hyper-V under the
hood — no third-party hypervisor required, no admin password
prompts after `wsl --install`.

## Step-by-step

### 1. Install WSL2

In an elevated PowerShell:

```powershell
wsl --install -d Ubuntu-24.04
```

This:

- Enables the WSL2 Windows feature.
- Downloads the Ubuntu 24.04 LTS distro.
- Reboots if needed.

After reboot, the first launch of the Ubuntu shell prompts for a
Linux username + password. Pick anything; you'll only use them
inside the VM.

Confirm:

```powershell
wsl -l -v
# NAME            STATE           VERSION
# Ubuntu-24.04    Running         2
```

### 2. Provision the WSL distro

In the Ubuntu shell:

```sh
sudo apt-get update -y
sudo apt-get install -y \
  bubblewrap \
  ca-certificates \
  curl \
  build-essential \
  pkg-config \
  libssl-dev \
  git

# Confirm bubblewrap can create user namespaces. WSL2 enables them
# by default; this is a smoke check.
bwrap --ro-bind / / --unshare-pid /bin/true && echo "bwrap OK"

# Install rustup if you don't already have a Rust toolchain.
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
    -y --default-toolchain stable --profile minimal
  . "$HOME/.cargo/env"
fi
```

### 3. Build Denyx inside WSL

```sh
git clone https://github.com/<owner>/post-sigil denyx
cd denyx
cargo build --release
```

The `target/release/denyx-mcp` is now a Linux ELF inside the WSL
distro. From Windows it's reachable at
`\\wsl$\Ubuntu-24.04\home\YOU\denyx\target\release\denyx-mcp` — but
you'll typically address it via `wsl.exe -e` rather than that UNC
path.

### 4. Decide where the policy file lives

You have two choices, and both work:

**(a) Policy on the Windows side, accessed via the auto-mount.** WSL2
mounts each Windows drive at `/mnt/<letter>/`. So
`C:\Users\YOU\projects\myapp\denyx.toml` is reachable inside WSL as
`/mnt/c/Users/YOU/projects/myapp/denyx.toml`. **Use this when the
policy lives next to a Windows-side project tree the agent is
editing.**

**(b) Policy on the Linux side.** Faster I/O, lives in the WSL
filesystem. **Use this when the agent's working tree is also on the
Linux side.**

The MCP `args` change accordingly — see below.

### 5. Wire it into Claude Code

Edit your Claude Code MCP config (typically
`%APPDATA%\Claude\mcp.json` or your project's `.mcp.json`):

```jsonc
{
  "mcpServers": {
    "denyx": {
      "command": "wsl.exe",
      "args": [
        "-d", "Ubuntu-24.04",
        "-e",
        "/home/YOU/denyx/target/release/denyx-mcp",
        "--policy", "/mnt/c/Users/YOU/projects/myapp/denyx.toml"
      ]
    }
  }
}
```

Notes:

- `-d Ubuntu-24.04` selects the distro. If you have only one
  installed and made it default, you can omit it.
- `-e` is the "execute" form: pass an executable path (no shell
  interpretation), then args. Avoid `wsl.exe bash -lc '...'`
  patterns for MCP wiring — they introduce shell-quoting bugs that
  break stdio JSON-RPC.
- The policy path is the *Linux-side* path, even if the file lives
  on `C:`. Use `/mnt/c/...` for Windows-resident files.
- WSL distros auto-start on first invocation; subsequent calls are
  ~10 ms pipe-overhead.

### 6. Verify the sandbox actually fired

In the Ubuntu shell:

```sh
echo 'fs.read("/etc/shadow")' > /tmp/check.star
~/denyx/target/release/denyx run \
  --policy /mnt/c/Users/YOU/projects/myapp/denyx.toml \
  /tmp/check.star
```

You should see a typed Policy denial — the path isn't in
`read_allow`. If you bypass the language gate via a subprocess
(`["cat", "/etc/shadow"]`), the bwrap layer ensures the file
literally doesn't exist in the child's filesystem view.

Flip the policy's `[subprocess].sandbox` setting between `"none"`
and `"bwrap"` to feel the difference.

## Performance notes

Numbers from a typical 2024 Windows 11 dev box (Ryzen / 32 GB RAM),
Ubuntu 24.04 inside WSL2:

- WSL distro cold-start: 1–3 s.
- First `wsl.exe -e` after boot: ~50 ms.
- Subsequent `denyx_run` calls: dominated by Starlark + bwrap, the
  pipe overhead is <5 ms.
- File reads through `/mnt/c/...` (Windows drive): noticeably
  slower than Linux-native I/O. For policy files this is fine; for
  large `read_allow` trees, prefer the Linux-side filesystem.
- Builds inside WSL: faster than native Windows for Cargo
  workloads, mostly because Linux filesystem semantics are friendlier
  to Rust's many-small-files build pattern.

## Updating

```sh
cd ~/denyx
git pull
cargo build --release
```

Or update the WSL distro itself:

```sh
sudo apt-get update && sudo apt-get upgrade -y
```

If WSL itself ships a kernel update on the Windows side, run
`wsl --update` from PowerShell.

## Tradeoffs

What you get:

- ✅ Real OS-level isolation (bwrap + Linux namespaces) on a
  Microsoft-blessed kernel.
- ✅ Same audit log, same policy file, same MCP surface as Linux.
- ✅ No native Windows code paths to maintain in Denyx.
- ✅ Future-proof — WSL2 is a strategic Microsoft product with
  consistent investment.

What you trade:

- ❌ Hyper-V is a Windows feature; it must be available (it is on
  Windows 10 Pro/Enterprise/Education and all Windows 11 SKUs;
  Windows 10 Home gets WSL2 but with reduced configurability).
- ❌ Path semantics differ between `/mnt/c/...` (Windows-mounted)
  and `~/...` (Linux-native). Operators have to decide where each
  file lives.
- ❌ A Windows machine without virtualisation extensions in
  BIOS/UEFI can't run WSL2 — they're enabled on essentially all
  modern hardware but worth confirming if `wsl --install` errors.

If those tradeoffs are unacceptable, see "Alternatives" below.

## Alternatives

| Tool                          | Same shape?     | When to use it                                   |
|-------------------------------|-----------------|--------------------------------------------------|
| **WSL2** (recommended)        | Yes             | Default; smallest setup tax, Microsoft-supported. |
| **Hyper-V VM** (Linux guest)  | Yes             | If your org mandates classic full VMs.           |
| **Docker Desktop** + container | Yes (container) | If your team already standardised on Docker on Windows. |
| **Windows Sandbox** (per-call) | Partial         | Built into Windows Pro/Enterprise. Ephemeral; useful for one-shot runs but heavyweight per-call. |
| **Multipass**                 | Yes             | Canonical's tool; simpler than full Hyper-V VMs. |
| **Native AppContainer integration** | Future (Denyx v0.2+ at earliest) | When demand justifies the engineering. Not on the v0.1 roadmap. |

The MCP wiring pattern is identical across all of these — only the
`command` (`wsl.exe`/`docker.exe`/`hyper-v-run`) and the args change.

## What's not covered

- **Native Windows AppContainer sandboxing.** Not on the v0.1
  roadmap. See the [threat model](04-security-threat-model.md) for
  honest scope.
- **Windows 10 1809 and earlier.** Lacks WSL2; only WSL1 is
  available, which doesn't have a real Linux kernel. Upgrade to
  21H2+ or use a Hyper-V VM directly.
- **GUI agents inside the WSL distro.** WSLg works but isn't
  required for `denyx-mcp`; this guide is headless.

## Where this fits in the docs

| Doc                                       | Role |
|-------------------------------------------|------|
| **This doc** (`windows-deployment.md`)    | Run Denyx on Windows. Operational guide. |
| [macos-deployment.md](macos-deployment.md) | The parallel doc for macOS + Lima. |
| [07-install.md](07-install.md)            | Generic install (Linux native, plus pointers here for Windows / macOS). |
| [06-policy-file.md](06-policy-file.md)    | Policy file reference. The same policy works on Linux, macOS-via-Lima, and Windows-via-WSL2. |
| [04-security-threat-model.md](04-security-threat-model.md) | What the runtime defends against. The deployment shape doesn't change the threat model. |
