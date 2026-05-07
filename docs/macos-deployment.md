# Denyx on macOS

> ← [Back to docs README](README.md) · [Install](07-install.md) · [Architecture](03-architecture.md)

> ⚠️ **Not yet exhaustively tested — feedback wanted.** Denyx's CI runs
> on Linux only. The macOS / Lima path below is the project's
> recommended approach for getting bubblewrap on macOS, but it has not
> been validated across many macOS versions, Lima versions, or
> Apple-Silicon vs Intel hardware. If something doesn't work, please
> [open an issue](https://github.com/Spin42/denyx/issues) or send a
> PR — feedback from real macOS users is exactly what hardens this
> path. Native (no-VM) macOS builds also compile but are similarly
> untested; see the [README's Prerequisites table](../README.md#prerequisites)
> for the trade-off.

This is the supported macOS deployment shape: **run `denyx-mcp`
inside a lightweight Linux VM (Lima) and let your host's MCP client
talk to it through `limactl shell`.** No native macOS code, no
deprecated APIs, no Apple-vendor entitlements. Same isolation
guarantees as a Linux deployment because it *is* a Linux deployment.

If you'd rather skip the rationale, the
[four-command quickstart](#quickstart) below gets you running.

## Why this shape

The honest situation on macOS in 2026:

- **`sandbox-exec` (Seatbelt)** has been deprecated since macOS 10.7
  (2011). Apple's own internal tools still use it; nobody knows how
  long that will last. We don't ship code that depends on it.
- **App Sandbox** requires a `.app` bundle, code-signing, and Launch
  Services — the wrong shape for a CLI runtime.
- **Endpoint Security framework** is the API Apple actually wants
  security tools to use, but the entitlement
  (`com.apple.developer.endpoint-security.client`) is granted
  case-by-case and the review process is months. Not viable for an
  open-source project today.
- **Virtualization.framework + a built-in microVM** is the
  long-term right answer, but it's 3–6 weeks of engineering and a
  shipped Linux disk image — disproportionate to v0.1.

So the immediately-correct answer is what the wider Mac ecosystem
already does for "Linux-shaped tooling on a Mac": run the tooling in
a small Linux VM. Docker Desktop, Lima, OrbStack, Colima, Bun's CI,
Buildkit, Nix's daemon — they all use this pattern. Denyx is not
special.

The cost of this shape is one-time setup (install Lima, boot a VM)
and the Linux kernel running on your machine. The benefit is that
**the macOS deployment behaves identically to a Linux deployment**:
bubblewrap real, namespaces real, audit log on a real ext4
filesystem, no platform-specific code paths to maintain.

## Quickstart

```sh
brew install lima

limactl start --name=denyx examples/macos/denyx.lima.yaml

limactl shell denyx -- bash -lc \
  "cd '$PWD' && cargo build --release"
```

Then add this to your Claude Code (or other MCP host) configuration:

```jsonc
{
  "mcpServers": {
    "denyx": {
      "command": "limactl",
      "args": [
        "shell", "denyx",
        "/Users/YOU/Projects/post-sigil/target/release/denyx-mcp",
        "--policy", "/Users/YOU/Projects/myapp/denyx.toml"
      ]
    }
  }
}
```

The agent calls `denyx_run` from the host; the call traverses
`limactl shell` (stdio JSON-RPC), lands in the VM, the script runs
under bubblewrap, the printed output flows back up the pipe. Path
arguments resolve identically on both sides because Lima mirrors the
host's `$HOME` at the same absolute path inside the VM.

## Prerequisites

| Component | Why                                                    | Link                                |
|-----------|--------------------------------------------------------|-------------------------------------|
| Lima      | Manages the Linux VM and the `limactl shell` bridge.   | <https://lima-vm.io>                |
| Homebrew  | Easiest way to install Lima.                           | <https://brew.sh>                   |
| Denyx     | The thing being sandboxed (built inside the VM).        | This repo.                          |

Hardware: any Apple Silicon Mac (M1+) on macOS 11 or newer, or any
Intel Mac on macOS 12 or newer. Lima uses Apple's
Virtualization.framework, so no kernel extensions and no admin
password prompts after `brew install`.

## Step-by-step

### 1. Install Lima

```sh
brew install lima
limactl --version    # 1.x or newer expected
```

### 2. Boot the Denyx VM

The repo ships a tested template at
[`examples/macos/denyx.lima.yaml`](../examples/macos/denyx.lima.yaml).
Boot a VM with it:

```sh
limactl start --name=denyx examples/macos/denyx.lima.yaml
```

First boot takes ~2 minutes (downloading the Ubuntu cloud image,
installing bubblewrap and the build toolchain). Subsequent
`limactl start denyx` calls bring the VM up in 5–10 s.

The template:

- Uses Ubuntu 24.04 LTS (recent kernel, bwrap in apt).
- Mirrors `~/` on the host into the VM at the same absolute path.
- Provisions `bubblewrap` and the Rust toolchain.
- Verifies user namespaces work before declaring provisioning
  complete — if the kernel can't run bwrap, the VM refuses to come
  up rather than silently degrading.
- Runs CPU/memory at 2 cores / 2 GiB by default. Bump in the YAML
  if you run heavy local-executor evals inside the VM.

### 3. Build Denyx inside the VM

Because Lima mirrors `$HOME` at the same path, you build *once*
inside the VM and the binary is reachable from both sides. From the
host:

```sh
cd ~/Projects/post-sigil    # wherever you cloned

limactl shell denyx -- bash -lc \
  "cd '$PWD' && cargo build --release"
```

The `target/release/denyx-mcp` binary now exists at the same path on
the host's filesystem (because `target/` is in your home, which is
mirrored). It's a Linux ELF — you can't run it on macOS directly,
which is fine: `limactl shell` is what runs it.

### 4. Wire it into Claude Code

Edit your Claude Code MCP config (typically
`~/.config/claude/mcp.json` or your project's `.mcp.json`):

```jsonc
{
  "mcpServers": {
    "denyx": {
      "command": "limactl",
      "args": [
        "shell", "denyx",
        "/Users/YOU/Projects/post-sigil/target/release/denyx-mcp",
        "--policy", "/Users/YOU/Projects/myapp/denyx.toml"
      ]
    }
  }
}
```

Replace `YOU` with your username and the policy path with whatever
applies to the project the agent is editing. **The path is the
literal Mac path**; Lima translates it into the same path inside the
VM automatically.

If the VM is stopped when Claude Code calls the MCP server,
`limactl shell` will boot it. There's a one-time ~5 s cold-start cost
for the first call; subsequent calls are stdio-pipe-fast.

### 5. Verify the sandbox actually fired

The whole point is OS-level isolation. Confirm bwrap is in the
chain:

```sh
limactl shell denyx -- bash -lc \
  "echo 'subprocess.exec([\"id\"])' > /tmp/check.star && \
   ~/Projects/post-sigil/target/release/denyx run --policy ~/Projects/myapp/denyx.toml /tmp/check.star"
```

You should see the `id` output. Now flip the policy's
`[subprocess].sandbox = "bwrap"` setting and add a path the agent
shouldn't reach (e.g. `/etc/shadow`) to a script:

```sh
limactl shell denyx -- bash -lc \
  "echo 'fs.read(\"/etc/shadow\")' > /tmp/check2.star && \
   ~/Projects/post-sigil/target/release/denyx run --policy ~/Projects/myapp/denyx.toml /tmp/check2.star"
```

You should see a typed Policy denial — the path isn't in
`read_allow`. If you bypass that gate via subprocess (`["cat",
"/etc/shadow"]`), the bwrap layer ensures the file literally doesn't
exist in the child's filesystem view.

If the policy mode is `"none"` instead of `"bwrap"`, the language
gate still fires but the OS-level layer is off. Use `"bwrap"` for
real production workloads on this VM.

## Performance notes

Numbers from a 2024 M2 MacBook Pro (Apple Silicon native), Ubuntu
24.04 inside Lima:

- VM boot from stopped: 5–10 s.
- First `limactl shell` after boot: ~200 ms.
- Subsequent `denyx_run` calls: dominated by Starlark + bwrap, the
  pipe overhead is <5 ms.
- File reads through virtiofs (host's `~`): within ~10% of native.
- Builds inside the VM: comparable to native macOS Rust builds for
  the same code (the kernel is Linux but the CPU is the same
  silicon).

If you build large workspaces inside the VM regularly, give it more
RAM (`memory: "8GiB"` in the YAML) and CPUs (`cpus: 6`).

## Updating

To pick up new Denyx releases:

```sh
cd ~/Projects/post-sigil
git pull
limactl shell denyx -- bash -lc \
  "cd '$PWD' && cargo build --release"
```

The binary path doesn't change, so your Claude Code MCP config
keeps working.

To update the VM's base OS or bwrap version:

```sh
limactl shell denyx -- bash -lc 'sudo apt-get update && sudo apt-get upgrade -y'
```

## Tradeoffs

What you get with this setup:

- ✅ Real OS-level isolation (bwrap + Linux namespaces).
- ✅ Same audit log, same policy file, same MCP surface as Linux.
- ✅ No native macOS code paths to maintain in Denyx.
- ✅ Future-proof — Lima sits on Apple's blessed
  Virtualization.framework, so no deprecation cliff.

What you trade away:

- ❌ A ~500 MB Linux image lives in `~/.lima/` plus the VM's RAM
  while running.
- ❌ A separate `limactl start denyx` step at boot if you don't
  configure auto-start.
- ❌ Cross-architecture: ARM Mac → ARM Linux, Intel Mac → x86_64
  Linux. If you need to build/test for the *other* arch, you need
  another VM or QEMU.

If those tradeoffs are unacceptable for your environment, see
"Alternatives" below.

## Alternatives

| Tool                | Same shape?        | When to use it                                   |
|---------------------|--------------------|--------------------------------------------------|
| **Lima**            | Yes (recommended)  | Default: smallest dependency footprint, OSS.     |
| **Colima**          | Yes (Lima fork)    | If you also use Docker; Colima ships both.       |
| **OrbStack**        | Yes (Lima-compatible) | Commercial; better UI; faster boot; $99/yr after trial. |
| **Docker Desktop**  | Yes, via container | If your team already standardised on Docker. Build a Dockerfile that installs bwrap + Denyx; run `denyx-mcp` as a long-running container. |
| **Multipass**       | Yes               | Canonical's tool; simpler setup than Lima but less flexible mounts. |
| **Native Virtualization.framework integration** | Future (Denyx v0.2+) | When the project sees enough Mac demand to justify embedding the VM in the binary. |

The MCP wiring pattern is identical across all of these — only the
`command` (`limactl`/`colima`/`orb`/`docker run`/`multipass`) and
the args change.

## What's not covered

- **Native macOS sandboxing.** Not on the v0.1 roadmap. See the
  [threat model](04-security-threat-model.md) for honest scope.
- **Ephemeral VMs per call.** The Lima VM is long-running. If you
  want fresh-VM-per-call isolation, that's the
  Virtualization.framework integration, not Lima.
- **GUI agents inside the VM.** This setup is headless. If you need
  Claude Desktop running inside the VM, use a different stack.

## Where this fits in the docs

| Doc                                            | Role |
|------------------------------------------------|------|
| **This doc** (`macos-deployment.md`)           | Run Denyx on a Mac. Operational guide. |
| [windows-deployment.md](windows-deployment.md) | The parallel doc for Windows + WSL2. |
| [07-install.md](07-install.md)                 | Generic install (Linux native, plus pointers here for macOS / Windows). |
| [06-policy-file.md](06-policy-file.md)         | Policy file reference. The same policy works on Linux, macOS-via-Lima, and Windows-via-WSL2. |
| [04-security-threat-model.md](04-security-threat-model.md) | What the runtime defends against. The deployment shape doesn't change the threat model. |
