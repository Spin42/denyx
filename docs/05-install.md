# Install

> ← [Back to docs README](README.md)

Denyx is a Rust workspace. There are no published crates yet — install
from source. The build process is the same on every platform; the
*runtime layer* differs because OS-level isolation is platform-specific.

## Pick your platform

| Host OS    | Where Denyx runs                          | Sandbox layer                   | Setup guide                                                |
|------------|-------------------------------------------|---------------------------------|------------------------------------------------------------|
| **Linux**  | Native binary on the host                 | `bubblewrap` (`bwrap`) — native | This doc, "[Linux native](#linux-native)" below            |
| **macOS**  | Linux binary inside a Lima VM             | `bubblewrap` inside the VM      | [macos-deployment.md](macos-deployment.md)                 |
| **Windows**| Linux binary inside WSL2                  | `bubblewrap` inside WSL         | [windows-deployment.md](windows-deployment.md)             |

The same policy file, the same MCP surface, and the same audit-log
shape work in all three configurations — the only thing that varies
is the bridge between your MCP host (Claude Code, opencode, …) and
the place `denyx-mcp` actually executes.

If you're a *developer* of Denyx itself (modifying the Rust crates),
you can build and run on any of the three; macOS and Windows builds
are uncommon for the runtime path because the bwrap-backed sandbox
is Linux-kernel-only.

## Linux (native)

This is the canonical path. `denyx-mcp` runs as a Linux binary on
your host, with `bwrap` available on `PATH` for OS-level isolation
when `[subprocess].sandbox = "bwrap"` is enabled in the policy.

### 1. Prerequisites

| Component   | Why                                          | Install                                                                      |
|-------------|----------------------------------------------|------------------------------------------------------------------------------|
| Rust stable | Building the workspace.                      | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh`            |
| `git`       | Cloning the repo.                            | Distro package; almost always pre-installed.                                 |
| `bubblewrap` | OS-level sandbox backend (optional but recommended). | Debian/Ubuntu: `apt install bubblewrap` · Fedora: `dnf install bubblewrap` · Arch: `pacman -S bubblewrap` |

If you only want the language-level gate (Starlark + capability
typing + audit log) without OS-level isolation, you can skip
bubblewrap. The policy then must use `[subprocess].sandbox = "none"`.

### 2. Build

```sh
git clone https://github.com/<owner>/post-sigil denyx
cd denyx
cargo build --release
```

That produces three binaries under `target/release/`:

- `denyx` — the CLI (run + init subcommands)
- `denyx-mcp` — the MCP server
- (`denyx-host` and `denyx-policy` are libraries, linked into both)

Optionally put them on your `PATH`:

```sh
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/target/release/denyx"     "$HOME/.local/bin/denyx"
ln -sf "$PWD/target/release/denyx-mcp" "$HOME/.local/bin/denyx-mcp"
```

### 3. Smoke test

```sh
denyx --help
denyx init --lang python --output -    # writes a sample policy to stdout
```

### 4. Run the test suite (optional)

```sh
cargo test --workspace
```

You should see ~177 tests pass.

## macOS

See **[macos-deployment.md](macos-deployment.md)**. Short version:

```sh
brew install lima
limactl start --name=denyx examples/macos/denyx.lima.yaml
limactl shell denyx -- bash -lc "cd '$PWD' && cargo build --release"
```

Then point Claude Code's MCP config at
`limactl shell denyx <path-to>/target/release/denyx-mcp ...`.

The Lima template in
[`examples/macos/denyx.lima.yaml`](../examples/macos/denyx.lima.yaml)
provisions bubblewrap and the Rust toolchain on first boot. Builds
and runs identically to a native Linux deployment from that point
on.

## Windows

See **[windows-deployment.md](windows-deployment.md)**. Short version,
in elevated PowerShell:

```powershell
wsl --install -d Ubuntu-24.04
```

Then in the resulting Ubuntu shell:

```sh
sudo apt-get install -y bubblewrap build-essential pkg-config libssl-dev curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"

git clone https://github.com/<owner>/post-sigil denyx
cd denyx
cargo build --release
```

Then point Claude Code's MCP config at
`wsl.exe -d Ubuntu-24.04 -e <path-to>/target/release/denyx-mcp ...`.

## Optional components

These are independent of the OS-level setup above. Install them on
the side that runs your *agent* (typically the host OS), not
necessarily the side that runs `denyx-mcp`.

### Ollama (for the local-executor flow)

If you want to run the architecture from
[09-local-executor.md](09-local-executor.md) — cloud orchestrator
delegating to a local model — you need [Ollama](https://ollama.com).

Linux:

```sh
curl -fsSL https://ollama.com/install.sh | sh
```

macOS: download from [ollama.com](https://ollama.com) and run the
installer (Ollama runs natively on macOS, no Lima needed for it).

Windows: download from [ollama.com](https://ollama.com); Ollama on
Windows runs natively, not inside WSL.

Pull the models the evaluation harness uses:

```sh
ollama pull qwen2.5-coder:7b      # local executor
ollama pull nomic-embed-text       # for the embedding-RAG retrieval
```

Disk: `qwen2.5-coder:7b` is ~4.7 GB; `nomic-embed-text` is ~270 MB.

Confirm it's serving on `http://localhost:11434`:

```sh
curl -s http://localhost:11434/api/tags | head -c 200
```

### Claude Code (for the orchestrator flow)

[Claude Code](https://claude.com/claude-code) provides the `claude`
CLI. The orchestrated harness uses
`claude -p ... --mcp-config ...` to run Sonnet or Opus as the
orchestrator while delegating actual code to the local executor via
`denyx-mcp`. See [07-claude-code.md](07-claude-code.md) for the
integration setup.

```sh
# follow https://claude.com/claude-code for the latest install method
claude --version
```

You'll need an Anthropic API key and a way to authenticate Claude
Code to your account; consult Claude Code's documentation for
current setup.

### opencode (alternative orchestrator host)

[opencode](https://opencode.ai/) is an open-source agentic IDE that
also speaks MCP. See [08-opencode.md](08-opencode.md) for the MCP
server configuration.

### Python (only if you want to reproduce the eval)

The harnesses under `examples/local_executor/` are pure-Python and
use only the standard library. Python 3.10+ is enough; no
`pip install` is required:

```sh
python3 examples/local_executor/run.py --help
python3 examples/local_executor/run_multistep.py --help
python3 examples/local_executor/run_orchestrated.py --help
python3 examples/local_executor/run_pentest.py --help
```

The orchestrated and pentest harnesses additionally require the
`claude` CLI on `PATH`.

## Where next

- [06-quickstart.md](06-quickstart.md) — generate a policy, run a
  script, watch the audit log.
- [07-claude-code.md](07-claude-code.md) — wire Denyx into Claude
  Code as an MCP tool.
- [08-opencode.md](08-opencode.md) — same for opencode.
- [09-local-executor.md](09-local-executor.md) — the full Sonnet/Opus
  → local 7B → Denyx architecture.
- [macos-deployment.md](macos-deployment.md) — full macOS guide.
- [windows-deployment.md](windows-deployment.md) — full Windows guide.
