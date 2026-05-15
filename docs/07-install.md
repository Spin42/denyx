# Install

> ← [Back to docs README](README.md)

Denyx ships as four crates on crates.io: `denyx-policy`, `denyx-host`,
`denyx-cli` (the `denyx` binary), and `denyx-mcp` (the MCP server
binary). The recommended install is `cargo install denyx-cli
denyx-mcp`. Build-from-source is a fallback for contributors and for
unreleased features.

The install command is the same on every platform; no platform-
specific packages are required for the policy gate, taint redaction,
audit log, Wasm-sandboxed Starlark runner, or host wiring. The only
platform variation is the optional `bubblewrap` layer for OS-level
*subprocess* isolation, which is Linux-only — see
[Advanced: OS-level subprocess sandbox](#advanced-os-level-subprocess-sandbox)
at the bottom of this doc.

## Pick your platform

| Host OS    | Where Denyx runs                          | Sandbox layer for the Starlark interpreter | Optional OS-level subprocess sandbox             | Setup guide                                                |
|------------|-------------------------------------------|--------------------------------------------|--------------------------------------------------|------------------------------------------------------------|
| **Linux**  | Native binary on the host                 | Wasm (wasmtime) — built in                 | `bubblewrap` (`bwrap`) — Linux-only, optional    | This doc, "[Linux native](#linux-native)" below            |
| **macOS**  | Native binary; Lima VM only if you want bwrap or Claude Code v2's OS sandbox | Wasm (wasmtime) — built in                 | `bubblewrap` inside the VM (optional)            | [macos-deployment.md](macos-deployment.md)                 |
| **Windows**| Native binary; WSL2 only if you want bwrap or Claude Code v2's OS sandbox | Wasm (wasmtime) — built in                 | `bubblewrap` inside WSL (optional)               | [windows-deployment.md](windows-deployment.md)             |

The interpreter-containment sandbox (wasmtime wrapping `starlark-rust`)
ships in the host binary on every platform; nothing to install
separately. The same policy file, the same MCP surface, and the same
audit-log shape work in all three configurations.

If you're a *developer* of Denyx itself (modifying the Rust crates),
you can build and run on any of the three.

## Linux (native)

This is the canonical path.

### 1. Prerequisites

| Component   | Why                                          | Install                                                                      |
|-------------|----------------------------------------------|------------------------------------------------------------------------------|
| Rust stable | `cargo install` and build-from-source both need it. | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh`            |
| `git`       | Only needed for the build-from-source fallback. | Distro package; almost always pre-installed.                                 |

No system-level sandbox package is required for the primary install:
the Wasm-sandboxed Starlark runner is built into the host binary.

### 2. Install

```sh
cargo install denyx-cli denyx-mcp
```

That installs two binaries into `~/.cargo/bin/`:

- `denyx` — the CLI (`run`, `init`, `policy explain`, `audit verify`, …)
- `denyx-mcp` — the MCP server (stdio JSON-RPC for Claude Code, opencode, …)

`~/.cargo/bin/` is on `$PATH` after rustup's standard install. If
you've never used `cargo install` before, source `~/.cargo/env` (or
restart your shell) so the binaries become reachable.

> **Building from source instead?** Use this if you need an unreleased
> feature or are contributing to Denyx.
>
> ```sh
> git clone https://github.com/Spin42/denyx
> cd denyx
> cargo build --release
> mkdir -p "$HOME/.local/bin"
> ln -sf "$PWD/target/release/denyx"     "$HOME/.local/bin/denyx"
> ln -sf "$PWD/target/release/denyx-mcp" "$HOME/.local/bin/denyx-mcp"
> ```

### 3. Smoke test

```sh
denyx --help
denyx init --lang python --output -    # writes a sample policy to stdout
```

### 4. Run the test suite (only relevant for build-from-source)

```sh
cargo test --workspace
```

(Run inside the `git clone`d checkout. `cargo install` doesn't ship the
test code; if you want to run the suite you need a source build.)

## macOS

See **[macos-deployment.md](macos-deployment.md)**. Native install:

```sh
cargo install denyx-cli denyx-mcp
```

For Lima-VM hosted setups (only needed if you want the optional bwrap
subprocess sandbox or Claude Code v2's OS sandbox):

```sh
brew install lima
limactl start --name=denyx examples/macos/denyx.lima.yaml
limactl shell denyx -- bash -lc "cargo install denyx-cli denyx-mcp"
```

The Lima template in
[`examples/macos/denyx.lima.yaml`](../examples/macos/denyx.lima.yaml)
provisions bubblewrap and the Rust toolchain on first boot.

## Windows

See **[windows-deployment.md](windows-deployment.md)**. The native
install works in a regular Windows shell after a Rust toolchain
install. WSL2 is only required if you want the optional bwrap
subprocess sandbox or Claude Code v2's OS sandbox.

For the WSL2 path, in elevated PowerShell:

```powershell
wsl --install -d Ubuntu-24.04
```

Then in the resulting Ubuntu shell:

```sh
sudo apt-get install -y build-essential pkg-config libssl-dev curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"

cargo install denyx-cli denyx-mcp
```

## Optional components

These are independent of the OS-level setup above. Install them on
the side that runs your *agent* (typically the host OS), not
necessarily the side that runs `denyx-mcp`.

### Ollama (for the local-executor flow)

If you want to run the architecture from
[12-local-executor.md](12-local-executor.md) — cloud orchestrator
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
`denyx-mcp`. See [09-claude-code.md](09-claude-code.md) for the
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
also speaks MCP. See [10-opencode.md](10-opencode.md) for the MCP
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

## Advanced: OS-level subprocess sandbox

`bubblewrap` is an **optional, advanced-operator-only** add-on. It
enables `[subprocess].sandbox = "bwrap"` in the policy, which wraps
every subprocess the script spawns in a fresh Linux namespace +
bind-mount jail per call.

This addresses a **different threat from the wasm sandbox**, not the
same one:

- The Wasm sandbox (always on with `--use-wasm`, no install required)
  contains the *Starlark interpreter* — interpreter-bug containment
  and fuel-based pure-CPU preemption.
- bwrap contains the *child processes* the script spawns — a
  permitted `python3` or `make` can't reach paths outside the
  policy's bind-mount layout, regardless of how it constructs them
  internally.

You want bwrap when your threat model includes subprocess escape via
path-gate misconfiguration (binaries that take inline code, paths
constructed at runtime inside an interpreter's heap). The wasm
sandbox does not cover that surface; they are complementary layers,
not substitutes.

Install:

```sh
# Debian/Ubuntu
sudo apt install bubblewrap

# Fedora
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

Then in your policy:

```toml
[subprocess]
allow_commands = ["python3", "git", "make"]
sandbox        = "bwrap"
```

Properties, caveats, and the full bind-mount layout are documented
in [`docs/06-policy-file.md` § Subprocess →
Layer 2](06-policy-file.md#subprocess-is-a-privilege-boundary).
Denyx refuses to load if `sandbox = "bwrap"` is set but the binary
isn't on `$PATH` — silent fall-through would be the wrong direction.

macOS and Windows operators can install bubblewrap inside a Lima VM
or WSL2 distro respectively (see the per-platform deployment guides
linked above); native macOS / Windows bwrap-equivalent backends
(`sandbox-exec`, Job Objects) are future work.

## Where next

- [08-quickstart.md](08-quickstart.md) — generate a policy, run a
  script, watch the audit log.
- [09-claude-code.md](09-claude-code.md) — wire Denyx into Claude
  Code as an MCP tool.
- [10-opencode.md](10-opencode.md) — same for opencode.
- [12-local-executor.md](12-local-executor.md) — the full Sonnet/Opus
  → local 7B → Denyx architecture.
- [macos-deployment.md](macos-deployment.md) — full macOS guide.
- [windows-deployment.md](windows-deployment.md) — full Windows guide.
