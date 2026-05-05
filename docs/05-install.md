# Install

> ← [Back to docs README](README.md)

Aegis is a Rust workspace. There are no published crates yet — install
from source.

## Prerequisites

| Component | Why                                                                | Required for                       |
|-----------|--------------------------------------------------------------------|------------------------------------|
| Rust      | Building the workspace.                                            | Everything.                         |
| `git`     | Cloning the repo and (optionally) the integration with VCS in your scripts. | Everything.                |
| Ollama    | Running the local executor model.                                  | The local-executor flow.           |
| Claude Code or opencode | The cloud-orchestrator side.                            | The orchestrated flow.             |
| Python 3.10+ | Running the example evaluation harnesses.                       | Reproducing the eval numbers.      |

If you only want to gate scripts you write yourself, you only need Rust
and git. The rest are for the agentic setups in
[09-local-executor.md](09-local-executor.md).

## Install Rust

The Aegis workspace targets stable Rust. Use [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustc --version    # 1.75+ confirmed
```

## Build Aegis

```sh
git clone https://github.com/<owner>/post-sigil aegis
cd aegis
cargo build --release
```

That produces three binaries under `target/release/`:

- `aegis` — the CLI (run + init subcommands)
- `aegis-mcp` — the MCP server
- (intentionally no separate library binary — `aegis-host` and
  `aegis-policy` are linked into the others)

Optionally put them on your `PATH`:

```sh
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/target/release/aegis"     "$HOME/.local/bin/aegis"
ln -sf "$PWD/target/release/aegis-mcp" "$HOME/.local/bin/aegis-mcp"
```

Smoke test:

```sh
aegis --help
aegis init --lang python --output -    # writes a sample policy to stdout
```

## Install Ollama (for the local-executor flow)

If you want to run the architecture from
[09-local-executor.md](09-local-executor.md) — cloud orchestrator
delegating to a local model — you need [Ollama](https://ollama.com).

Linux:

```sh
curl -fsSL https://ollama.com/install.sh | sh
```

macOS: download from [ollama.com](https://ollama.com) and run the
installer.

Start the daemon (it usually runs as a systemd service after install;
otherwise `ollama serve &`).

Pull the models the evaluation harness uses:

```sh
ollama pull qwen2.5-coder:7b      # local executor (default in the harness)
ollama pull nomic-embed-text       # for the embedding-RAG retrieval
```

Disk: `qwen2.5-coder:7b` is ~4.7 GB; `nomic-embed-text` is ~270 MB.

Confirm it's serving on `http://localhost:11434`:

```sh
curl -s http://localhost:11434/api/tags | head -c 200
```

The local executor harness lives at
`examples/local_executor/run_multistep.py`. It assumes Ollama is
reachable at the default URL and that `qwen2.5-coder:7b` is installed.

## Install Claude Code (for the orchestrator flow)

[Claude Code](https://claude.com/claude-code) provides the `claude` CLI.
The orchestrated harness uses `claude -p ... --mcp-config ...` to run
Sonnet or Opus as the orchestrator while delegating actual code to the
local executor via `aegis-mcp`. See
[07-claude-code.md](07-claude-code.md) for the integration setup.

Install:

```sh
# follow https://claude.com/claude-code for the latest install method
claude --version
```

You'll need an Anthropic API key and a way to authenticate Claude Code
to your account; consult Claude Code's documentation for current setup.

## Install opencode (alternative orchestrator host)

[opencode](https://opencode.ai/) is an open-source agentic IDE that also
speaks MCP. See [08-opencode.md](08-opencode.md) for the MCP server
configuration.

## Python (only if you want to reproduce the eval)

The harnesses under `examples/local_executor/` are pure-Python and use
only the standard library plus `urllib`. Python 3.10+ is enough; no
`pip install` is required:

```sh
python3 examples/local_executor/run.py --help
python3 examples/local_executor/run_multistep.py --help
python3 examples/local_executor/run_orchestrated.py --help
```

The orchestrated harness (`run_orchestrated.py`) additionally requires
the `claude` CLI on `PATH`.

## Run the test suite

Confirm everything is wired:

```sh
cargo test
```

You should see output like:

```
     Running tests/policy.rs (target/debug/deps/policy-...)
test result: ok. 34 passed; 0 failed; ...
     Running tests/host.rs (target/debug/deps/host-...)
test result: ok. 7 passed; 0 failed; ...
     Running tests/taint.rs (target/debug/deps/taint-...)
test result: ok. 7 passed; 0 failed; ...
     Running tests/verifier.rs (target/debug/deps/verifier-...)
test result: ok. 8 passed; 0 failed; ...
     Running tests/init.rs (target/debug/deps/init-...)
test result: ok. 10 passed; 0 failed; ...
```

## Where next

- [06-quickstart.md](06-quickstart.md) — generate a policy, run a script,
  watch the audit log.
- [07-claude-code.md](07-claude-code.md) — wire Aegis into Claude Code as
  an MCP tool.
- [08-opencode.md](08-opencode.md) — same for opencode.
- [09-local-executor.md](09-local-executor.md) — the full Sonnet/Opus →
  local 7B → Aegis architecture.
