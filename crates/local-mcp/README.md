# denyx-local-mcp

The local-executor MCP server for [Denyx](https://github.com/Spin42/denyx).

A cloud orchestrator (Claude Sonnet / Opus / etc.) sees one tool,
`delegate_to_local`. When it calls that tool with a natural-language
step description, this server:

1. retrieves the top-K relevant Starlark code examples from the
   embedded library (cosine similarity over a local embedding model),
2. asks a local chat model (e.g. `qwen2.5-coder:7b`) to emit a
   Starlark program for the step, given the retrieved examples plus
   a strict-rules system prompt,
3. runs the program through a child `denyx-mcp` subprocess so the
   Denyx policy gates every effecting call,
4. on a parse / runtime error (NOT a policy denial), feeds the
   diagnostic back to the model and gives it one fix-it attempt,
5. returns the Denyx output (or full diagnostic on failure) to the
   orchestrator as a tool-call result.

Why this shape: the orchestrator never sees raw `fs.read` content,
HTTP responses, or env-var values — only the per-step result string
the bridge surfaces. Cloud-API token spend drops to "decomposition
+ delegation" instead of "every effect"; secrets stay on the local
machine.

## Install

```sh
cargo install denyx-local-mcp denyx-mcp
```

Or build from source:

```sh
git clone https://github.com/Spin42/denyx
cd denyx
cargo build --release -p denyx-local-mcp -p denyx-mcp
```

## Local model providers

`denyx-local-mcp` speaks the **OpenAI v1 API** (`/chat/completions`
+ `/embeddings`). Every relevant local model server in 2026 supports
this natively — point `--endpoint` at the right base URL:

| Server                  | Default endpoint                  |
|-------------------------|-----------------------------------|
| Ollama (default)        | `http://localhost:11434/v1`       |
| llama.cpp (`llama-server`) | `http://localhost:8080/v1`     |
| LM Studio               | `http://localhost:1234/v1`        |
| vLLM                    | `http://localhost:8000/v1`        |
| LocalAI                 | `http://localhost:8080/v1`        |
| Text Generation WebUI   | `http://localhost:5000/v1`        |
| MLX-LM (Apple Silicon)  | `http://localhost:8080/v1`        |
| TabbyAPI                | `http://localhost:5000/v1`        |
| mistral.rs              | `http://localhost:1234/v1`        |
| NVIDIA NIM              | server-specific `/v1`             |

If your server requires auth (LocalAI's auth plugin, hosted compat
shims, etc.), pass `--api-key <token>` or set
`DENYX_LOCAL_API_KEY`.

### Custom backends

For runtimes that don't speak the OpenAI v1 shape (Triton without a
NIM front, MLC LLM as a server, custom in-house APIs), depend on
this crate as a library and implement two trait methods:

```rust
use denyx_local_mcp::provider::{ChatMessage, ChatProvider};
use denyx_local_mcp::rag::EmbedProvider;

struct MyBackend { /* … */ }

impl ChatProvider for MyBackend {
    fn call_chat(&self, model: &str, messages: &[ChatMessage]) -> anyhow::Result<String> {
        // your HTTP / gRPC / FFI call
        todo!()
    }
}

impl EmbedProvider for MyBackend {
    fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>> {
        todo!()
    }
}
```

Then wire it into the server in your own binary using
`denyx_local_mcp::server::run`.

## Usage

Wire into Claude Code by adding to `.mcp.json`:

```json
{
  "mcpServers": {
    "local-executor": {
      "command": "denyx-local-mcp",
      "args": [
        "--policy", "./denyx.toml",
        "--mcp-bin", "denyx-mcp",
        "--audit-log", "./.denyx/audit.jsonl"
      ]
    }
  }
}
```

The full architecture, the eval numbers, and the threat-model
discussion live in
[`docs/12-local-executor.md`](../../docs/12-local-executor.md).

### Note for Ollama users

Ollama's OpenAI-compatibility layer doesn't accept `num_ctx` per
request — context size is set in the Modelfile. Most coder models
default to `num_ctx=2048`, which is too small for our long system
prompt + RAG examples + step description. Either pull a tag with a
larger context or build a custom Modelfile:

```
FROM qwen2.5-coder:7b
PARAMETER num_ctx 8192
```

```sh
ollama create qwen2.5-coder:7b-ctx8k -f Modelfile
denyx-local-mcp --model qwen2.5-coder:7b-ctx8k --policy ./denyx.toml ...
```

Other servers (llama.cpp, LM Studio, vLLM, LocalAI) set context size
at server-launch time, not per request — same operational shape.

## Crate layout

- `provider` — `ChatProvider` trait + `ChatMessage` + `strip_fences`.
- `openai_compat` — built-in HTTP client speaking OpenAI v1.
- `rag` — embedded library of Starlark examples + retrieval (cosine over embeddings) + `EmbedProvider` trait.
- `prompt` — system prompt template + `[tools.X]` routing parsing.
- `denyx_client` — subprocess JSON-RPC client for child `denyx-mcp`.
- `pipeline` — `execute_step` (chat → run → maybe-retry).
- `server` — the outer MCP server loop.
