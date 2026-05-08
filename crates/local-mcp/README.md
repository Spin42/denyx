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

`denyx-local-mcp` is provider-agnostic. Pick one:

| `--provider`           | Endpoints used                       | Works with                                                    |
|------------------------|--------------------------------------|---------------------------------------------------------------|
| `ollama` (default)     | `/api/chat` + `/api/embeddings`      | [Ollama](https://ollama.com)                                  |
| `openai-compat`        | `/chat/completions` + `/embeddings`  | llama.cpp's server, LM Studio, vLLM, LocalAI, Text Generation WebUI's OpenAI extension, Ollama's `/v1` compat layer, anything else exposing the OpenAI v1 API |

Custom backends can implement the [`ChatProvider`] / [`EmbedProvider`]
traits and link the crate as a library — see
[`docs/12-local-executor.md`](../../docs/12-local-executor.md) for
how to drive that in your own deployment.

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

For a non-Ollama provider, also pass `--provider openai-compat
--endpoint http://localhost:8080/v1` (or wherever your server lives).

The full architecture, the eval numbers, and the threat-model
discussion live in
[`docs/12-local-executor.md`](../../docs/12-local-executor.md).

## Crate layout

- `provider` — `ChatProvider` trait + `ChatMessage` + provider-agnostic helpers.
- `ollama` — Ollama HTTP client (chat + embeddings).
- `openai_compat` — OpenAI-compatible HTTP client.
- `rag` — embedded library of Starlark examples + retrieval (cosine over embeddings).
- `prompt` — system prompt template + `[tools.X]` routing parsing.
- `denyx_client` — subprocess JSON-RPC client for child `denyx-mcp`.
- `pipeline` — `execute_step` (chat → run → maybe-retry).
- `server` — the outer MCP server loop.

[`ChatProvider`]: src/provider.rs
[`EmbedProvider`]: src/rag.rs
