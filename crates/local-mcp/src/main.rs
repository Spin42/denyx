//! `denyx-local-mcp` binary entrypoint.
//!
//! Wires the CLI flags into the library's modules and spins up the
//! JSON-RPC server loop on stdio. The actual logic lives in the
//! library; this file is glue.
//!
//! Provider selection:
//!   --provider ollama         → native Ollama API at --endpoint
//!   --provider openai-compat  → OpenAI-compat API at --endpoint
//!                                (llama.cpp / LM Studio / vLLM /
//!                                 LocalAI / Text Gen WebUI / etc.)
//!
//! Default: `ollama` at http://localhost:11434.

use std::io::{stdin, stdout, BufReader};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use clap::Parser;

use denyx_local_mcp::denyx_client::DenyxMcpClient;
use denyx_local_mcp::ollama::{OllamaChat, OllamaEmbed};
use denyx_local_mcp::openai_compat::{OpenAiCompatChat, OpenAiCompatEmbed};
use denyx_local_mcp::pipeline::StepConfig;
use denyx_local_mcp::prompt::{load_tools_routing, render_tools_routing};
use denyx_local_mcp::provider::ChatProvider;
use denyx_local_mcp::rag::{CachedEmbed, EmbedProvider};
use denyx_local_mcp::server::{self, FileTraceSink, TraceSink};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ProviderKind {
    Ollama,
    OpenAiCompat,
}

impl FromStr for ProviderKind {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "ollama" => Ok(Self::Ollama),
            "openai-compat" | "openai" | "compat" => Ok(Self::OpenAiCompat),
            other => Err(format!(
                "unknown provider {other:?}; expected one of: ollama, openai-compat"
            )),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "denyx-local-mcp",
    version,
    about = "Local-executor MCP server: Ollama / OpenAI-compatible local model + Denyx policy gate."
)]
struct Cli {
    /// Path to the Denyx policy TOML file. Passed to the child
    /// denyx-mcp; also read here for the `[tools.X]` routing block
    /// surfaced to the local model.
    #[arg(long)]
    policy: PathBuf,

    /// Path to the denyx-mcp binary. Defaults to
    /// `target/release/denyx-mcp` relative to the cwd, which works
    /// for source builds. For `cargo install`-d setups, point at
    /// `~/.cargo/bin/denyx-mcp` or pass `denyx-mcp` if it's on
    /// $PATH.
    #[arg(long, default_value = "target/release/denyx-mcp")]
    mcp_bin: PathBuf,

    /// Local model identifier (provider-specific naming).
    #[arg(long, default_value = "qwen2.5-coder:7b")]
    model: String,

    /// Embedding model identifier (provider-specific naming).
    #[arg(long, default_value = "nomic-embed-text")]
    embed_model: String,

    /// Which provider API to speak to.
    #[arg(long, default_value = "ollama")]
    provider: ProviderKind,

    /// Provider endpoint. Defaults to Ollama's default
    /// (`http://localhost:11434`). For OpenAI-compat servers, pass
    /// the `/v1` base URL — examples:
    /// `http://localhost:8080/v1` (llama.cpp, LocalAI),
    /// `http://localhost:1234/v1` (LM Studio),
    /// `http://localhost:8000/v1` (vLLM).
    #[arg(long, default_value = "http://localhost:11434")]
    endpoint: String,

    /// Bearer token for OpenAI-compat servers that require auth.
    /// Ignored by the Ollama provider.
    #[arg(long, env = "DENYX_LOCAL_API_KEY")]
    api_key: Option<String>,

    /// Where the child denyx-mcp writes its audit log. Optional —
    /// without it, the child uses its own default.
    #[arg(long)]
    audit_log: Option<PathBuf>,

    /// Append per-step trace lines (JSON) to this file for analysis.
    #[arg(long)]
    trace: Option<PathBuf>,

    /// Skip pre-warming the embedding cache. The first
    /// `delegate_to_local` call will then pay for K embedding HTTP
    /// requests; subsequent calls are warm.
    #[arg(long)]
    no_precompute: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.mcp_bin.exists() {
        return Err(anyhow!(
            "denyx-mcp binary not found at {:?}. Pass --mcp-bin to point at the right location.",
            cli.mcp_bin
        ));
    }

    // Build the chat provider.
    let chat: Box<dyn ChatProvider> = match cli.provider {
        ProviderKind::Ollama => Box::new(OllamaChat::new(cli.endpoint.clone())),
        ProviderKind::OpenAiCompat => {
            Box::new(OpenAiCompatChat::new(cli.endpoint.clone()).with_api_key(cli.api_key.clone()))
        }
    };

    // Build the embed provider, wrapped in a cache.
    let embed_inner: Box<dyn EmbedProvider> = match cli.provider {
        ProviderKind::Ollama => Box::new(OllamaEmbed::new(cli.endpoint.clone(), &cli.embed_model)),
        ProviderKind::OpenAiCompat => Box::new(
            OpenAiCompatEmbed::new(cli.endpoint.clone(), &cli.embed_model)
                .with_api_key(cli.api_key.clone()),
        ),
    };
    let embed = CachedEmbed::new(embed_inner);

    // Pre-warm. Skipped on --no-precompute.
    if !cli.no_precompute {
        if let Err(e) = embed.precompute_library_embeddings() {
            eprintln!(
                "[denyx-local-mcp] warning: precompute_library_embeddings failed: {e}. \
                 Continuing; first call will pay the embedding cost."
            );
        }
    }

    let denyx = DenyxMcpClient::spawn(&cli.mcp_bin, &cli.policy, cli.audit_log.as_deref())
        .context("spawn child denyx-mcp")?;

    let routing_block = render_tools_routing(&load_tools_routing(&cli.policy));
    if !routing_block.is_empty() {
        let tool_count = routing_block.matches("\n- ").count();
        eprintln!("[denyx-local-mcp] surfaced {tool_count} declared tool(s) to the local model");
    }

    let cfg = StepConfig {
        model: cli.model,
        tools_routing: routing_block,
        max_retries: 1,
        retrieve_k: 4,
    };

    let counter = Mutex::new(0u64);
    let stdin = stdin();
    let reader = BufReader::new(stdin.lock());
    let writer = Mutex::new(stdout());

    let trace: Box<dyn TraceSink> = match cli.trace {
        Some(p) => Box::new(FileTraceSink::new(p)),
        None => Box::new(()),
    };

    server::run(
        reader, &writer, &*chat, &embed, &denyx, &cfg, &counter, &*trace,
    )?;

    drop(embed);
    denyx.close();
    Ok(())
}
