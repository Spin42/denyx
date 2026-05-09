//! `denyx-local-mcp` binary entrypoint.
//!
//! Two subcommands:
//!
//! - `serve` — the MCP server. What Claude Code / opencode launches
//!   per-project. Speaks newline-delimited JSON-RPC 2.0 on stdio,
//!   exposes one tool: `delegate_to_local`.
//! - `doctor` — read-only diagnostic preflight. Probes the
//!   configured endpoint, fingerprints the server, verifies the
//!   chat + embed models are available, and on Ollama reads
//!   `num_ctx` to flag the common "default 2048 too small" pitfall.
//!   Prints copy-pasteable next-steps; never auto-fixes.
//!
//! The chat + embeddings client speaks the **OpenAI v1 API**
//! (`/chat/completions` + `/embeddings`) — every relevant local
//! model server in 2026 supports this natively. Operators point
//! `--endpoint` at:
//!
//!   - Ollama:        `http://localhost:11434/v1` (the default)
//!   - llama.cpp:     `http://localhost:8080/v1`
//!   - LM Studio:     `http://localhost:1234/v1`
//!   - vLLM:          `http://localhost:8000/v1`
//!   - LocalAI:       `http://localhost:8080/v1`
//!   - Text Gen WebUI: `http://localhost:5000/v1`
//!   - MLX-LM:        `http://localhost:8080/v1`
//!
//! Backends that don't speak this shape can implement the
//! `ChatProvider` / `EmbedProvider` traits and link this crate as
//! a library — see the crate README.

use std::io::{stdin, stdout, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use denyx_local_mcp::denyx_client::DenyxMcpClient;
use denyx_local_mcp::doctor::{self, DoctorArgs};
use denyx_local_mcp::openai_compat::{OpenAiCompatChat, OpenAiCompatEmbed};
use denyx_local_mcp::pipeline::StepConfig;
use denyx_local_mcp::prompt::{load_tools_routing, render_tools_routing};
use denyx_local_mcp::rag::CachedEmbed;
use denyx_local_mcp::server::{self, FileTraceSink, TraceSink};

#[derive(Parser, Debug)]
#[command(
    name = "denyx-local-mcp",
    version,
    about = "Local-executor MCP server: OpenAI-compatible local model + Denyx policy gate."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the MCP server (newline-delimited JSON-RPC 2.0 on stdio).
    /// This is what Claude Code / opencode launches per-project.
    Serve(ServeArgs),
    /// Run a read-only preflight check against the configured
    /// endpoint. Probes the server, verifies models are available,
    /// flags Ollama num_ctx pitfalls. Prints fix instructions on
    /// failure; never modifies anything.
    Doctor(DoctorCli),
}

#[derive(Parser, Debug)]
struct ServeArgs {
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

    /// Local chat model identifier. Provider-specific naming
    /// (e.g. `qwen2.5-coder:7b` on Ollama, `qwen2.5-coder-7b-instruct`
    /// on LM Studio, full HF id on vLLM).
    #[arg(long, default_value = "qwen2.5-coder:7b")]
    model: String,

    /// Embedding model identifier. Provider-specific naming.
    #[arg(long, default_value = "nomic-embed-text")]
    embed_model: String,

    /// OpenAI-compatible API base URL. Default points at Ollama's
    /// compat layer; for other servers see the table in the
    /// crate-level docs.
    #[arg(long, default_value = "http://localhost:11434/v1")]
    endpoint: String,

    /// Bearer token for servers that require auth (LocalAI's auth
    /// plugin, hosted compat shims, etc.). Most local servers ignore
    /// this.
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

#[derive(Parser, Debug)]
struct DoctorCli {
    /// OpenAI-compatible API base URL to verify. **If omitted**,
    /// doctor runs in scan mode: probes the standard local-LLM
    /// ports (Ollama 11434, llama.cpp 8080, LM Studio 1234, vLLM
    /// 8000, Text Gen WebUI 5000), lists what's running, and
    /// suggests a copy-pasteable `serve` command.
    #[arg(long)]
    endpoint: Option<String>,

    /// Bearer token, if the server requires auth.
    #[arg(long, env = "DENYX_LOCAL_API_KEY")]
    api_key: Option<String>,

    /// Chat model id to verify is served. Only used in targeted
    /// mode (when `--endpoint` is set).
    #[arg(long, default_value = "qwen2.5-coder:7b")]
    model: String,

    /// Embed model id to verify is served + can produce a vector.
    /// Only used in targeted mode.
    #[arg(long, default_value = "nomic-embed-text")]
    embed_model: String,

    /// Project root to inspect for `denyx.toml`, host-config files,
    /// and audit-dir setup. Defaults to the current working
    /// directory; pass a different path if you're running doctor
    /// from somewhere other than the project root. Pass `--no-project`
    /// to skip the project-side checks entirely.
    #[arg(long)]
    project_path: Option<PathBuf>,

    /// Skip the project-side checks (policy file, host configs,
    /// audit dir, .gitignore). Useful when running `doctor` purely
    /// to verify a remote LLM endpoint.
    #[arg(long)]
    no_project: bool,
}

fn main() -> ExitCode {
    // Implicit-default-subcommand back-compat. Existing `.mcp.json`
    // entries from before subcommands were introduced look like
    // `denyx-local-mcp --policy ./… --mcp-bin denyx-mcp …` (no
    // "serve" word). Without rewriting, clap rejects those with a
    // "missing subcommand" error. Detect that shape by checking
    // whether argv[1] is a known subcommand or top-level flag — if
    // not (i.e. it starts with `-`), inject "serve" so the existing
    // configs keep working.
    let argv: Vec<std::ffi::OsString> = inject_implicit_serve(std::env::args_os().collect());
    let cli = Cli::parse_from(argv);
    match cli.command {
        Cmd::Serve(args) => match serve(args) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("denyx-local-mcp: {e}");
                ExitCode::from(1)
            }
        },
        Cmd::Doctor(args) => {
            // Resolve project path: explicit --project-path > cwd
            // (unless --no-project disables it).
            let project_path = if args.no_project {
                None
            } else {
                args.project_path
                    .clone()
                    .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
                    .or_else(doctor::default_project_path)
            };
            match args.endpoint {
                None => {
                    // Scan mode: probe known ports, suggest a setup.
                    let scan = doctor::scan();
                    let project = project_path
                        .as_deref()
                        .map(denyx_host::project_diagnosis::diagnose);
                    let (out, code) = doctor::render_scan_with_project(&scan, project.as_ref());
                    print!("{out}");
                    ExitCode::from(code as u8)
                }
                Some(ep) => {
                    // Targeted mode: verify a specific endpoint + models.
                    let report = doctor::run(&DoctorArgs {
                        endpoint: ep,
                        api_key: args.api_key,
                        chat_model: args.model,
                        embed_model: args.embed_model,
                        project_path,
                    });
                    let (out, code) = doctor::render(&report);
                    print!("{out}");
                    ExitCode::from(code as u8)
                }
            }
        }
    }
}

fn serve(cli: ServeArgs) -> Result<()> {
    if !cli.mcp_bin.exists() {
        return Err(anyhow!(
            "denyx-mcp binary not found at {:?}. Pass --mcp-bin to point at the right location.",
            cli.mcp_bin
        ));
    }

    let chat = OpenAiCompatChat::new(cli.endpoint.clone()).with_api_key(cli.api_key.clone());

    let embed_inner = OpenAiCompatEmbed::new(cli.endpoint.clone(), &cli.embed_model)
        .with_api_key(cli.api_key.clone());
    let embed = CachedEmbed::new(embed_inner);

    if !cli.no_precompute {
        if let Err(e) = embed.precompute_library_embeddings() {
            eprintln!(
                "[denyx-local-mcp] warning: precompute_library_embeddings failed: {e}. \
                 Continuing; first call will pay the embedding cost. \
                 Run `denyx-local-mcp doctor` for a structured diagnosis."
            );
        }
    }

    let denyx = DenyxMcpClient::spawn(&cli.mcp_bin, &cli.policy, cli.audit_log.as_deref())
        .context("spawn child denyx-mcp")?;

    // Cross-cutting consistency check: load the same policy file the
    // child denyx-mcp loads, run it through the project diagnosis,
    // and put the bridge into BLOCKED mode if any Critical issues
    // are found. The visibility shape mirrors denyx-mcp's: instead
    // of advertising `delegate_to_local`, the bridge advertises only
    // `denyx_blocked` so the model is told about the inconsistency
    // before it can route any work to the local executor. See
    // `denyx_host::startup_block`.
    let blocked = match denyx_host::Policy::load(&cli.policy) {
        Ok(policy) => {
            let project_root =
                std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let diagnosis = denyx_host::project_diagnosis::diagnose(&project_root);
            denyx_host::startup_block::compute(&policy, &diagnosis)
        }
        // Policy file unloadable here is not fatal — the child
        // denyx-mcp will report it via its own startup banner /
        // tool-call errors. Skip the consistency check; the child
        // is the source of truth for policy validity.
        Err(_) => None,
    };
    if let Some(ref state) = blocked {
        eprint!("{}", state.stderr_banner);
    }

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
        reader,
        &writer,
        &chat,
        &embed,
        &denyx,
        &cfg,
        &counter,
        &*trace,
        blocked.as_ref(),
    )?;

    drop(embed);
    denyx.close();
    Ok(())
}

/// Rewrite `argv` to inject "serve" as the implicit subcommand if
/// `argv[1]` is a flag (starts with `-`) or absent. Preserves the
/// "named subcommand" shape (`denyx-local-mcp serve …` and
/// `denyx-local-mcp doctor …`) while keeping back-compat with
/// pre-subcommand .mcp.json entries that look like
/// `denyx-local-mcp --policy ./…`.
fn inject_implicit_serve(mut argv: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    if argv.len() < 2 {
        return argv;
    }
    let first = argv[1].to_string_lossy().into_owned();
    // Pass through known subcommands and clap meta-flags untouched.
    const PASSTHROUGH: &[&str] = &["serve", "doctor", "help", "--help", "-h", "--version", "-V"];
    if PASSTHROUGH.iter().any(|p| first == *p) {
        return argv;
    }
    // Anything else (typically `--policy`, `--mcp-bin`, etc.) is a
    // legacy direct-serve invocation — inject "serve".
    argv.insert(1, std::ffi::OsString::from("serve"));
    argv
}

#[cfg(test)]
mod tests {
    use super::inject_implicit_serve;
    use std::ffi::OsString;

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(|s| OsString::from(*s)).collect()
    }

    #[test]
    fn injects_serve_when_first_arg_is_a_flag() {
        let out = inject_implicit_serve(os(&["denyx-local-mcp", "--policy", "./denyx.toml"]));
        assert_eq!(
            out,
            os(&["denyx-local-mcp", "serve", "--policy", "./denyx.toml"])
        );
    }

    #[test]
    fn passes_through_explicit_serve_subcommand() {
        let out = inject_implicit_serve(os(&["denyx-local-mcp", "serve", "--policy", "x"]));
        assert_eq!(out, os(&["denyx-local-mcp", "serve", "--policy", "x"]));
    }

    #[test]
    fn passes_through_doctor_subcommand() {
        let out = inject_implicit_serve(os(&["denyx-local-mcp", "doctor"]));
        assert_eq!(out, os(&["denyx-local-mcp", "doctor"]));
    }

    #[test]
    fn passes_through_help_and_version() {
        for arg in ["--help", "-h", "--version", "-V", "help"] {
            let out = inject_implicit_serve(os(&["denyx-local-mcp", arg]));
            assert_eq!(out, os(&["denyx-local-mcp", arg]));
        }
    }

    #[test]
    fn empty_or_one_arg_is_unchanged() {
        assert_eq!(inject_implicit_serve(os(&[])), Vec::<OsString>::new());
        assert_eq!(
            inject_implicit_serve(os(&["denyx-local-mcp"])),
            os(&["denyx-local-mcp"])
        );
    }
}
