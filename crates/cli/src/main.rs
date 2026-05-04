//! `aegis` CLI: load a policy and a Starlark script, run the script
//! against the host with policy enforcement and audit logging.
//!
//! Exit codes:
//!   0 — script ran to completion
//!   1 — script error (Starlark eval failure)
//!   2 — policy violation at runtime
//!   3 — pre-execution verifier rejection
//!   4 — confirm hook denied
//!   5 — i/o or configuration error

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use aegis_host::{
    AegisError, AllowAllConfirm, AuditSink, ConfirmDecision, ConfirmHook, ConfirmRequest,
    DenyAllConfirm, JsonlAuditSink, Runner,
};
use aegis_policy::Policy;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "aegis", version, about = "Run Starlark agent scripts under capability-typed policy")]
struct Cli {
    /// Path to the policy TOML file.
    #[arg(short, long)]
    policy: PathBuf,

    /// Starlark script to run.
    script: PathBuf,

    /// Append audit events to this file (JSON Lines). Defaults to stderr.
    #[arg(long)]
    audit_log: Option<PathBuf>,

    /// Task id stamped into audit events. Defaults to the script filename.
    #[arg(long)]
    task_id: Option<String>,

    /// Auto-confirm every confirm-per-call capability without prompting.
    /// Useful in tests/CI; refuse in production.
    #[arg(long)]
    yes: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("aegis: {e}");
            match e {
                CliError::Aegis(AegisError::Verifier(_)) => ExitCode::from(3),
                CliError::Aegis(AegisError::Policy(_)) => ExitCode::from(2),
                CliError::Aegis(AegisError::ConfirmDenied(_)) => ExitCode::from(4),
                CliError::Aegis(AegisError::Starlark(_)) => ExitCode::from(1),
                CliError::Aegis(AegisError::Io(_)) | CliError::Io(_) | CliError::Other(_) => {
                    ExitCode::from(5)
                }
                CliError::Aegis(AegisError::Other(_)) => ExitCode::from(5),
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Aegis(#[from] AegisError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let policy = Policy::load(&cli.policy)
        .map_err(|e| CliError::Other(format!("load policy {:?}: {e}", cli.policy)))?;
    let script = std::fs::read_to_string(&cli.script)?;
    let task_id = cli
        .task_id
        .unwrap_or_else(|| {
            cli.script
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("script.star")
                .to_string()
        });

    let audit: Arc<dyn AuditSink> = match &cli.audit_log {
        Some(path) => Arc::new(JsonlAuditSink::file(path)?),
        None => Arc::new(JsonlAuditSink::stderr()),
    };
    let confirm: Arc<dyn ConfirmHook> = if cli.yes {
        Arc::new(AllowAllConfirm)
    } else if std::io::stderr().is_terminal() && std::io::stdin().is_terminal() {
        Arc::new(TtyConfirm)
    } else {
        Arc::new(DenyAllConfirm)
    };

    let runner = Runner::new(policy)
        .with_audit(audit)
        .with_confirm_hook(confirm);

    let outcome = runner.run(&task_id, &script, cli.script.to_string_lossy().as_ref())?;
    for line in &outcome.printed {
        println!("{line}");
    }
    Ok(())
}

struct TtyConfirm;
impl ConfirmHook for TtyConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmDecision {
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "[aegis] confirm {} for task {}: {}",
            request.capability, request.task_id, request.summary
        );
        let _ = write!(stderr, "        allow? [y/N] ");
        let _ = stderr.flush();
        let mut line = String::new();
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        if handle.read_line(&mut line).is_err() {
            return ConfirmDecision::Deny;
        }
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed == "y" || trimmed == "yes" {
            ConfirmDecision::Allow
        } else {
            ConfirmDecision::Deny
        }
    }
}
