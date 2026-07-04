//! `denyx` CLI. Two subcommands:
//!
//! - `denyx run --policy <toml> <script.star>` — load a policy and a
//!   Starlark script, run the script under capability-typed enforcement.
//! - `denyx init --lang <python|node|ruby|rust|go> [--output PATH]` —
//!   emit a starter policy file inheriting `secure-defaults`, with a
//!   language-appropriate toolchain allowlist and git-destructive /
//!   staging-config denies.
//!
//! Run exit codes:
//!   0 — script ran to completion
//!   1 — script error (Starlark eval failure)
//!   2 — policy violation at runtime
//!   3 — pre-execution verifier rejection
//!   4 — confirm hook denied
//!   5 — i/o or configuration error
//!   6 — runtime cap exceeded (wall-time deadline / call-stack)

mod doctor;
mod hook;
mod hook_daemon;
mod host_config;
mod init;

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use denyx_host::{
    AllowAllConfirm, AuditSink, ConfirmDecision, ConfirmHook, ConfirmRequest, DenyAllConfirm,
    DenyxError, JsonlAuditSink, Runner, WasmRunner,
};
use denyx_policy::Policy;

use crate::host_config::{
    claude_mcp, claude_settings, merge_claude_mcp, merge_claude_settings, merge_opencode,
    opencode_config, prepare_audit_dir, Existing, Host, Opts, Platform, Sandbox,
};
use crate::init::Lang;

#[derive(Parser, Debug)]
#[command(
    name = "denyx",
    version,
    about = "Run Starlark agent scripts under capability-typed policy"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a Starlark script under a policy.
    Run(RunArgs),
    /// Generate a starter policy file for a project language.
    Init(InitArgs),
    /// Inspect or validate a policy file.
    Policy(PolicyCli),
    /// Inspect or verify the audit log.
    Audit(AuditCli),
    /// Generate / merge Claude Code or opencode host configs from a
    /// Denyx policy: MCP server wiring + lockdown of built-in
    /// effecting tools + (opt-in) Claude Code OS sandbox stanza.
    HostConfig(HostConfigArgs),
    /// Read-only project preflight: combines project_diagnosis (what
    /// files exist, what's wired, lockdown state) with cross-cutting
    /// consistency checks (policy ↔ host-config ↔ launch-flag ↔
    /// project state). Single entry point for "is my Denyx setup
    /// right?". Defaults to the cwd; pass `--project-path <PATH>`.
    Doctor(doctor::DoctorArgs),
    /// PreToolUse-shaped hook endpoint: reads one tool-call request
    /// as JSON on stdin, checks it against the same policy `denyx
    /// run` enforces, and exits 0 (allow, JSON decision on stdout)
    /// or 2 (deny — for any reason, including internal errors).
    /// Lets Claude Code / opencode delegate native tool-call
    /// authorization to Denyx without routing through the Starlark
    /// MCP surface. See `crates/cli/src/hook.rs` module docs for the
    /// trade-offs (no cross-call IFC, shell composition refused).
    Hook(hook::HookArgs),
    /// Long-lived `denyx hook` backend: keeps a policy resident behind
    /// a Unix socket so `denyx hook --daemon-socket <path>` skips the
    /// cold policy parse on every call. Optional — `denyx hook` on its
    /// own always works standalone. See `crates/cli/src/hook_daemon.rs`
    /// module docs for the wire protocol and its trade-offs (fixed
    /// daemon-side config, no self-daemonization).
    #[command(name = "hook-daemon")]
    HookDaemon(hook_daemon::HookDaemonCli),
}

#[derive(Parser, Debug)]
struct AuditCli {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Subcommand, Debug)]
enum AuditCommand {
    /// Walk a JSONL audit log and verify the SHA-256 chain. Each
    /// entry's `denyx_prev_hash` is checked against the SHA-256 of
    /// the previous line, and `denyx_seq` is checked for monotonic
    /// +1 progression. Reports per-line failures with the kind of
    /// mismatch. Exits 0 if the chain is intact, non-zero
    /// otherwise.
    Verify(AuditTargetArgs),
}

#[derive(Parser, Debug)]
struct AuditTargetArgs {
    /// Path to the JSONL audit log to verify.
    log: PathBuf,

    /// Fail verification if the log's last `denyx_seq` is below this
    /// value. The SHA-256 chain alone detects in-place tampering and
    /// removal of a line from the MIDDLE of the log (both break the
    /// chain and show up as a failure) — but truncating the TAIL
    /// (deleting the most recent N events) produces a shorter, fully
    /// self-consistent chain that `verify_chain` cannot distinguish
    /// from an honestly-shorter log. `--min-seq` closes that only
    /// when paired with external monitoring that remembers the
    /// last-seen count (e.g. a CI step or cron job persisting the
    /// previous `last_seq` and passing it back in on the next run).
    /// It is a mitigation, not a boundary: an attacker with full
    /// local file access can still delete the whole file or replace
    /// it with a forged one at a plausible sequence number. The
    /// actual boundary against a fully compromised local machine is
    /// pushing events to a remote server in real time
    /// (`HttpAuditSink` / `--audit-url`, see `11-denyx-for-teams.md`)
    /// — a local truncation can't retroactively un-send an event
    /// that already left the machine.
    #[arg(long)]
    min_seq: Option<u64>,
}

#[derive(Parser, Debug)]
struct PolicyCli {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    /// Parse a policy file, resolve inheritance, run all load-time
    /// safety checks (including the self-writable guard), and exit 0
    /// on success. Useful as a CI lint step. Non-zero exit + a
    /// human-readable error on failure.
    Validate(PolicyTargetArgs),
    /// Print a human-readable summary of a policy: effective
    /// capabilities (derived from populated resource sections), all
    /// allow/deny rules, declared tools with routing hints, runtime
    /// caps, confirm-gated capabilities. Exits 0 on success.
    Show(PolicyTargetArgs),
}

#[derive(Parser, Debug)]
struct PolicyTargetArgs {
    /// Path to the policy TOML file.
    policy: PathBuf,
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Path to the policy TOML file. If omitted, falls back to the
    /// built-in `secure-defaults` baseline (denies every effecting
    /// capability) and prints a banner explaining how to grant any.
    #[arg(short, long)]
    policy: Option<PathBuf>,

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

    /// Select the legacy in-process Starlark interpreter
    /// instead of the wasmtime-sandboxed runner. The wasm sandbox
    /// is the default in v0.4.0+; pass --no-wasm to opt out for
    /// the (uncommon) case where wasmtime is not available or you
    /// need the in-process runner's behaviour for a specific test.
    /// The wasm path enforces the same Policy gate as the in-process
    /// runner and also enforces [runtime].max_seconds + wasmtime
    /// fuel-based preemption (see docs/wasm-sandbox.md).
    #[arg(long)]
    no_wasm: bool,

    /// Deprecated alias: the wasm sandbox is the default in v0.4.0+,
    /// so this flag is a no-op kept for backward compatibility with
    /// scripts that pass it explicitly. Emits a one-line stderr
    /// reminder when present; will be removed in a future release.
    #[arg(long)]
    use_wasm: bool,
}

#[derive(Parser, Debug)]
struct HostConfigArgs {
    /// Path to the policy TOML file. Used to derive sandbox
    /// `allowedDomains` / `allowWrite` from the policy.
    #[arg(long)]
    policy: PathBuf,

    /// Which host(s) to wire. Comma-separated list. Recognised values:
    /// `claude` (Claude Code), `opencode`, `cursor`, `copilot`
    /// (VSCode + GitHub Copilot agent mode), `continue`, `cline`.
    /// Convenience aliases: `both` = `claude,opencode` (legacy);
    /// `all` = every supported host; `auto` = detect from environment
    /// variables and cwd files.
    #[arg(long, default_value = "auto")]
    host: HostList,

    /// Where to write the configs (project root). Defaults to cwd.
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,

    /// How `denyx-mcp` is launched on this platform.
    #[arg(long, default_value = "native")]
    platform: PlatformArg,

    /// Resolved location of the `denyx-mcp` binary as the host (or
    /// VM/distro for lima/wsl) sees it. Defaults to the bare command
    /// name, which works when `denyx-mcp` is on $PATH (e.g. via
    /// `cargo install denyx-mcp`).
    #[arg(long, default_value = "denyx-mcp")]
    denyx_mcp_binary: String,

    /// Lima VM name. Only used when `--platform lima`.
    #[arg(long, default_value = "denyx")]
    lima_vm: String,

    /// WSL2 distro name. Required when `--platform wsl`.
    #[arg(long)]
    wsl_distro: Option<String>,

    /// Where `denyx-mcp` writes the audit log. The default is project-
    /// local under `./.denyx/`. For Lima/WSL2, pass an absolute path
    /// the VM/distro can write to (the VM mirrors the host's `$HOME`,
    /// so a host absolute path usually works for Lima).
    #[arg(long, default_value = "./.denyx/audit.jsonl")]
    audit_log: PathBuf,

    /// Team mode: bake `--policy-url <URL>` into the MCP entry instead
    /// of `--policy <path>`. The local `--policy` file is still required
    /// because the OS-sandbox stanza is derived from it; at runtime
    /// `denyx-mcp` fetches the URL and ignores the local file. Pair
    /// with `DENYX_AUTH_TOKEN` distributed via direnv / your secrets
    /// tool. See docs/11-denyx-for-teams.md.
    #[arg(long)]
    policy_url: Option<String>,

    /// Team mode: bake `--audit-url <URL>` into the MCP entry instead
    /// of `--audit-log <path>`. Audit events POST to the URL with the
    /// same auth token. May be combined with `--policy-url` (full team
    /// mode) or used alone (centralised audit, local policy).
    #[arg(long)]
    audit_url: Option<String>,

    /// OS-level sandbox emission policy.
    /// - `auto` (default): emit the sandbox stanza with
    ///   `failIfUnavailable: false`. Hosts without bubblewrap warn
    ///   and fall back to non-sandboxed.
    /// - `required`: emit with `failIfUnavailable: true`. The host
    ///   refuses to start unless the sandbox can come up. Use in
    ///   managed deployments where sandboxing is a security gate.
    /// - `off`: omit the sandbox stanza entirely. Denyx still gates
    ///   capabilities; you lose the OS-layer defense-in-depth.
    #[arg(long, default_value = "auto")]
    sandbox: SandboxArg,

    /// Add `PowerShell` to the Claude Code deny list. Set on Windows
    /// hosts; harmless on others (the rule just doesn't match anything).
    #[arg(long)]
    windows: bool,

    /// How to handle existing config files.
    /// - `merge` (default): preserve unrelated keys, union deny lists,
    ///   replace the denyx MCP entry, deep-merge sandbox arrays.
    /// - `replace`: write the generated config as if no file existed.
    #[arg(long, default_value = "merge")]
    existing: ExistingArg,

    /// Print the generated configs to stdout instead of writing to disk.
    #[arg(long)]
    dry_run: bool,

    /// Skip the MCP server wiring. Writes only the lockdown layer
    /// (`.claude/settings.json` deny list + opencode `tools` /
    /// `permission` blocks + sandbox stanza). Use this when the
    /// project's MCP server is something other than `denyx-mcp` —
    /// e.g. the local-executor flow uses `local_mcp.py`, which the
    /// operator wires manually, and Denyx is responsible for the
    /// lockdown only.
    #[arg(long)]
    no_mcp: bool,

    /// When merging `.mcp.json` for Claude Code / Cursor (which
    /// share the schema), refuse to write if any non-denyx
    /// `mcpServers` entry is already present. The threat-model
    /// claim that "the cloud orchestrator only sees
    /// `delegate_to_local`" depends on denyx-local-mcp being the
    /// sole configured MCP server; this flag enforces that
    /// precondition at host-config time. Without it, an operator
    /// can silently invalidate the claim by adding any other
    /// server to the project. Has no effect on hosts that don't
    /// use a shared `.mcp.json` (opencode, Continue).
    #[arg(long)]
    strict_mcp: bool,
}

/// One or more hosts to wire. Wraps a `Vec<Host>` so clap can parse
/// the comma-separated CLI form into the dispatch list. `auto` means
/// "detect from env vars and cwd files at run time"; we represent
/// it by storing an empty `hosts` and a `was_auto` flag so the dispatch
/// can re-resolve it.
#[derive(Clone, Debug)]
struct HostList {
    hosts: Vec<Host>,
    was_auto: bool,
}

impl FromStr for HostList {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lc = s.to_ascii_lowercase();
        let lc = lc.trim();
        if lc == "auto" {
            return Ok(HostList {
                hosts: Vec::new(),
                was_auto: true,
            });
        }
        if lc == "all" {
            return Ok(HostList {
                hosts: vec![
                    Host::Claude,
                    Host::Opencode,
                    Host::Cursor,
                    Host::Copilot,
                    Host::Continue,
                    Host::Cline,
                ],
                was_auto: false,
            });
        }
        let mut out: std::collections::BTreeSet<Host> = std::collections::BTreeSet::new();
        for raw in lc.split(',') {
            let part = raw.trim();
            if part.is_empty() {
                continue;
            }
            let host = match part {
                "claude" | "claude-code" | "claudecode" => Host::Claude,
                "opencode" => Host::Opencode,
                "cursor" => Host::Cursor,
                "copilot" | "github-copilot" | "vscode-copilot" => Host::Copilot,
                "continue" | "continue-dev" => Host::Continue,
                "cline" | "roo" | "roo-code" => Host::Cline,
                "both" => {
                    out.insert(Host::Claude);
                    out.insert(Host::Opencode);
                    continue;
                }
                other => {
                    return Err(format!(
                        "unknown host {other:?}; expected one or more of: \
                         claude, opencode, cursor, copilot, continue, cline \
                         (or aliases: both, all, auto)"
                    ));
                }
            };
            out.insert(host);
        }
        if out.is_empty() {
            return Err("--host got an empty list; pass at least one value".into());
        }
        Ok(HostList {
            hosts: out.into_iter().collect(),
            was_auto: false,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PlatformArg {
    Native,
    Lima,
    Wsl,
}

impl FromStr for PlatformArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "native" | "linux" => Ok(Self::Native),
            "lima" | "macos" | "darwin" => Ok(Self::Lima),
            "wsl" | "wsl2" | "windows" => Ok(Self::Wsl),
            other => Err(format!(
                "unknown platform {other:?}; expected one of: native, lima, wsl"
            )),
        }
    }
}

impl PlatformArg {
    fn as_platform(self) -> Platform {
        match self {
            Self::Native => Platform::Native,
            Self::Lima => Platform::Lima,
            Self::Wsl => Platform::Wsl,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SandboxArg {
    Auto,
    Required,
    Off,
}

impl FromStr for SandboxArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" | "on" => Ok(Self::Auto),
            "required" | "strict" => Ok(Self::Required),
            "off" | "none" | "disable" => Ok(Self::Off),
            other => Err(format!(
                "unknown sandbox mode {other:?}; expected one of: auto, required, off"
            )),
        }
    }
}

impl SandboxArg {
    fn as_sandbox(self) -> Sandbox {
        match self {
            Self::Auto => Sandbox::Auto,
            Self::Required => Sandbox::Required,
            Self::Off => Sandbox::Off,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ExistingArg {
    Merge,
    Replace,
}

impl FromStr for ExistingArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "merge" => Ok(Self::Merge),
            "replace" | "overwrite" => Ok(Self::Replace),
            other => Err(format!(
                "unknown existing-file mode {other:?}; expected: merge or replace"
            )),
        }
    }
}

impl ExistingArg {
    fn as_existing(self) -> Existing {
        match self {
            Self::Merge => Existing::Merge,
            Self::Replace => Existing::Replace,
        }
    }
}

#[derive(Parser, Debug)]
struct InitArgs {
    /// Project language. Determines the toolchain allowlist and
    /// project-layout read/write_allow defaults.
    #[arg(short, long)]
    lang: Lang,

    /// Output path. Defaults to `denyx.toml` in the current directory.
    /// Use `-` to write to stdout instead.
    #[arg(short, long, default_value = "denyx.toml")]
    output: String,

    /// Overwrite an existing file at `--output`. Refused by default
    /// to protect a pre-existing policy.
    #[arg(short, long)]
    force: bool,

    /// Generate a more permissive starter policy. Adds `/tmp/**` to
    /// `write_allow` so scripts can drop scratch files there without
    /// editing the policy. The minimal default (without this flag)
    /// is the conservative choice: project-scoped write paths only.
    /// Opt into `--permissive` when "make it work without thinking
    /// about what to allow" is more important than narrow blast
    /// radius. The doctor will warn on the broader allow-lists this
    /// produces — that's intentional, not a bug.
    #[arg(long)]
    permissive: bool,
}

fn main() -> ExitCode {
    match dispatch() {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("denyx: {e}");
            match e {
                CliError::Denyx(DenyxError::Verifier(_)) => ExitCode::from(3),
                CliError::Denyx(DenyxError::Policy(_)) => ExitCode::from(2),
                CliError::Denyx(DenyxError::ConfirmDenied(_)) => ExitCode::from(4),
                CliError::Denyx(DenyxError::Starlark(_)) => ExitCode::from(1),
                CliError::Denyx(DenyxError::RuntimeLimit(_)) => ExitCode::from(6),
                CliError::Denyx(DenyxError::Io(_)) | CliError::Io(_) | CliError::Other(_) => {
                    ExitCode::from(5)
                }
                CliError::Denyx(DenyxError::Other(_)) => ExitCode::from(5),
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Denyx(#[from] DenyxError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

fn dispatch() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => run(args),
        Command::Init(args) => init_cmd(args),
        Command::Policy(p) => match p.command {
            PolicyCommand::Validate(a) => policy_validate(a),
            PolicyCommand::Show(a) => policy_show(a),
        },
        Command::Audit(a) => match a.command {
            AuditCommand::Verify(args) => audit_verify(args),
        },
        Command::HostConfig(args) => host_config_cmd(args),
        Command::Doctor(args) => {
            let code = doctor::run(args);
            std::process::exit(code);
        }
        Command::Hook(args) => hook::run_and_exit(args),
        Command::HookDaemon(cli) => {
            let code = hook_daemon::run(cli);
            std::process::exit(code);
        }
    }
}

fn host_config_cmd(args: HostConfigArgs) -> Result<(), CliError> {
    if args.platform == PlatformArg::Wsl && args.wsl_distro.is_none() {
        return Err(CliError::Other(
            "--platform wsl requires --wsl-distro <distro-name>".to_string(),
        ));
    }

    let policy = Policy::load(&args.policy)
        .map_err(|e| CliError::Other(format!("load policy {:?}: {e}", args.policy)))?;

    let opts = Opts {
        platform: args.platform.as_platform(),
        denyx_mcp_binary: args.denyx_mcp_binary,
        policy_path: args.policy.clone(),
        policy_url: args.policy_url.clone(),
        audit_log_path: args.audit_log,
        audit_url: args.audit_url.clone(),
        lima_vm: args.lima_vm,
        wsl_distro: args.wsl_distro,
        sandbox: args.sandbox.as_sandbox(),
        windows: args.windows,
        strict_mcp: args.strict_mcp,
    };
    let existing_mode = args.existing.as_existing();

    if opts.policy_url.is_some() {
        eprintln!(
            "denyx host-config: team mode — generated MCP entry uses \
             --policy-url; local --policy {:?} is only used to derive \
             the OS-sandbox stanza (re-run after policy edits to refresh).",
            args.policy
        );
        eprintln!(
            "  Distribute DENYX_AUTH_TOKEN via direnv / your secrets tool. \
             See docs/11-denyx-for-teams.md."
        );
    }
    if opts.audit_url.is_some() {
        eprintln!(
            "denyx host-config: team mode — generated MCP entry uses \
             --audit-url; the local audit log under .denyx/ will not be \
             written (events POST to the URL instead)."
        );
    }

    // Resolve `--host auto` to the actually-detected list. Done lazily
    // so the standard `--host claude,opencode` path doesn't pay for it.
    let hosts: Vec<Host> = if args.host.was_auto {
        let detected = detect_hosts(&args.output_dir);
        if detected.is_empty() {
            eprintln!(
                "denyx host-config: --host=auto found no signals; \
                 defaulting to claude,opencode. Pass --host explicitly \
                 to override."
            );
            vec![Host::Claude, Host::Opencode]
        } else {
            eprintln!(
                "denyx host-config: detected host(s): {}",
                detected
                    .iter()
                    .map(host_label)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            detected
        }
    } else {
        args.host.hosts.clone()
    };

    if args.dry_run {
        emit_dry_run(&policy, &opts, existing_mode, args.no_mcp, &hosts);
        return Ok(());
    }

    write_audit_dir(&args.output_dir)?;

    for host in &hosts {
        match host {
            Host::Claude => {
                write_claude(&args.output_dir, &policy, &opts, existing_mode, args.no_mcp)?
            }
            Host::Opencode => {
                write_opencode(&args.output_dir, &policy, &opts, existing_mode, args.no_mcp)?
            }
            Host::Cursor => write_cursor(&args.output_dir, &opts, existing_mode, args.no_mcp)?,
            Host::Copilot => write_copilot(&args.output_dir, &opts, existing_mode, args.no_mcp)?,
            Host::Continue => {
                write_continue(&args.output_dir, &policy, &opts, existing_mode, args.no_mcp)?
            }
            Host::Cline => {
                if args.no_mcp {
                    eprintln!(
                        "denyx host-config: --no-mcp + --host cline: \
                         nothing to write (Cline has no project-local \
                         lockdown layer Denyx can target)."
                    );
                } else {
                    eprintln!("\n{}", host_config::cline_instructions(&opts));
                }
            }
        }
    }

    eprintln!("denyx host-config: done.");
    Ok(())
}

/// Auto-detect which hosts are likely active. Order: env-var signals
/// (most reliable when this CLI is invoked from inside an agent's
/// shell), then cwd file signals (useful when run from a plain
/// terminal in a project that already has host configs).
fn detect_hosts(cwd: &Path) -> Vec<Host> {
    let mut detected: std::collections::BTreeSet<Host> = std::collections::BTreeSet::new();

    // Env-var signals.
    if std::env::var_os("CLAUDECODE").is_some()
        || std::env::var_os("CLAUDE_CODE_ENTRYPOINT").is_some()
    {
        detected.insert(Host::Claude);
    }
    if std::env::var_os("OPENCODE").is_some() || std::env::var_os("OPENCODE_BIN").is_some() {
        detected.insert(Host::Opencode);
    }
    if let Ok(term) = std::env::var("TERM_PROGRAM") {
        match term.as_str() {
            "cursor" | "Cursor" => {
                detected.insert(Host::Cursor);
            }
            "vscode" | "VSCode" => {
                // Plain VSCode terminal — we can't tell which AI extension
                // is active, but Copilot agent mode is the most common.
                detected.insert(Host::Copilot);
            }
            _ => {}
        }
    }
    if std::env::var_os("CURSOR_TRACE_ID").is_some() {
        detected.insert(Host::Cursor);
    }

    // File signals from cwd (cumulative — a project may have multiple).
    if cwd.join(".mcp.json").exists() || cwd.join(".claude").join("settings.json").exists() {
        detected.insert(Host::Claude);
    }
    if cwd.join("opencode.json").exists() {
        detected.insert(Host::Opencode);
    }
    if cwd.join(".cursor").join("mcp.json").exists() {
        detected.insert(Host::Cursor);
    }
    if cwd.join(".vscode").join("settings.json").exists() {
        detected.insert(Host::Copilot);
    }
    if cwd.join(".continue").join("config.json").exists() {
        detected.insert(Host::Continue);
    }

    detected.into_iter().collect()
}

fn host_label(h: &Host) -> &'static str {
    match h {
        Host::Claude => "claude",
        Host::Opencode => "opencode",
        Host::Cursor => "cursor",
        Host::Copilot => "copilot",
        Host::Continue => "continue",
        Host::Cline => "cline",
    }
}

fn write_audit_dir(dir: &Path) -> Result<(), CliError> {
    let (created, gi_updated) =
        prepare_audit_dir(dir).map_err(|e| CliError::Other(format!("prepare audit dir: {e}")))?;
    if created {
        eprintln!("  + created {}/.denyx/", dir.display());
    }
    if gi_updated {
        eprintln!("  + added .denyx/ to {}/.gitignore", dir.display());
    }
    Ok(())
}

fn write_claude(
    dir: &Path,
    policy: &Policy,
    opts: &Opts,
    existing: Existing,
    no_mcp: bool,
) -> Result<(), CliError> {
    let settings_path = dir.join(".claude").join("settings.json");

    if !no_mcp {
        let mcp_path = dir.join(".mcp.json");
        let mcp_value = claude_mcp(opts);
        let final_mcp = match (existing, read_json_if_exists(&mcp_path)?) {
            (Existing::Replace, _) | (_, None) => mcp_value,
            (Existing::Merge, Some(existing_val)) => {
                if opts.strict_mcp {
                    match host_config::merge_claude_mcp_strict(existing_val, mcp_value) {
                        Ok(v) => v,
                        Err(violation) => {
                            return Err(CliError::Other(format!(
                                "{}\n  (existing file: {}, --existing replace would overwrite it)",
                                violation,
                                mcp_path.display(),
                            )));
                        }
                    }
                } else {
                    merge_claude_mcp(existing_val, mcp_value)
                }
            }
        };
        write_json(&mcp_path, &final_mcp)?;
        eprintln!("  + wrote {}", mcp_path.display());
    }

    let settings_value = claude_settings(policy, opts);
    let final_settings = match (existing, read_json_if_exists(&settings_path)?) {
        (Existing::Replace, _) | (_, None) => settings_value,
        (Existing::Merge, Some(existing_val)) => {
            merge_claude_settings(existing_val, settings_value)
        }
    };
    write_json(&settings_path, &final_settings)?;
    eprintln!("  + wrote {}", settings_path.display());
    Ok(())
}

fn write_opencode(
    dir: &Path,
    policy: &Policy,
    opts: &Opts,
    existing: Existing,
    no_mcp: bool,
) -> Result<(), CliError> {
    let path = dir.join("opencode.json");
    let mut value = opencode_config(policy, opts);
    if no_mcp {
        // Drop the mcp.denyx entry; keep the tools and permission blocks.
        if let Some(obj) = value.as_object_mut() {
            obj.remove("mcp");
        }
    }
    let final_value = match (existing, read_json_if_exists(&path)?) {
        (Existing::Replace, _) | (_, None) => value,
        (Existing::Merge, Some(existing_val)) => merge_opencode(existing_val, value),
    };
    write_json(&path, &final_value)?;
    eprintln!("  + wrote {}", path.display());
    Ok(())
}

fn write_cursor(dir: &Path, opts: &Opts, existing: Existing, no_mcp: bool) -> Result<(), CliError> {
    if no_mcp {
        // Cursor's only Denyx-relevant file is the MCP entry; with
        // --no-mcp there's nothing to do.
        eprintln!("  - skipping cursor (--no-mcp; nothing else to write)");
        return Ok(());
    }
    let path = dir.join(".cursor").join("mcp.json");
    let value = host_config::cursor_mcp(opts);
    let final_value = match (existing, read_json_if_exists(&path)?) {
        (Existing::Replace, _) | (_, None) => value,
        (Existing::Merge, Some(existing_val)) => {
            if opts.strict_mcp {
                match host_config::merge_claude_mcp_strict(existing_val, value) {
                    Ok(v) => v,
                    Err(violation) => {
                        return Err(CliError::Other(format!(
                            "{}\n  (existing file: {}, --existing replace would overwrite it)",
                            violation,
                            path.display(),
                        )));
                    }
                }
            } else {
                host_config::merge_cursor_mcp(existing_val, value)
            }
        }
    };
    write_json(&path, &final_value)?;
    eprintln!("  + wrote {} (Cursor)", path.display());
    eprintln!(
        "    Cursor's built-in tool toggles are UI-only; lockdown of \
         Edit / Read / Bash equivalents is not project-local."
    );
    Ok(())
}

fn write_copilot(
    dir: &Path,
    opts: &Opts,
    existing: Existing,
    no_mcp: bool,
) -> Result<(), CliError> {
    if no_mcp {
        eprintln!("  - skipping copilot (--no-mcp; nothing else to write)");
        return Ok(());
    }
    let path = dir.join(".vscode").join("settings.json");
    let value = host_config::copilot_workspace_settings(opts);
    let final_value = match (existing, read_json_if_exists(&path)?) {
        (Existing::Replace, _) | (_, None) => value,
        (Existing::Merge, Some(existing_val)) => {
            host_config::merge_copilot_workspace(existing_val, value)
        }
    };
    write_json(&path, &final_value)?;
    eprintln!(
        "  + wrote {} (VSCode + GitHub Copilot agent mode)",
        path.display()
    );
    eprintln!(
        "    Copilot has no project-local deny list; tool approval \
         happens per-call at runtime. The Denyx gate still applies to \
         every MCP-routed call."
    );
    Ok(())
}

fn write_continue(
    dir: &Path,
    policy: &Policy,
    opts: &Opts,
    existing: Existing,
    no_mcp: bool,
) -> Result<(), CliError> {
    let path = dir.join(".continue").join("config.json");
    let mut value = host_config::continue_config(policy, opts);
    if no_mcp {
        if let Some(obj) = value.as_object_mut() {
            obj.remove("mcpServers");
        }
    }
    let final_value = match (existing, read_json_if_exists(&path)?) {
        (Existing::Replace, _) | (_, None) => value,
        (Existing::Merge, Some(existing_val)) => {
            host_config::merge_continue_config(existing_val, value)
        }
    };
    write_json(&path, &final_value)?;
    eprintln!("  + wrote {} (Continue)", path.display());
    Ok(())
}

fn read_json_if_exists(path: &Path) -> Result<Option<serde_json::Value>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(path)?;
    if body.trim().is_empty() {
        return Ok(None);
    }
    let v = serde_json::from_str(&body)
        .map_err(|e| CliError::Other(format!("parse {path:?} as JSON: {e}")))?;
    Ok(Some(v))
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut body = serde_json::to_string_pretty(value)
        .map_err(|e| CliError::Other(format!("serialize {path:?}: {e}")))?;
    body.push('\n');
    std::fs::write(path, body)?;
    Ok(())
}

fn emit_dry_run(policy: &Policy, opts: &Opts, _existing: Existing, no_mcp: bool, hosts: &[Host]) {
    for host in hosts {
        match host {
            Host::Claude => {
                if !no_mcp {
                    println!("// .mcp.json");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&claude_mcp(opts)).expect("serialize")
                    );
                }
                println!("// .claude/settings.json");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&claude_settings(policy, opts))
                        .expect("serialize")
                );
            }
            Host::Opencode => {
                let mut oc = opencode_config(policy, opts);
                if no_mcp {
                    if let Some(obj) = oc.as_object_mut() {
                        obj.remove("mcp");
                    }
                }
                println!("// opencode.json");
                println!("{}", serde_json::to_string_pretty(&oc).expect("serialize"));
            }
            Host::Cursor => {
                if !no_mcp {
                    println!("// .cursor/mcp.json");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&host_config::cursor_mcp(opts))
                            .expect("serialize")
                    );
                }
            }
            Host::Copilot => {
                if !no_mcp {
                    println!("// .vscode/settings.json");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&host_config::copilot_workspace_settings(
                            opts
                        ))
                        .expect("serialize")
                    );
                }
            }
            Host::Continue => {
                let mut c = host_config::continue_config(policy, opts);
                if no_mcp {
                    if let Some(obj) = c.as_object_mut() {
                        obj.remove("mcpServers");
                    }
                }
                println!("// .continue/config.json");
                println!("{}", serde_json::to_string_pretty(&c).expect("serialize"));
            }
            Host::Cline => {
                println!("// Cline (paste into the extension UI):");
                println!("{}", host_config::cline_instructions(opts));
            }
        }
    }
}

fn audit_verify(args: AuditTargetArgs) -> Result<(), CliError> {
    let report = denyx_host::verify_chain(&args.log).map_err(CliError::Io)?;
    if report.ok() {
        if let Some(min_seq) = args.min_seq {
            if report.last_seq < min_seq {
                return Err(CliError::Other(format!(
                    "audit log {:?} chain is internally valid but its last seq ({}) is \
                     BELOW the expected minimum ({min_seq}) — this is consistent with the \
                     tail of the log having been truncated (the most recent entries \
                     deleted) since the minimum was last recorded. A valid chain alone \
                     cannot rule this out; --min-seq exists specifically to catch it \
                     when paired with an externally-remembered count.",
                    args.log, report.last_seq
                )));
            }
        }
        println!(
            "OK: {} entries, chain valid (last seq = {}).",
            report.total_lines, report.last_seq
        );
        return Ok(());
    }
    eprintln!(
        "audit: chain BROKEN — {} failure(s) across {} entries",
        report.failures.len(),
        report.total_lines
    );
    for f in &report.failures {
        let seq = f
            .seq
            .map(|s| format!("seq={s}"))
            .unwrap_or_else(|| "seq=?".to_string());
        eprintln!("  line {} ({}): {}", f.line_number, seq, f.reason);
    }
    Err(CliError::Other(format!(
        "audit log {:?} failed verification ({} failures)",
        args.log,
        report.failures.len()
    )))
}

fn policy_validate(args: PolicyTargetArgs) -> Result<(), CliError> {
    let policy = Policy::load(&args.policy)
        .map_err(|e| CliError::Other(format!("validation failed: {e}")))?;
    let n = policy.effective_functions().len();
    println!(
        "OK: {} parses, resolves, passes self-writable guard. {n} capability(ies) enabled.",
        args.policy.display()
    );
    Ok(())
}

fn policy_show(args: PolicyTargetArgs) -> Result<(), CliError> {
    let policy = Policy::load(&args.policy)
        .map_err(|e| CliError::Other(format!("load policy {:?}: {e}", args.policy)))?;
    let file = policy.file_snapshot();

    println!("# policy: {}", args.policy.display());
    if let Some(name) = &file.name {
        println!("# name:   {name}");
    }
    if let Some(desc) = &file.description {
        println!("# desc:   {desc}");
    }
    if let Some(parent) = &file.inherits {
        println!("# inherits: {parent}");
    }
    println!();

    let effective = policy.effective_functions();
    println!("[capabilities]   (derived from populated resource sections)");
    if effective.is_empty() {
        println!("  (none — every effecting call will be denied)");
    } else {
        for cap in &effective {
            println!("  - {cap}");
        }
    }
    println!();

    print_section_list("[filesystem].read_allow", &file.filesystem.read_allow);
    print_section_list(
        "[filesystem].local_only_read",
        &file.filesystem.local_only_read,
    );
    print_section_list("[filesystem].write_allow", &file.filesystem.write_allow);
    print_section_list("[filesystem].delete_allow", &file.filesystem.delete_allow);
    print_section_list("[filesystem].deny", &file.filesystem.deny);

    print_section_list("[network].http_get_allow", &file.network.http_get_allow);
    print_section_list("[network].http_post_allow", &file.network.http_post_allow);
    print_section_list("[network].http_put_allow", &file.network.http_put_allow);
    print_section_list("[network].http_patch_allow", &file.network.http_patch_allow);
    print_section_list(
        "[network].http_delete_allow",
        &file.network.http_delete_allow,
    );
    print_section_list("[network].local_only_hosts", &file.network.local_only_hosts);
    print_section_list("[network].deny_hosts", &file.network.deny_hosts);
    print_section_list("[network].deny_ips", &file.network.deny_ips);

    print_section_list("[environment].allow_vars", &file.environment.allow_vars);
    print_section_list(
        "[environment].local_only_vars",
        &file.environment.local_only_vars,
    );
    print_section_list("[environment].deny_vars", &file.environment.deny_vars);

    print_section_list(
        "[subprocess].allow_commands",
        &file.subprocess.allow_commands,
    );
    print_section_list(
        "[subprocess].local_only_commands",
        &file.subprocess.local_only_commands,
    );
    print_section_list("[subprocess].deny_commands", &file.subprocess.deny_commands);
    if !file.subprocess.deny_args.is_empty() {
        println!("[subprocess.deny_args]");
        for (cmd, patterns) in &file.subprocess.deny_args {
            println!("  - {cmd}: {patterns:?}");
        }
        println!();
    }

    if file.runtime.max_seconds.is_some() || file.runtime.max_callstack_size.is_some() {
        println!("[runtime]");
        if let Some(s) = file.runtime.max_seconds {
            println!("  - max_seconds: {s}");
        }
        if let Some(n) = file.runtime.max_callstack_size {
            println!("  - max_callstack_size: {n}");
        }
        println!();
    }

    if !file.tools.is_empty() {
        println!("[tools]");
        for (name, record) in &file.tools {
            println!("  - {name}: {:?}", record.capabilities);
            if let Some(url) = &record.backend_url {
                println!("      → {} {url}", record.method());
            }
            if let Some(d) = &record.description {
                println!("      ({d})");
            }
        }
        println!();
    }

    if !file.requires_approval.is_empty() {
        println!("[requires_approval]");
        for cap in &file.requires_approval {
            println!("  - {cap}");
        }
        println!();
    }

    Ok(())
}

fn print_section_list(label: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    println!("{label}");
    for item in items {
        println!("  - {item}");
    }
    println!();
}

fn init_cmd(args: InitArgs) -> Result<(), CliError> {
    let body = init::generate(args.lang, args.permissive);
    if args.output == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(body.as_bytes())?;
        return Ok(());
    }
    let path = PathBuf::from(&args.output);
    if path.exists() && !args.force {
        return Err(CliError::Other(format!(
            "{path:?} already exists; pass --force to overwrite"
        )));
    }
    std::fs::write(&path, &body)?;
    let mode_label = if args.permissive {
        "permissive"
    } else {
        "minimal"
    };
    eprintln!(
        "denyx: wrote {path} ({lang}, {mode_label}). Review the file, then run with --policy {path}.",
        path = path.display(),
        lang = args.lang.name(),
    );
    if !args.permissive {
        eprintln!(
            "       Minimal policy excludes `/tmp/**` from write_allow. \
             Pass --permissive if your workflow needs scratch writes there."
        );
    }
    Ok(())
}

fn run(args: RunArgs) -> Result<(), CliError> {
    let policy = match args.policy.as_deref() {
        Some(path) => {
            Policy::load(path).map_err(|e| CliError::Other(format!("load policy {path:?}: {e}")))?
        }
        None => {
            print_no_policy_banner();
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            Policy::secure_defaults_at(cwd)
                .map_err(|e| CliError::Other(format!("load secure-defaults baseline: {e}")))?
        }
    };
    let script = std::fs::read_to_string(&args.script)?;
    let task_id = args.task_id.unwrap_or_else(|| {
        args.script
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("script.star")
            .to_string()
    });

    let audit: Arc<dyn AuditSink> = match &args.audit_log {
        Some(path) => {
            // Refuse to start if the audit log path is reachable to
            // the agent — write/delete would let it fabricate or
            // erase history; read would let it compute valid
            // hash-chain prev_hash values for forged appends. The
            // self-writable guard's audit-log sibling.
            let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            policy.guard_audit_log(&canon).map_err(|e| {
                CliError::Other(format!("audit-log path is reachable to the agent: {e}"))
            })?;
            Arc::new(JsonlAuditSink::file(path)?)
        }
        None => Arc::new(JsonlAuditSink::stderr()),
    };
    let confirm: Arc<dyn ConfirmHook> = if args.yes {
        Arc::new(AllowAllConfirm)
    } else if std::io::stderr().is_terminal() && std::io::stdin().is_terminal() {
        Arc::new(TtyConfirm)
    } else {
        Arc::new(DenyAllConfirm)
    };

    if args.use_wasm {
        eprintln!(
            "denyx: --use-wasm is a no-op as of v0.4.0; the wasm sandbox is the default. Pass --no-wasm to select the legacy in-process runner."
        );
    }
    let outcome = if args.no_wasm {
        let runner = Runner::new(policy)
            .with_audit(audit)
            .with_confirm_hook(confirm);
        runner.run(&task_id, &script, args.script.to_string_lossy().as_ref())?
    } else {
        let runner = WasmRunner::new(policy)
            .with_audit(audit)
            .with_confirm_hook(confirm);
        runner.run(&task_id, &script, args.script.to_string_lossy().as_ref())?
    };
    for line in &outcome.printed {
        println!("{line}");
    }
    Ok(())
}

/// Loud-and-safe banner shown when `denyx run` fires without `--policy`.
/// Stderr only so it doesn't pollute structured stdout output.
fn print_no_policy_banner() {
    eprintln!("denyx: no --policy provided; using built-in `secure-defaults` baseline.");
    eprintln!("       This baseline DENIES every fs / net / subprocess / env capability.");
    eprintln!("       Pure computation and print() still work; every effect will fail.");
    eprintln!("       To grant capabilities, generate a starter policy:");
    eprintln!();
    eprintln!("           denyx init --lang python   # or node, ruby, rust, go");
    eprintln!();
    eprintln!("       Then run with `--policy denyx.toml`. See examples/policies/ for templates.");
}

struct TtyConfirm;
impl ConfirmHook for TtyConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmDecision {
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "[denyx] confirm {} for task {}: {}",
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
