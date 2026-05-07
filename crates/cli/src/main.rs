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
    DenyxError, JsonlAuditSink, Runner,
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
}

#[derive(Parser, Debug)]
struct HostConfigArgs {
    /// Path to the policy TOML file. Used to derive sandbox
    /// `allowedDomains` / `allowWrite` from the policy.
    #[arg(long)]
    policy: PathBuf,

    /// Which host's configs to write.
    #[arg(long, default_value = "both")]
    host: HostArg,

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
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum HostArg {
    Claude,
    Opencode,
    Both,
}

impl FromStr for HostArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "claude" | "claude-code" | "claudecode" => Ok(Self::Claude),
            "opencode" => Ok(Self::Opencode),
            "both" => Ok(Self::Both),
            other => Err(format!(
                "unknown host {other:?}; expected one of: claude, opencode, both"
            )),
        }
    }
}

impl HostArg {
    fn as_host(self) -> Host {
        match self {
            Self::Claude => Host::Claude,
            Self::Opencode => Host::Opencode,
            Self::Both => Host::Both,
        }
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
        host: args.host.as_host(),
        platform: args.platform.as_platform(),
        denyx_mcp_binary: args.denyx_mcp_binary,
        policy_path: args.policy.clone(),
        audit_log_path: args.audit_log,
        lima_vm: args.lima_vm,
        wsl_distro: args.wsl_distro,
        sandbox: args.sandbox.as_sandbox(),
        windows: args.windows,
    };
    let existing_mode = args.existing.as_existing();

    if args.dry_run {
        emit_dry_run(&policy, &opts, existing_mode, args.no_mcp);
        return Ok(());
    }

    write_audit_dir(&args.output_dir)?;

    match opts.host {
        Host::Claude => write_claude(&args.output_dir, &policy, &opts, existing_mode, args.no_mcp)?,
        Host::Opencode => {
            write_opencode(&args.output_dir, &policy, &opts, existing_mode, args.no_mcp)?
        }
        Host::Both => {
            write_claude(&args.output_dir, &policy, &opts, existing_mode, args.no_mcp)?;
            write_opencode(&args.output_dir, &policy, &opts, existing_mode, args.no_mcp)?;
        }
    }

    eprintln!("denyx host-config: done.");
    Ok(())
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
            (Existing::Merge, Some(existing_val)) => merge_claude_mcp(existing_val, mcp_value),
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

fn emit_dry_run(policy: &Policy, opts: &Opts, _existing: Existing, no_mcp: bool) {
    if matches!(opts.host, Host::Claude | Host::Both) {
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
            serde_json::to_string_pretty(&claude_settings(policy, opts)).expect("serialize")
        );
    }
    if matches!(opts.host, Host::Opencode | Host::Both) {
        let mut oc = opencode_config(policy, opts);
        if no_mcp {
            if let Some(obj) = oc.as_object_mut() {
                obj.remove("mcp");
            }
        }
        println!("// opencode.json");
        println!("{}", serde_json::to_string_pretty(&oc).expect("serialize"));
    }
}

fn audit_verify(args: AuditTargetArgs) -> Result<(), CliError> {
    let report = denyx_host::verify_chain(&args.log).map_err(CliError::Io)?;
    if report.ok() {
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
    let body = init::generate(args.lang);
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
    eprintln!(
        "denyx: wrote {path} ({lang}). Review the file, then run with --policy {path}.",
        path = path.display(),
        lang = args.lang.name(),
    );
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

    let runner = Runner::new(policy)
        .with_audit(audit)
        .with_confirm_hook(confirm);

    let outcome = runner.run(&task_id, &script, args.script.to_string_lossy().as_ref())?;
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
