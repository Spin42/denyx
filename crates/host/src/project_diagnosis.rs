//! Read-only project diagnosis for `denyx-mcp doctor` and
//! `denyx-local-mcp doctor`.
//!
//! Walks a project root and reports on:
//!
//!   - presence + validity of `denyx.toml`
//!   - which host-config files exist (`.mcp.json`, `opencode.json`,
//!     `.cursor/mcp.json`, `.vscode/settings.json`,
//!     `.continue/config.json`)
//!   - what each host-config wires: are there `denyx-mcp` /
//!     `denyx-local-mcp` MCP server entries? what flags do they
//!     pass?
//!   - audit-dir setup (`.denyx/` exists, `.gitignore` excludes it)
//!
//! The module is **read-only**: it never modifies anything. Both
//! doctors take the resulting [`ProjectDiagnosis`] and render it as
//! `[OK]` / `[WARN]` / `[INFO]` / `[FAIL]` lines with fix
//! instructions, with each binary applying its own interpretation
//! (e.g., `denyx-local-mcp doctor` warns when only `denyx-mcp` is
//! wired because the local-executor bridge is being bypassed).

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Top-level diagnosis result.
#[derive(Debug, Clone)]
pub struct ProjectDiagnosis {
    /// Absolute path of the project root that was inspected.
    pub root: PathBuf,
    /// State of `<root>/denyx.toml`.
    pub policy: PolicyCheck,
    /// Host-config files found, in deterministic order
    /// (claude → opencode → cursor → copilot → continue).
    pub host_configs: Vec<HostConfigEntry>,
    /// State of `<root>/.denyx/`.
    pub audit_dir: AuditDirCheck,
    /// State of `<root>/.gitignore` w.r.t. the audit dir.
    pub gitignore: GitignoreCheck,
}

/// Whether the project's policy file is present + valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyCheck {
    /// `denyx.toml` exists and parses + passes the self-writable
    /// guard. The runtime would load it without complaint.
    Valid {
        path: PathBuf,
        name: Option<String>,
        capability_count: usize,
    },
    /// `denyx.toml` exists but is malformed or fails a load-time
    /// safety check.
    Invalid { path: PathBuf, reason: String },
    /// `denyx.toml` is absent. Not an error: the runtime falls back
    /// to `secure-defaults` (deny everything) when invoked without
    /// a `--policy` arg. Doctor reports this as INFO.
    Missing,
}

/// Whether `<root>/.denyx/` exists and looks usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditDirCheck {
    /// `.denyx/` exists and is a directory.
    Present { path: PathBuf },
    /// `.denyx/` does not exist. Not necessarily an error — Denyx
    /// can write the audit log to any path passed via `--audit-log`.
    Absent,
    /// `.denyx/` exists but is a file (operator's mistake).
    NotADirectory { path: PathBuf },
}

/// Whether `.gitignore` excludes the audit dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitignoreCheck {
    /// `.gitignore` exists and contains a `.denyx/` line.
    Excluded,
    /// `.gitignore` exists but no `.denyx/` line — audit logs
    /// might get committed by accident.
    NotExcluded,
    /// No `.gitignore` in the project root.
    Missing,
}

/// One host-config file we found and parsed.
#[derive(Debug, Clone)]
pub struct HostConfigEntry {
    pub path: PathBuf,
    pub host: HostName,
    pub denyx_servers: Vec<DetectedDenyxServer>,
    /// Whether the file's deny-list / lockdown layer is configured
    /// (host-specific check). `None` if the host doesn't have such
    /// a layer (Cursor / Copilot — UI-only deny).
    pub lockdown_state: LockdownState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostName {
    Claude,
    Opencode,
    Cursor,
    Copilot,
    Continue,
}

impl HostName {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Opencode => "opencode",
            Self::Cursor => "Cursor",
            Self::Copilot => "VSCode + Copilot",
            Self::Continue => "Continue",
        }
    }
}

/// State of the host's built-in-tool lockdown for this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockdownState {
    /// Built-in deny list is in place — Bash/Read/Edit/Write/etc.
    /// are denied so the model has to route through Denyx.
    Active,
    /// File exists but the deny list is missing or shorter than
    /// the canonical Denyx list.
    Partial { missing: Vec<String> },
    /// No deny-list mechanism on this host (Cursor / Copilot).
    NotApplicable,
    /// File exists but no deny list at all.
    Absent,
}

/// One MCP server entry we identified inside a host-config file.
#[derive(Debug, Clone)]
pub struct DetectedDenyxServer {
    /// Name of the entry in the host-config (e.g. "denyx",
    /// "local-executor").
    pub name: String,
    /// Which Denyx binary this entry invokes (after peeling Lima /
    /// WSL platform wrappers).
    pub flavor: DenyxFlavor,
    /// The literal `command` value (binary path or wrapper).
    pub command: String,
    /// The literal `args` array.
    pub args: Vec<String>,
    /// True if `command` is `limactl` or `wsl.exe` and we peeled
    /// it back to find the inner Denyx binary in `args`.
    pub via_wrapper: Option<PlatformWrapper>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformWrapper {
    Lima,
    Wsl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyxFlavor {
    /// `denyx-mcp`: standalone gate.
    DenyxMcp,
    /// `denyx-local-mcp`: local-executor bridge.
    DenyxLocalMcp,
    /// Some other command — possibly a custom in-house wrapper.
    /// The string is the original command for reporting.
    Other(String),
}

// ─────────────────────────── public API ───────────────────────────

/// Inspect the given project root and return a complete diagnosis.
/// Never panics on missing files; all conditions are reflected in
/// the returned struct.
pub fn diagnose(project_root: &Path) -> ProjectDiagnosis {
    let root = project_root.to_path_buf();
    ProjectDiagnosis {
        policy: check_policy(&root),
        host_configs: collect_host_configs(&root),
        audit_dir: check_audit_dir(&root),
        gitignore: check_gitignore(&root),
        root,
    }
}

// ───────────────────────────── policy ─────────────────────────────

fn check_policy(root: &Path) -> PolicyCheck {
    let path = root.join("denyx.toml");
    if !path.exists() {
        return PolicyCheck::Missing;
    }
    match denyx_policy::Policy::load(&path) {
        Ok(policy) => {
            let snap = policy.file_snapshot();
            PolicyCheck::Valid {
                path,
                name: snap.name.clone(),
                capability_count: policy.effective_functions().len(),
            }
        }
        Err(e) => PolicyCheck::Invalid {
            path,
            reason: e.to_string(),
        },
    }
}

// ──────────────────────────── audit dir ────────────────────────────

fn check_audit_dir(root: &Path) -> AuditDirCheck {
    let path = root.join(".denyx");
    if !path.exists() {
        return AuditDirCheck::Absent;
    }
    if path.is_dir() {
        AuditDirCheck::Present { path }
    } else {
        AuditDirCheck::NotADirectory { path }
    }
}

fn check_gitignore(root: &Path) -> GitignoreCheck {
    let path = root.join(".gitignore");
    let body = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return GitignoreCheck::Missing,
    };
    if body
        .lines()
        .any(|l| l.trim() == ".denyx/" || l.trim() == ".denyx" || l.trim() == "/.denyx/")
    {
        GitignoreCheck::Excluded
    } else {
        GitignoreCheck::NotExcluded
    }
}

// ─────────────────────────── host-configs ───────────────────────────

fn collect_host_configs(root: &Path) -> Vec<HostConfigEntry> {
    let mut out = Vec::new();
    if let Some(e) = parse_claude_mcp_json(root) {
        out.push(e);
    }
    if let Some(e) = parse_opencode_json(root) {
        out.push(e);
    }
    if let Some(e) = parse_cursor_mcp_json(root) {
        out.push(e);
    }
    if let Some(e) = parse_vscode_settings_json(root) {
        out.push(e);
    }
    if let Some(e) = parse_continue_config_json(root) {
        out.push(e);
    }
    out
}

fn read_json(path: &Path) -> Option<Value> {
    let body = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

fn parse_claude_mcp_json(root: &Path) -> Option<HostConfigEntry> {
    let path = root.join(".mcp.json");
    let v = read_json(&path)?;
    let denyx_servers = parse_mcp_servers_object(&v);
    let lockdown_state = check_claude_lockdown(root);
    Some(HostConfigEntry {
        path,
        host: HostName::Claude,
        denyx_servers,
        lockdown_state,
    })
}

fn check_claude_lockdown(root: &Path) -> LockdownState {
    let settings_path = root.join(".claude").join("settings.json");
    let v = match read_json(&settings_path) {
        Some(v) => v,
        None => return LockdownState::Absent,
    };
    let deny = v
        .pointer("/permissions/deny")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let deny_set: std::collections::BTreeSet<&str> =
        deny.iter().filter_map(|v| v.as_str()).collect();
    let canonical = [
        "Bash",
        "Edit",
        "Write",
        "Read",
        "Glob",
        "Grep",
        "WebFetch",
        "WebSearch",
    ];
    let missing: Vec<String> = canonical
        .iter()
        .filter(|t| !deny_set.contains(*t))
        .map(|s| (*s).to_string())
        .collect();
    if missing.is_empty() {
        LockdownState::Active
    } else if missing.len() == canonical.len() {
        LockdownState::Absent
    } else {
        LockdownState::Partial { missing }
    }
}

fn parse_opencode_json(root: &Path) -> Option<HostConfigEntry> {
    let path = root.join("opencode.json");
    let v = read_json(&path)?;
    let denyx_servers = parse_opencode_mcp(&v);
    let lockdown_state = check_opencode_lockdown(&v);
    Some(HostConfigEntry {
        path,
        host: HostName::Opencode,
        denyx_servers,
        lockdown_state,
    })
}

fn check_opencode_lockdown(v: &Value) -> LockdownState {
    let tools = match v.get("tools").and_then(|t| t.as_object()) {
        Some(t) => t,
        None => return LockdownState::Absent,
    };
    let canonical = [
        "bash",
        "read",
        "write",
        "edit",
        "glob",
        "grep",
        "webfetch",
        "websearch",
    ];
    let missing: Vec<String> = canonical
        .iter()
        .filter(|t| tools.get(**t).and_then(|v| v.as_bool()) != Some(false))
        .map(|s| (*s).to_string())
        .collect();
    if missing.is_empty() {
        LockdownState::Active
    } else if missing.len() == canonical.len() {
        LockdownState::Absent
    } else {
        LockdownState::Partial { missing }
    }
}

fn parse_opencode_mcp(v: &Value) -> Vec<DetectedDenyxServer> {
    let mcp = match v.get("mcp").and_then(|m| m.as_object()) {
        Some(m) => m,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (name, entry) in mcp {
        let cmd_arr = match entry.get("command").and_then(|c| c.as_array()) {
            Some(a) => a,
            None => continue,
        };
        let mut iter = cmd_arr.iter().filter_map(|v| v.as_str().map(String::from));
        let bin = match iter.next() {
            Some(b) => b,
            None => continue,
        };
        let rest: Vec<String> = iter.collect();
        let (flavor, via_wrapper, command, args) = classify_command(bin, rest);
        out.push(DetectedDenyxServer {
            name: name.clone(),
            flavor,
            via_wrapper,
            command,
            args,
        });
    }
    out
}

fn parse_cursor_mcp_json(root: &Path) -> Option<HostConfigEntry> {
    let path = root.join(".cursor").join("mcp.json");
    let v = read_json(&path)?;
    let denyx_servers = parse_mcp_servers_object(&v);
    Some(HostConfigEntry {
        path,
        host: HostName::Cursor,
        denyx_servers,
        lockdown_state: LockdownState::NotApplicable,
    })
}

fn parse_vscode_settings_json(root: &Path) -> Option<HostConfigEntry> {
    let path = root.join(".vscode").join("settings.json");
    let v = read_json(&path)?;
    let mut denyx_servers = Vec::new();
    if let Some(servers) = v.get("chat.mcp.servers").and_then(|s| s.as_object()) {
        for (name, entry) in servers {
            if let Some(s) = parse_command_args_entry(name, entry) {
                denyx_servers.push(s);
            }
        }
    }
    Some(HostConfigEntry {
        path,
        host: HostName::Copilot,
        denyx_servers,
        lockdown_state: LockdownState::NotApplicable,
    })
}

fn parse_continue_config_json(root: &Path) -> Option<HostConfigEntry> {
    let path = root.join(".continue").join("config.json");
    let v = read_json(&path)?;
    let mut denyx_servers = Vec::new();
    if let Some(arr) = v.get("mcpServers").and_then(|s| s.as_array()) {
        for entry in arr {
            let name = entry
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("(unnamed)")
                .to_string();
            if let Some(s) = parse_command_args_entry(&name, entry) {
                denyx_servers.push(s);
            }
        }
    }
    // Continue's tools array is allowlist-style: any built-in not
    // listed is unavailable. Empty tools = full lockdown.
    let lockdown_state = match v.get("tools") {
        Some(Value::Array(a)) if a.is_empty() => LockdownState::Active,
        Some(Value::Array(a)) => LockdownState::Partial {
            missing: a
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        },
        _ => LockdownState::Absent,
    };
    Some(HostConfigEntry {
        path,
        host: HostName::Continue,
        denyx_servers,
        lockdown_state,
    })
}

/// Parse the standard Claude/Cursor `{ "mcpServers": { name: { command, args } } }` shape.
fn parse_mcp_servers_object(v: &Value) -> Vec<DetectedDenyxServer> {
    let servers = match v.get("mcpServers").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (name, entry) in servers {
        if let Some(s) = parse_command_args_entry(name, entry) {
            out.push(s);
        }
    }
    out
}

/// Parse one `{ command: "...", args: [...] }` entry.
fn parse_command_args_entry(name: &str, entry: &Value) -> Option<DetectedDenyxServer> {
    let cmd = entry.get("command").and_then(|c| c.as_str())?.to_string();
    let args: Vec<String> = entry
        .get("args")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let (flavor, via_wrapper, command, args) = classify_command(cmd, args);
    Some(DetectedDenyxServer {
        name: name.to_string(),
        flavor,
        via_wrapper,
        command,
        args,
    })
}

/// Given a (command, args) pair, identify which Denyx binary it
/// effectively invokes — peeling Lima / WSL platform wrappers as
/// needed. Returns (flavor, wrapper, displayed_command, displayed_args).
fn classify_command(
    cmd: String,
    args: Vec<String>,
) -> (DenyxFlavor, Option<PlatformWrapper>, String, Vec<String>) {
    // Peel Lima: `limactl shell <vm> <bin> <bin-args...>`
    if basename(&cmd) == "limactl"
        && args.first().map(|s| s.as_str()) == Some("shell")
        && args.len() >= 3
    {
        let inner_bin = args[2].clone();
        let inner_args = args[3..].to_vec();
        let flavor = classify_flavor(&inner_bin);
        return (flavor, Some(PlatformWrapper::Lima), inner_bin, inner_args);
    }
    // Peel WSL: `wsl.exe -d <distro> -e <bin> <bin-args...>`
    let cmd_base = basename(&cmd);
    if cmd_base == "wsl.exe" || cmd_base == "wsl" {
        // Find `-e <bin>` in args.
        if let Some(idx) = args.iter().position(|a| a == "-e") {
            if let Some(inner_bin) = args.get(idx + 1) {
                let inner_args = args[idx + 2..].to_vec();
                let flavor = classify_flavor(inner_bin);
                return (
                    flavor,
                    Some(PlatformWrapper::Wsl),
                    inner_bin.clone(),
                    inner_args,
                );
            }
        }
    }
    let flavor = classify_flavor(&cmd);
    (flavor, None, cmd, args)
}

fn classify_flavor(bin: &str) -> DenyxFlavor {
    let bn = basename(bin).trim_end_matches(".exe").to_string();
    match bn.as_str() {
        "denyx-mcp" => DenyxFlavor::DenyxMcp,
        "denyx-local-mcp" => DenyxFlavor::DenyxLocalMcp,
        _ => DenyxFlavor::Other(bin.to_string()),
    }
}

fn basename(path: &str) -> &str {
    // Cross-platform: handles forward and back slashes.
    let after_fwd = path.rsplit('/').next().unwrap_or(path);
    after_fwd.rsplit('\\').next().unwrap_or(after_fwd)
}

// ─────────────────────── convenience methods ───────────────────────

impl ProjectDiagnosis {
    /// Iterator over every detected Denyx server entry across all
    /// host-config files. Useful for "is my project wired to use
    /// the local executor?" — a single yes/no answer.
    pub fn all_denyx_servers(
        &self,
    ) -> impl Iterator<Item = (&HostConfigEntry, &DetectedDenyxServer)> {
        self.host_configs
            .iter()
            .flat_map(|hc| hc.denyx_servers.iter().map(move |s| (hc, s)))
    }

    /// True if any host-config wires `denyx-mcp` directly.
    pub fn has_denyx_mcp(&self) -> bool {
        self.all_denyx_servers()
            .any(|(_, s)| s.flavor == DenyxFlavor::DenyxMcp)
    }

    /// True if any host-config wires `denyx-local-mcp`.
    pub fn has_denyx_local_mcp(&self) -> bool {
        self.all_denyx_servers()
            .any(|(_, s)| s.flavor == DenyxFlavor::DenyxLocalMcp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_tempdir(label: &str) -> PathBuf {
        // Use std::env::temp_dir under the test name. Tests don't
        // load policies (they write their own minimal toml that
        // passes the self-writable guard).
        let base = std::env::temp_dir().join(format!(
            "denyx_project_diag_{label}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn classify_flavor_recognises_denyx_mcp_and_local() {
        assert_eq!(classify_flavor("denyx-mcp"), DenyxFlavor::DenyxMcp);
        assert_eq!(
            classify_flavor("denyx-local-mcp"),
            DenyxFlavor::DenyxLocalMcp
        );
        assert_eq!(
            classify_flavor("/usr/local/bin/denyx-mcp"),
            DenyxFlavor::DenyxMcp
        );
        assert_eq!(
            classify_flavor("C:\\bin\\denyx-mcp.exe"),
            DenyxFlavor::DenyxMcp
        );
        assert_eq!(
            classify_flavor("denyx-local-mcp.exe"),
            DenyxFlavor::DenyxLocalMcp
        );
        assert_eq!(
            classify_flavor("/some/path/bash"),
            DenyxFlavor::Other("/some/path/bash".to_string())
        );
    }

    #[test]
    fn classify_command_peels_lima_wrapper() {
        let (flavor, wrap, cmd, args) = classify_command(
            "limactl".to_string(),
            vec![
                "shell".into(),
                "denyx".into(),
                "denyx-mcp".into(),
                "--policy".into(),
                "./denyx.toml".into(),
            ],
        );
        assert_eq!(flavor, DenyxFlavor::DenyxMcp);
        assert_eq!(wrap, Some(PlatformWrapper::Lima));
        assert_eq!(cmd, "denyx-mcp");
        assert_eq!(args, vec!["--policy".to_string(), "./denyx.toml".into()]);
    }

    #[test]
    fn classify_command_peels_wsl_wrapper() {
        let (flavor, wrap, cmd, args) = classify_command(
            "wsl.exe".to_string(),
            vec![
                "-d".into(),
                "Ubuntu-24.04".into(),
                "-e".into(),
                "denyx-local-mcp".into(),
                "serve".into(),
                "--policy".into(),
                "./denyx.toml".into(),
            ],
        );
        assert_eq!(flavor, DenyxFlavor::DenyxLocalMcp);
        assert_eq!(wrap, Some(PlatformWrapper::Wsl));
        assert_eq!(cmd, "denyx-local-mcp");
        assert_eq!(
            args,
            vec![
                "serve".to_string(),
                "--policy".into(),
                "./denyx.toml".into(),
            ]
        );
    }

    #[test]
    fn classify_command_passes_through_non_wrappers() {
        let (flavor, wrap, cmd, args) = classify_command(
            "/usr/bin/python3".to_string(),
            vec!["/path/to/local_mcp.py".into()],
        );
        assert!(matches!(flavor, DenyxFlavor::Other(_)));
        assert!(wrap.is_none());
        assert_eq!(cmd, "/usr/bin/python3");
        assert_eq!(args, vec!["/path/to/local_mcp.py".to_string()]);
    }

    #[test]
    fn diagnose_no_files_returns_all_missing() {
        let tmp = unique_tempdir("nofiles");
        let d = diagnose(&tmp);
        assert_eq!(d.policy, PolicyCheck::Missing);
        assert!(d.host_configs.is_empty());
        assert_eq!(d.audit_dir, AuditDirCheck::Absent);
        assert_eq!(d.gitignore, GitignoreCheck::Missing);
        assert!(!d.has_denyx_mcp());
        assert!(!d.has_denyx_local_mcp());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_finds_claude_mcp_json_with_denyx_mcp_entry() {
        let tmp = unique_tempdir("claude_mcp");
        std::fs::write(
            tmp.join(".mcp.json"),
            r#"{
              "mcpServers": {
                "denyx": {
                  "command": "denyx-mcp",
                  "args": ["--policy", "./denyx.toml"]
                }
              }
            }"#,
        )
        .unwrap();
        let d = diagnose(&tmp);
        assert_eq!(d.host_configs.len(), 1);
        let hc = &d.host_configs[0];
        assert_eq!(hc.host, HostName::Claude);
        assert_eq!(hc.denyx_servers.len(), 1);
        assert_eq!(hc.denyx_servers[0].name, "denyx");
        assert_eq!(hc.denyx_servers[0].flavor, DenyxFlavor::DenyxMcp);
        assert!(d.has_denyx_mcp());
        assert!(!d.has_denyx_local_mcp());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_finds_opencode_with_denyx_local_mcp_entry() {
        let tmp = unique_tempdir("opencode");
        std::fs::write(
            tmp.join("opencode.json"),
            r#"{
              "$schema": "https://opencode.ai/config.json",
              "tools": {"bash": false, "read": false, "write": false, "edit": false,
                        "glob": false, "grep": false, "webfetch": false, "websearch": false},
              "mcp": {
                "local-executor": {
                  "type": "local",
                  "command": ["denyx-local-mcp", "serve", "--policy", "./denyx.toml"],
                  "enabled": true
                }
              }
            }"#,
        )
        .unwrap();
        let d = diagnose(&tmp);
        assert_eq!(d.host_configs.len(), 1);
        let hc = &d.host_configs[0];
        assert_eq!(hc.host, HostName::Opencode);
        assert_eq!(hc.denyx_servers.len(), 1);
        assert_eq!(hc.denyx_servers[0].flavor, DenyxFlavor::DenyxLocalMcp);
        assert_eq!(hc.lockdown_state, LockdownState::Active);
        assert!(d.has_denyx_local_mcp());
        assert!(!d.has_denyx_mcp());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_partial_opencode_lockdown_lists_missing_tools() {
        let tmp = unique_tempdir("partial_oc");
        std::fs::write(
            tmp.join("opencode.json"),
            r#"{
              "tools": {"bash": false, "edit": false},
              "mcp": {}
            }"#,
        )
        .unwrap();
        let d = diagnose(&tmp);
        let hc = &d.host_configs[0];
        match &hc.lockdown_state {
            LockdownState::Partial { missing } => {
                assert!(missing.contains(&"read".to_string()));
                assert!(missing.contains(&"write".to_string()));
                assert!(missing.contains(&"webfetch".to_string()));
                assert!(!missing.contains(&"bash".to_string()));
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_finds_claude_settings_active_lockdown() {
        let tmp = unique_tempdir("claude_lock");
        std::fs::create_dir_all(tmp.join(".claude")).unwrap();
        std::fs::write(
            tmp.join(".claude").join("settings.json"),
            r#"{"permissions":{"deny":["Bash","Edit","Write","Read","Glob","Grep","WebFetch","WebSearch","Monitor","NotebookEdit"]}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join(".mcp.json"),
            r#"{"mcpServers":{"denyx":{"command":"denyx-mcp","args":[]}}}"#,
        )
        .unwrap();
        let d = diagnose(&tmp);
        let hc = &d.host_configs[0];
        assert_eq!(hc.lockdown_state, LockdownState::Active);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_finds_cursor_mcp_json() {
        let tmp = unique_tempdir("cursor");
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();
        std::fs::write(
            tmp.join(".cursor").join("mcp.json"),
            r#"{"mcpServers":{"denyx":{"command":"denyx-mcp","args":["--policy","./denyx.toml"]}}}"#,
        )
        .unwrap();
        let d = diagnose(&tmp);
        assert_eq!(d.host_configs.len(), 1);
        assert_eq!(d.host_configs[0].host, HostName::Cursor);
        assert_eq!(
            d.host_configs[0].lockdown_state,
            LockdownState::NotApplicable
        );
        assert!(d.has_denyx_mcp());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_finds_copilot_workspace_settings() {
        let tmp = unique_tempdir("copilot");
        std::fs::create_dir_all(tmp.join(".vscode")).unwrap();
        std::fs::write(
            tmp.join(".vscode").join("settings.json"),
            r#"{
              "editor.fontSize": 14,
              "chat.mcp.servers": {
                "denyx": {"command":"denyx-local-mcp","args":["serve","--policy","./denyx.toml"]}
              }
            }"#,
        )
        .unwrap();
        let d = diagnose(&tmp);
        assert_eq!(d.host_configs.len(), 1);
        assert_eq!(d.host_configs[0].host, HostName::Copilot);
        assert_eq!(
            d.host_configs[0].denyx_servers[0].flavor,
            DenyxFlavor::DenyxLocalMcp
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_finds_continue_with_array_mcp_servers() {
        let tmp = unique_tempdir("continue");
        std::fs::create_dir_all(tmp.join(".continue")).unwrap();
        std::fs::write(
            tmp.join(".continue").join("config.json"),
            r#"{
              "mcpServers": [
                {"name":"denyx","command":"denyx-mcp","args":["--policy","./denyx.toml"]}
              ],
              "tools": []
            }"#,
        )
        .unwrap();
        let d = diagnose(&tmp);
        assert_eq!(d.host_configs.len(), 1);
        assert_eq!(d.host_configs[0].host, HostName::Continue);
        assert_eq!(d.host_configs[0].denyx_servers.len(), 1);
        assert_eq!(
            d.host_configs[0].denyx_servers[0].flavor,
            DenyxFlavor::DenyxMcp
        );
        assert_eq!(d.host_configs[0].lockdown_state, LockdownState::Active);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn diagnose_handles_mixed_setup_with_both_flavors() {
        let tmp = unique_tempdir("mixed");
        // Claude wires denyx-mcp; opencode wires denyx-local-mcp.
        std::fs::write(
            tmp.join(".mcp.json"),
            r#"{"mcpServers":{"denyx":{"command":"denyx-mcp","args":[]}}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("opencode.json"),
            r#"{"mcp":{"x":{"command":["denyx-local-mcp","serve"]}}}"#,
        )
        .unwrap();
        let d = diagnose(&tmp);
        assert_eq!(d.host_configs.len(), 2);
        assert!(d.has_denyx_mcp());
        assert!(d.has_denyx_local_mcp());
    }

    #[test]
    fn diagnose_ignores_malformed_json_silently() {
        let tmp = unique_tempdir("malformed");
        std::fs::write(tmp.join(".mcp.json"), "this is not json {[").unwrap();
        let d = diagnose(&tmp);
        // Malformed file is just dropped from the host_configs list.
        assert_eq!(d.host_configs.len(), 0);
    }

    #[test]
    fn diagnose_audit_dir_present_when_dir_exists() {
        let tmp = unique_tempdir("audit_dir");
        std::fs::create_dir_all(tmp.join(".denyx")).unwrap();
        let d = diagnose(&tmp);
        assert!(matches!(d.audit_dir, AuditDirCheck::Present { .. }));
    }

    #[test]
    fn diagnose_audit_dir_not_a_directory_when_file_at_path() {
        let tmp = unique_tempdir("audit_file");
        std::fs::write(tmp.join(".denyx"), "oops").unwrap();
        let d = diagnose(&tmp);
        assert!(matches!(d.audit_dir, AuditDirCheck::NotADirectory { .. }));
    }

    #[test]
    fn diagnose_gitignore_excluded_recognises_dotdenyx_slash() {
        let tmp = unique_tempdir("gi_excluded");
        std::fs::write(tmp.join(".gitignore"), "target/\n.denyx/\nfoo\n").unwrap();
        let d = diagnose(&tmp);
        assert_eq!(d.gitignore, GitignoreCheck::Excluded);
    }

    #[test]
    fn diagnose_gitignore_not_excluded_when_no_match() {
        let tmp = unique_tempdir("gi_not_excluded");
        std::fs::write(tmp.join(".gitignore"), "target/\n").unwrap();
        let d = diagnose(&tmp);
        assert_eq!(d.gitignore, GitignoreCheck::NotExcluded);
    }
}
