//! Cross-cutting consistency checks between a Denyx [`Policy`] and a
//! [`ProjectDiagnosis`]. Used by `denyx doctor` to surface
//! contradictions between what the policy declares and what the
//! project's host-configs / launch flags / project state actually
//! enforce.
//!
//! These checks complement (don't replace) the per-binary doctors:
//! `denyx-mcp doctor` and `denyx-local-mcp doctor` each verify their
//! own slice; this module checks the *seams* between policy and
//! wiring, the things only an external view can spot.
//!
//! Every check is read-only and pure — given the same inputs it
//! returns the same issues. Tests cover individual checks with
//! synthetic Policy + ProjectDiagnosis fixtures.

use std::collections::BTreeSet;

use denyx_policy::Policy;

use crate::project_diagnosis::{
    DenyxFlavor, DetectedDenyxServer, HostConfigEntry, ProjectDiagnosis,
};

/// One contradiction the doctor surfaced. Each variant carries the
/// minimum data needed for a useful fix message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyIssue {
    /// `[tools.X].backend_url`'s host is not allowed by any
    /// `[network].http_*_allow` list. Calling that tool would fail
    /// at runtime with a network-deny.
    ToolUrlNotInNetworkAllow {
        tool_name: String,
        host: String,
        method: String,
    },
    /// `[tools.X]` declares a capability whose resource section is
    /// empty in the policy. The verifier rejects calls to such
    /// capabilities at runtime — the tool is declared but unusable.
    ToolDeclaresUnsupportedCapability {
        tool_name: String,
        capability: String,
    },
    /// Policy lists `requires_approval` capabilities, but at least
    /// one host-config launches denyx-mcp / denyx-local-mcp with
    /// `--confirm-mode auto-allow` — bypassing every approval.
    RequiresApprovalBypassed {
        host_config: String,
        approval_caps: Vec<String>,
    },
    /// Two host-configs in the same project pass DIFFERENT `--policy`
    /// paths. Likely a mistake — the gate enforces different policies
    /// depending on which host is launched.
    ConflictingPolicyPaths { paths: Vec<(String, String)> },
    /// One or more non-glob paths in `read_allow` / `write_allow` /
    /// `delete_allow` don't exist on disk. INFO-level — most starter
    /// policies advertise toolchain files (`pyproject.toml`,
    /// `setup.py`, …) the project might not actually have. Aggregated
    /// into one issue so the doctor doesn't print 20 lines for one
    /// concept.
    PolicyPathsDoNotExist {
        entries: Vec<(&'static str, String)>,
    },
    /// One or more `[subprocess].allow_commands` entries (bare command
    /// names, not absolute paths) aren't on the doctor's `$PATH`.
    /// INFO-level: the gate may run in a different environment than
    /// the doctor (Lima VM on macOS, WSL2 distro on Windows,
    /// container in CI), so "missing here" doesn't always mean
    /// "missing at runtime." Aggregated into one issue.
    SubprocessCommandsNotOnPath { commands: Vec<String> },
    /// Hosts in the policy's `http_*_allow` lists that are missing
    /// from `.claude/settings.json`'s `sandbox.network.allowedDomains`.
    /// The OS sandbox would block calls to these hosts before the
    /// Denyx policy gate even sees them — visible to the operator
    /// only as a confusing kernel-level error. Caused by editing
    /// `denyx.toml` without re-running `denyx host-config`.
    SandboxAllowedDomainsStale { missing_hosts: Vec<String> },
    /// Absolute / home-relative paths in the policy's `write_allow`
    /// that are missing from `.claude/settings.json`'s
    /// `sandbox.filesystem.allowWrite`. Same drift as
    /// `SandboxAllowedDomainsStale` but for filesystem writes.
    SandboxAllowWriteStale { missing_paths: Vec<String> },
}

/// Severity classification for the doctor's [OK]/[INFO]/[WARN]/[FAIL]
/// rendering. Critical = setup is broken; Warning = setup is
/// inconsistent and probably intended-but-worth-flagging; Info = FYI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl ConsistencyIssue {
    pub fn severity(&self) -> Severity {
        match self {
            // Tool wired with a URL the network gate denies → tool
            // can't function. Critical.
            Self::ToolUrlNotInNetworkAllow { .. } => Severity::Critical,
            // Tool declares a capability not actually granted → the
            // verifier rejects every call. Critical.
            Self::ToolDeclaresUnsupportedCapability { .. } => Severity::Critical,
            // Approval gate bypassed → policy intent is silently
            // overridden. Warning (intentional override is possible
            // for tests / demos, but worth flagging on every doctor
            // run).
            Self::RequiresApprovalBypassed { .. } => Severity::Warning,
            // Two configs disagreeing on the policy file path → likely
            // a mistake but possibly per-host intent. Warning.
            Self::ConflictingPolicyPaths { .. } => Severity::Warning,
            // Heads-up only — the paths / commands might be created
            // later, intentionally optional, or live in the gate's
            // runtime env (which the doctor doesn't see).
            Self::PolicyPathsDoNotExist { .. } => Severity::Info,
            Self::SubprocessCommandsNotOnPath { .. } => Severity::Info,
            // Sandbox drift means the OS layer can block calls the
            // policy permits — operator-visible kernel errors with
            // no Denyx breadcrumb. Warning, not Critical: the gate
            // still works, it just might surface confusing failures
            // until host-config is re-run.
            Self::SandboxAllowedDomainsStale { .. } => Severity::Warning,
            Self::SandboxAllowWriteStale { .. } => Severity::Warning,
        }
    }

    /// Short one-line summary suitable for a `[X] label: msg` line.
    pub fn summary(&self) -> String {
        match self {
            Self::ToolUrlNotInNetworkAllow {
                tool_name,
                host,
                method,
            } => format!(
                "tool '{tool_name}' declares {method} {host} but {host} is not in [network].http_{}_allow",
                method.to_lowercase()
            ),
            Self::ToolDeclaresUnsupportedCapability {
                tool_name,
                capability,
            } => format!(
                "tool '{tool_name}' declares capability '{capability}' but the policy doesn't grant it"
            ),
            Self::RequiresApprovalBypassed {
                host_config,
                approval_caps,
            } => format!(
                "{host_config} launches with --confirm-mode auto-allow, bypassing requires_approval ({})",
                approval_caps.join(", ")
            ),
            Self::ConflictingPolicyPaths { paths } => {
                let listed = paths
                    .iter()
                    .map(|(host, p)| format!("{host} → {p}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                format!("multiple host-configs reference different --policy paths: {listed}")
            }
            Self::PolicyPathsDoNotExist { entries } => {
                let n = entries.len();
                let preview: Vec<String> = entries
                    .iter()
                    .take(8)
                    .map(|(section, p)| format!("{p} ({section})"))
                    .collect();
                let suffix = if entries.len() > 8 {
                    format!(", … (+{} more)", entries.len() - 8)
                } else {
                    String::new()
                };
                format!(
                    "{n} declared path{} not present on disk: {}{suffix}",
                    if n == 1 { "" } else { "s" },
                    preview.join(", ")
                )
            }
            Self::SubprocessCommandsNotOnPath { commands } => {
                let n = commands.len();
                format!(
                    "{n} subprocess.allow_commands {} not on the doctor's PATH: {}",
                    if n == 1 { "entry" } else { "entries" },
                    commands.join(", ")
                )
            }
            Self::SandboxAllowedDomainsStale { missing_hosts } => {
                let n = missing_hosts.len();
                format!(
                    "{n} host{} allowed by [network].http_*_allow but absent from \
                     .claude/settings.json sandbox.network.allowedDomains: {}",
                    if n == 1 { "" } else { "s" },
                    missing_hosts.join(", ")
                )
            }
            Self::SandboxAllowWriteStale { missing_paths } => {
                let n = missing_paths.len();
                format!(
                    "{n} write path{} allowed by [filesystem].write_allow but absent \
                     from .claude/settings.json sandbox.filesystem.allowWrite: {}",
                    if n == 1 { "" } else { "s" },
                    missing_paths.join(", ")
                )
            }
        }
    }

    /// Multi-line fix instructions, copy-pasteable when possible.
    pub fn fix(&self) -> String {
        match self {
            Self::ToolUrlNotInNetworkAllow { host, method, .. } => format!(
                "Add the host to [network].http_{}_allow:\n  http_{}_allow = [\"{}\"]\nOr remove the [tools.X] entry if the tool isn't actually used.",
                method.to_lowercase(),
                method.to_lowercase(),
                host
            ),
            Self::ToolDeclaresUnsupportedCapability { capability, .. } => format!(
                "Either populate the resource section that grants '{capability}' (e.g. add an entry to [filesystem].read_allow for fs.read), or drop the capability from the [tools.X] declaration."
            ),
            Self::RequiresApprovalBypassed { .. } =>
                "Change `--confirm-mode auto-allow` to `--confirm-mode auto` (the default) so approval-gated capabilities elicit per-call. `auto-allow` is intended for tests and demos only.".to_string(),
            Self::ConflictingPolicyPaths { .. } =>
                "Pick one canonical denyx.toml location and re-run `denyx host-config --existing replace` for every host that should use it. Per-host policy paths are rarely the right design.".to_string(),
            Self::PolicyPathsDoNotExist { .. } =>
                "These paths might be created later (build artifacts, downloads), intentionally optional (starter-policy templates list every conceivable toolchain file), or typos. Heads-up only — the policy is still valid and the runtime won't fail because of these.".to_string(),
            Self::SubprocessCommandsNotOnPath { .. } =>
                "Heads-up: the doctor's PATH is the env that ran `denyx doctor`. The gate (denyx-mcp) may run in a different env — a Lima VM on macOS, a WSL2 distro on Windows, a container in CI — where these commands could be present. Verify the gate's runtime PATH if any of these matter; remove from [subprocess].allow_commands if you don't actually need them.".to_string(),
            Self::SandboxAllowedDomainsStale { .. } | Self::SandboxAllowWriteStale { .. } =>
                "Re-run `denyx host-config --existing replace --host claude` to refresh the sandbox stanza from the live policy. The sandbox stanza is a frozen snapshot taken at host-config time; edits to denyx.toml don't propagate automatically. Without the refresh, calls Denyx permits will be blocked at the OS layer (bubblewrap on Linux/WSL2, Seatbelt on macOS) with errors that don't mention Denyx.".to_string(),
        }
    }
}

// ─────────────────────────── public API ───────────────────────────

/// Run every cross-cutting consistency check. The policy is optional:
/// when `None`, only checks that don't require policy data run
/// (currently just "conflicting policy paths across host-configs").
pub fn check(policy: Option<&Policy>, diagnosis: &ProjectDiagnosis) -> Vec<ConsistencyIssue> {
    let mut out = Vec::new();
    out.extend(check_conflicting_policy_paths(diagnosis));
    if let Some(p) = policy {
        let file = p.file_snapshot();
        out.extend(check_tool_urls_against_network(file));
        out.extend(check_tool_capabilities_against_policy(file, p));
        out.extend(check_requires_approval_vs_confirm_mode(file, diagnosis));
        out.extend(check_policy_paths_exist(file, &diagnosis.root));
        out.extend(check_subprocess_commands_on_path(file));
        out.extend(check_sandbox_drift(file, diagnosis));
    }
    out
}

// ─────────────────────── individual checks ───────────────────────

fn check_tool_urls_against_network(file: &denyx_policy::PolicyFile) -> Vec<ConsistencyIssue> {
    let mut out = Vec::new();
    for (tool_name, record) in &file.tools {
        let url_str = match record.backend_url.as_deref() {
            Some(u) => u,
            None => continue,
        };
        let host = match url::Url::parse(url_str)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
        {
            Some(h) => h,
            None => continue,
        };
        let method = record
            .backend_method
            .as_deref()
            .unwrap_or("GET")
            .to_uppercase();
        let allowed_set: &Vec<String> = match method.as_str() {
            "GET" => &file.network.http_get_allow,
            "POST" => &file.network.http_post_allow,
            "PUT" => &file.network.http_put_allow,
            "PATCH" => &file.network.http_patch_allow,
            "DELETE" => &file.network.http_delete_allow,
            _ => continue,
        };
        if !host_matches_any(&host, allowed_set) {
            out.push(ConsistencyIssue::ToolUrlNotInNetworkAllow {
                tool_name: tool_name.clone(),
                host,
                method,
            });
        }
    }
    out
}

/// Check whether `host` matches any pattern in `allow_list`. Patterns
/// can be exact strings or globs (e.g., `*.example.com`); we use a
/// simple "exact match or wildcard suffix" rule that mirrors what the
/// runtime accepts.
fn host_matches_any(host: &str, allow_list: &[String]) -> bool {
    for pat in allow_list {
        if pat == host {
            return true;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            // *.example.com matches example.com, foo.example.com, etc.
            if host == suffix || host.ends_with(&format!(".{suffix}")) {
                return true;
            }
        }
    }
    false
}

fn check_tool_capabilities_against_policy(
    file: &denyx_policy::PolicyFile,
    policy: &Policy,
) -> Vec<ConsistencyIssue> {
    let granted: BTreeSet<&str> = policy.effective_functions().into_iter().collect();
    let mut out = Vec::new();
    for (tool_name, record) in &file.tools {
        for cap in &record.capabilities {
            if !granted.contains(cap.as_str()) {
                out.push(ConsistencyIssue::ToolDeclaresUnsupportedCapability {
                    tool_name: tool_name.clone(),
                    capability: cap.clone(),
                });
            }
        }
    }
    out
}

fn check_requires_approval_vs_confirm_mode(
    file: &denyx_policy::PolicyFile,
    diagnosis: &ProjectDiagnosis,
) -> Vec<ConsistencyIssue> {
    if file.requires_approval.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for hc in &diagnosis.host_configs {
        for server in denyx_servers_in(hc) {
            if has_auto_allow_confirm_mode(server) {
                out.push(ConsistencyIssue::RequiresApprovalBypassed {
                    host_config: format!("{} ({})", hc.host.label(), hc.path.display()),
                    approval_caps: file.requires_approval.clone(),
                });
                // Don't report twice for the same host-config even
                // if it has multiple denyx servers wired.
                break;
            }
        }
    }
    out
}

/// Iterator over every Denyx-flavored MCP server in a host-config
/// (denyx-mcp or denyx-local-mcp).
fn denyx_servers_in(hc: &HostConfigEntry) -> impl Iterator<Item = &DetectedDenyxServer> {
    hc.denyx_servers
        .iter()
        .filter(|s| matches!(s.flavor, DenyxFlavor::DenyxMcp | DenyxFlavor::DenyxLocalMcp))
}

/// True when args contain `--confirm-mode auto-allow` (in either
/// `--confirm-mode=auto-allow` or split-arg form).
fn has_auto_allow_confirm_mode(server: &DetectedDenyxServer) -> bool {
    let mut iter = server.args.iter();
    while let Some(a) = iter.next() {
        if a == "--confirm-mode" {
            if let Some(v) = iter.next() {
                if v == "auto-allow" {
                    return true;
                }
            }
        } else if let Some(v) = a.strip_prefix("--confirm-mode=") {
            if v == "auto-allow" {
                return true;
            }
        }
    }
    false
}

fn check_conflicting_policy_paths(diagnosis: &ProjectDiagnosis) -> Vec<ConsistencyIssue> {
    let mut paths: Vec<(String, String)> = Vec::new();
    for hc in &diagnosis.host_configs {
        for server in denyx_servers_in(hc) {
            if let Some(p) = extract_policy_path(server) {
                paths.push((hc.host.label().to_string(), p));
            }
        }
    }
    let unique: BTreeSet<&str> = paths.iter().map(|(_, p)| p.as_str()).collect();
    if unique.len() > 1 {
        vec![ConsistencyIssue::ConflictingPolicyPaths { paths }]
    } else {
        Vec::new()
    }
}

fn extract_policy_path(server: &DetectedDenyxServer) -> Option<String> {
    let mut iter = server.args.iter();
    while let Some(a) = iter.next() {
        if a == "--policy" {
            return iter.next().cloned();
        } else if let Some(v) = a.strip_prefix("--policy=") {
            return Some(v.to_string());
        }
    }
    None
}

fn check_policy_paths_exist(
    file: &denyx_policy::PolicyFile,
    project_root: &std::path::Path,
) -> Vec<ConsistencyIssue> {
    let mut entries: Vec<(&'static str, String)> = Vec::new();
    for (section, list) in [
        ("read_allow", &file.filesystem.read_allow),
        ("write_allow", &file.filesystem.write_allow),
        ("delete_allow", &file.filesystem.delete_allow),
    ] {
        for raw in list {
            // Skip globs and home-relative paths (we don't expand `~`).
            if raw.contains('*') || raw.contains('?') || raw.starts_with('~') {
                continue;
            }
            // Only check project-relative paths to avoid false positives
            // on absolute paths that exist on the operator's machine but
            // not where the doctor runs.
            if raw.starts_with('/') {
                continue;
            }
            let stripped = raw.trim_start_matches("./");
            let abs = project_root.join(stripped);
            if !abs.exists() {
                entries.push((section, raw.clone()));
            }
        }
    }
    if entries.is_empty() {
        Vec::new()
    } else {
        vec![ConsistencyIssue::PolicyPathsDoNotExist { entries }]
    }
}

/// Compare the policy's allow lists against `.claude/settings.json`'s
/// `sandbox` stanza. If the sandbox is missing entries the policy
/// allows, the OS sandbox would block those calls before Denyx's
/// gate ever sees them — visible to the operator only as a confusing
/// kernel-level error. Caused by editing `denyx.toml` without
/// re-running `denyx host-config`.
///
/// Only runs when `.claude/settings.json` actually has a sandbox
/// stanza. Projects without Claude Code, or that ran
/// `host-config --sandbox off`, get no issues from this check.
fn check_sandbox_drift(
    file: &denyx_policy::PolicyFile,
    diagnosis: &ProjectDiagnosis,
) -> Vec<ConsistencyIssue> {
    let sandbox = match &diagnosis.claude_sandbox {
        Some(s) if s.enabled => s,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();

    // ── allowedDomains drift ──────────────────────────────────────
    // Policy hosts that should be in the sandbox's allowed list.
    let policy_hosts: BTreeSet<&str> = file
        .network
        .http_get_allow
        .iter()
        .chain(&file.network.http_post_allow)
        .chain(&file.network.http_put_allow)
        .chain(&file.network.http_patch_allow)
        .chain(&file.network.http_delete_allow)
        .chain(&file.network.local_only_hosts)
        .map(|s| s.as_str())
        .collect();
    let sandbox_hosts: BTreeSet<&str> =
        sandbox.allowed_domains.iter().map(|s| s.as_str()).collect();
    let missing_hosts: Vec<String> = policy_hosts
        .difference(&sandbox_hosts)
        .map(|s| (*s).to_string())
        .collect();
    if !missing_hosts.is_empty() {
        out.push(ConsistencyIssue::SandboxAllowedDomainsStale { missing_hosts });
    }

    // ── allowWrite drift ──────────────────────────────────────────
    // Mirror what host_config.rs::sandbox_stanza emits: only
    // absolute / home-relative paths, with trailing /** or /* stripped.
    // Project-relative paths are covered by Claude's "cwd writable"
    // default — not in the snapshot, not a drift candidate here.
    let mut policy_writes: BTreeSet<String> = BTreeSet::new();
    for raw in &file.filesystem.write_allow {
        if !(raw.starts_with('/') || raw.starts_with("~/")) {
            continue;
        }
        let cleaned = raw.trim_end_matches("/**").trim_end_matches("/*");
        if !cleaned.is_empty() {
            policy_writes.insert(cleaned.to_string());
        }
    }
    let sandbox_writes: BTreeSet<&str> = sandbox.allow_write.iter().map(|s| s.as_str()).collect();
    let missing_paths: Vec<String> = policy_writes
        .iter()
        .filter(|p| !sandbox_writes.contains(p.as_str()))
        .cloned()
        .collect();
    if !missing_paths.is_empty() {
        out.push(ConsistencyIssue::SandboxAllowWriteStale { missing_paths });
    }

    out
}

fn check_subprocess_commands_on_path(file: &denyx_policy::PolicyFile) -> Vec<ConsistencyIssue> {
    let mut commands: Vec<String> = Vec::new();
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let path_dirs: Vec<std::path::PathBuf> = std::env::split_paths(&path_var).collect();
    for cmd in &file.subprocess.allow_commands {
        // Skip absolute paths and globby entries; only check bare commands.
        if cmd.contains('/') || cmd.contains('*') {
            continue;
        }
        let found = path_dirs.iter().any(|d| {
            let candidate = d.join(cmd);
            candidate.exists() || candidate.with_extension("exe").exists()
        });
        if !found {
            commands.push(cmd.clone());
        }
    }
    if commands.is_empty() {
        Vec::new()
    } else {
        vec![ConsistencyIssue::SubprocessCommandsNotOnPath { commands }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_diagnosis::{
        AuditDirCheck, GitignoreCheck, HostName, LockdownState, PolicyCheck,
    };
    use std::path::PathBuf;

    fn empty_diagnosis() -> ProjectDiagnosis {
        ProjectDiagnosis {
            root: PathBuf::from("/proj"),
            policy: PolicyCheck::Missing,
            host_configs: vec![],
            audit_dir: AuditDirCheck::Absent,
            gitignore: GitignoreCheck::Missing,
            claude_sandbox: None,
        }
    }

    fn server(
        name: &str,
        command: &str,
        args: Vec<&str>,
        flavor: DenyxFlavor,
    ) -> DetectedDenyxServer {
        DetectedDenyxServer {
            name: name.to_string(),
            flavor,
            command: command.to_string(),
            args: args.into_iter().map(String::from).collect(),
            via_wrapper: None,
        }
    }

    fn host_config(host: HostName, servers: Vec<DetectedDenyxServer>) -> HostConfigEntry {
        HostConfigEntry {
            path: PathBuf::from(".mcp.json"),
            host,
            denyx_servers: servers,
            lockdown_state: LockdownState::Active,
        }
    }

    #[test]
    fn host_matches_any_handles_exact_and_wildcard() {
        assert!(host_matches_any(
            "api.github.com",
            &["api.github.com".into()]
        ));
        assert!(host_matches_any("api.github.com", &["*.github.com".into()]));
        assert!(host_matches_any("github.com", &["*.github.com".into()]));
        assert!(!host_matches_any("evil.com", &["api.github.com".into()]));
        assert!(!host_matches_any("a.evil.com", &["*.github.com".into()]));
    }

    #[test]
    fn extract_policy_path_finds_value_after_flag() {
        let s = server(
            "x",
            "denyx-mcp",
            vec!["--policy", "./denyx.toml"],
            DenyxFlavor::DenyxMcp,
        );
        assert_eq!(extract_policy_path(&s), Some("./denyx.toml".to_string()));
    }

    #[test]
    fn extract_policy_path_handles_equals_form() {
        let s = server(
            "x",
            "denyx-mcp",
            vec!["--policy=./denyx.toml"],
            DenyxFlavor::DenyxMcp,
        );
        assert_eq!(extract_policy_path(&s), Some("./denyx.toml".to_string()));
    }

    #[test]
    fn has_auto_allow_confirm_mode_recognises_both_forms() {
        let s1 = server(
            "x",
            "denyx-mcp",
            vec!["--confirm-mode", "auto-allow"],
            DenyxFlavor::DenyxMcp,
        );
        assert!(has_auto_allow_confirm_mode(&s1));
        let s2 = server(
            "x",
            "denyx-mcp",
            vec!["--confirm-mode=auto-allow"],
            DenyxFlavor::DenyxMcp,
        );
        assert!(has_auto_allow_confirm_mode(&s2));
        let s3 = server(
            "x",
            "denyx-mcp",
            vec!["--confirm-mode", "auto"],
            DenyxFlavor::DenyxMcp,
        );
        assert!(!has_auto_allow_confirm_mode(&s3));
    }

    #[test]
    fn check_conflicting_policy_paths_returns_empty_for_one_path() {
        let mut diag = empty_diagnosis();
        diag.host_configs.push(host_config(
            HostName::Claude,
            vec![server(
                "x",
                "denyx-mcp",
                vec!["--policy", "./a.toml"],
                DenyxFlavor::DenyxMcp,
            )],
        ));
        diag.host_configs.push(host_config(
            HostName::Opencode,
            vec![server(
                "y",
                "denyx-mcp",
                vec!["--policy", "./a.toml"],
                DenyxFlavor::DenyxMcp,
            )],
        ));
        let out = check_conflicting_policy_paths(&diag);
        assert!(out.is_empty());
    }

    #[test]
    fn check_conflicting_policy_paths_detects_mismatch() {
        let mut diag = empty_diagnosis();
        diag.host_configs.push(host_config(
            HostName::Claude,
            vec![server(
                "x",
                "denyx-mcp",
                vec!["--policy", "./a.toml"],
                DenyxFlavor::DenyxMcp,
            )],
        ));
        diag.host_configs.push(host_config(
            HostName::Opencode,
            vec![server(
                "y",
                "denyx-mcp",
                vec!["--policy", "./b.toml"],
                DenyxFlavor::DenyxMcp,
            )],
        ));
        let out = check_conflicting_policy_paths(&diag);
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0],
            ConsistencyIssue::ConflictingPolicyPaths { .. }
        ));
    }

    fn parse_policy(toml: &str) -> Policy {
        let file = denyx_policy::PolicyFile::from_toml_str(toml)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        Policy::from_file(file, std::env::temp_dir()).unwrap()
    }

    #[test]
    fn tool_url_not_in_network_allow_is_critical() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["api.github.com"]

[tools.SearchAPI]
backend_url = "https://search.example.com/api"
backend_method = "GET"
capabilities = ["net.http_get"]
"#,
        );
        let issues = check_tool_urls_against_network(p.file_snapshot());
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity(), Severity::Critical);
        assert!(issues[0].summary().contains("search.example.com"));
        assert!(issues[0].fix().contains("http_get_allow"));
    }

    #[test]
    fn tool_url_passes_when_host_is_allowed_via_wildcard() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["*.github.com"]

[tools.GitHubSearch]
backend_url = "https://api.github.com/search/repos"
backend_method = "GET"
"#,
        );
        let issues = check_tool_urls_against_network(p.file_snapshot());
        assert!(issues.is_empty(), "wildcard match should pass: {issues:?}");
    }

    #[test]
    fn requires_approval_with_auto_allow_is_warning() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"
requires_approval = ["fs.delete", "subprocess.exec"]
"#,
        );
        let mut diag = empty_diagnosis();
        diag.host_configs.push(host_config(
            HostName::Claude,
            vec![server(
                "denyx",
                "denyx-mcp",
                vec!["--policy", "./denyx.toml", "--confirm-mode", "auto-allow"],
                DenyxFlavor::DenyxMcp,
            )],
        ));
        let issues = check_requires_approval_vs_confirm_mode(p.file_snapshot(), &diag);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity(), Severity::Warning);
        let s = issues[0].summary();
        assert!(s.contains("auto-allow"));
        assert!(s.contains("fs.delete"));
    }

    #[test]
    fn requires_approval_with_auto_mode_is_clean() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"
requires_approval = ["fs.delete"]
"#,
        );
        let mut diag = empty_diagnosis();
        diag.host_configs.push(host_config(
            HostName::Claude,
            vec![server(
                "denyx",
                "denyx-mcp",
                vec!["--confirm-mode", "auto"],
                DenyxFlavor::DenyxMcp,
            )],
        ));
        assert!(check_requires_approval_vs_confirm_mode(p.file_snapshot(), &diag).is_empty());
    }

    #[test]
    fn no_requires_approval_means_no_check() {
        // Bare PolicyFile without inheriting secure-defaults so
        // requires_approval is genuinely empty.
        let p = parse_policy("");
        let mut diag = empty_diagnosis();
        diag.host_configs.push(host_config(
            HostName::Claude,
            vec![server(
                "denyx",
                "denyx-mcp",
                vec!["--confirm-mode", "auto-allow"],
                DenyxFlavor::DenyxMcp,
            )],
        ));
        assert!(p.file_snapshot().requires_approval.is_empty());
        assert!(check_requires_approval_vs_confirm_mode(p.file_snapshot(), &diag).is_empty());
    }

    #[test]
    fn check_returns_empty_when_no_policy_and_one_host_config() {
        let diag = empty_diagnosis();
        assert!(check(None, &diag).is_empty());
    }

    fn diag_with_sandbox(allowed_domains: Vec<&str>, allow_write: Vec<&str>) -> ProjectDiagnosis {
        let mut d = empty_diagnosis();
        d.claude_sandbox = Some(crate::project_diagnosis::SandboxSnapshot {
            enabled: true,
            allowed_domains: allowed_domains.into_iter().map(String::from).collect(),
            allow_write: allow_write.into_iter().map(String::from).collect(),
        });
        d
    }

    #[test]
    fn check_sandbox_drift_clean_when_sandbox_matches_policy() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["api.github.com"]

[filesystem]
write_allow = ["/var/tmp/myproj/**", "src/**"]
"#,
        );
        // Sandbox snapshot mirrors what host-config would emit:
        // api.github.com in allowedDomains, /var/tmp/myproj in
        // allowWrite (project-relative src/** is skipped).
        let d = diag_with_sandbox(vec!["api.github.com"], vec!["/var/tmp/myproj"]);
        assert!(check_sandbox_drift(p.file_snapshot(), &d).is_empty());
    }

    #[test]
    fn check_sandbox_drift_flags_missing_allowed_domain() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["api.github.com", "api.openai.com"]
"#,
        );
        // Sandbox is stale: only has the original github host.
        let d = diag_with_sandbox(vec!["api.github.com"], vec![]);
        let issues = check_sandbox_drift(p.file_snapshot(), &d);
        assert_eq!(issues.len(), 1);
        match &issues[0] {
            ConsistencyIssue::SandboxAllowedDomainsStale { missing_hosts } => {
                assert_eq!(missing_hosts, &vec!["api.openai.com".to_string()]);
            }
            other => panic!("expected SandboxAllowedDomainsStale, got {other:?}"),
        }
        assert_eq!(issues[0].severity(), Severity::Warning);
        assert!(issues[0]
            .fix()
            .contains("denyx host-config --existing replace"));
    }

    #[test]
    fn check_sandbox_drift_flags_missing_allow_write_path() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[filesystem]
write_allow = ["/var/log/myapp/**", "/opt/cache/**"]
"#,
        );
        let d = diag_with_sandbox(vec![], vec!["/var/log/myapp"]); // /opt/cache missing
        let issues = check_sandbox_drift(p.file_snapshot(), &d);
        assert_eq!(issues.len(), 1);
        match &issues[0] {
            ConsistencyIssue::SandboxAllowWriteStale { missing_paths } => {
                assert_eq!(missing_paths, &vec!["/opt/cache".to_string()]);
            }
            other => panic!("expected SandboxAllowWriteStale, got {other:?}"),
        }
    }

    #[test]
    fn check_sandbox_drift_skips_project_relative_writes() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[filesystem]
write_allow = ["src/**", "tests/**"]
"#,
        );
        // No absolute writes → nothing to check against the sandbox.
        let d = diag_with_sandbox(vec![], vec![]);
        assert!(check_sandbox_drift(p.file_snapshot(), &d).is_empty());
    }

    #[test]
    fn check_sandbox_drift_returns_empty_when_no_sandbox_in_settings() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["api.github.com"]
"#,
        );
        // claude_sandbox is None — projects without Claude Code or
        // those that ran host-config --sandbox off.
        let d = empty_diagnosis();
        assert!(check_sandbox_drift(p.file_snapshot(), &d).is_empty());
    }

    #[test]
    fn check_sandbox_drift_returns_empty_when_sandbox_is_disabled() {
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["api.github.com"]
"#,
        );
        let mut d = empty_diagnosis();
        d.claude_sandbox = Some(crate::project_diagnosis::SandboxSnapshot {
            enabled: false,
            allowed_domains: vec![],
            allow_write: vec![],
        });
        assert!(check_sandbox_drift(p.file_snapshot(), &d).is_empty());
    }

    #[test]
    fn check_sandbox_drift_strips_glob_suffix_when_comparing() {
        // host-config trims /** and /* from policy paths before
        // putting them in the sandbox stanza. The drift check must
        // do the same trimming to compare like-with-like.
        let p = parse_policy(
            r#"
inherits = "secure-defaults"

[filesystem]
write_allow = ["/var/log/myapp/**"]
"#,
        );
        let d = diag_with_sandbox(vec![], vec!["/var/log/myapp"]); // post-trim form
        assert!(check_sandbox_drift(p.file_snapshot(), &d).is_empty());
    }

    #[test]
    fn issue_summary_and_fix_are_non_empty() {
        let i = ConsistencyIssue::ToolUrlNotInNetworkAllow {
            tool_name: "X".into(),
            host: "y".into(),
            method: "GET".into(),
        };
        assert!(!i.summary().is_empty());
        assert!(!i.fix().is_empty());
    }
}
