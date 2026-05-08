//! `denyx doctor` — operator-facing project preflight.
//!
//! Single entry point for "is my Denyx setup right?". Combines:
//!
//!   * `denyx_host::project_diagnosis::diagnose` — what files exist,
//!     what's wired, lockdown state.
//!   * `denyx_host::policy_host_consistency::check` — cross-cutting
//!     policy ↔ host-config ↔ launch-flag ↔ project-state checks
//!     that neither binary-specific doctor can see.
//!
//! Renders with the same `[OK]/[INFO]/[WARN]/[FAIL]` formatting
//! language as `denyx-mcp doctor` and `denyx-local-mcp doctor`.
//! Doesn't talk to a network or modify anything.

use std::path::{Path, PathBuf};

use clap::Parser;
use denyx_host::policy_host_consistency::{self, ConsistencyIssue, Severity};
use denyx_host::project_diagnosis::{
    self, AuditDirCheck, DenyxFlavor, GitignoreCheck, LockdownState, PolicyCheck, ProjectDiagnosis,
};
use denyx_policy::Policy;

#[derive(Parser, Debug)]
pub struct DoctorArgs {
    /// Project root to inspect. Defaults to the current directory.
    #[arg(long)]
    pub project_path: Option<PathBuf>,

    /// Apply mechanical fixes for issues that can be safely
    /// re-derived from the policy:
    ///   - missing `.denyx/` audit dir → `mkdir`
    ///   - `.gitignore` missing `.denyx/` line → append
    ///   - stale sandbox stanza in `.claude/settings.json` →
    ///     re-emit from policy via `host-config --existing replace`
    ///   - missing / partial built-in deny list → same
    ///
    /// Issues that require operator judgment (policy decisions —
    /// adding hosts to allow lists, granting capabilities,
    /// resolving conflicting policy paths) are NEVER auto-fixed.
    /// Those still require manual action and remain in the
    /// post-fix report.
    #[arg(long)]
    pub fix: bool,
}

pub fn run(args: DoctorArgs) -> i32 {
    let project_path = args
        .project_path
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .unwrap_or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
                .unwrap_or_else(|| PathBuf::from("."))
        });

    let (out, code, diagnosis, issues) = run_diagnosis(&project_path);
    print!("{out}");

    if !args.fix {
        return code;
    }

    // ── --fix: plan, confirm, apply, re-diagnose ───────────────────
    let fixes = plan_fixes(&diagnosis, &issues);
    let non_fixable = non_fixable_issues(&issues);

    if fixes.is_empty() {
        println!();
        println!("--fix: no auto-fixable issues to apply.");
        if !non_fixable.is_empty() {
            println!(
                "       {} issue(s) above require operator decision; see the fix \
                 instructions in the report.",
                non_fixable.len()
            );
        }
        return code;
    }

    print!("{}", render_fix_plan(&fixes, &non_fixable));

    let approved = confirm(&format!(
        "Apply the {} auto-fix{} above? [y/N]: ",
        fixes.len(),
        if fixes.len() == 1 { "" } else { "es" }
    ));
    if !approved {
        println!();
        println!(
            "Skipped. Re-run `denyx doctor --fix` from a terminal to apply, or \
             fix manually using the instructions in the report above."
        );
        return code;
    }

    println!();
    let mut all_ok = true;
    for fix in &fixes {
        match apply_fix(fix, &project_path) {
            Ok(detail) => println!("  [FIX] {}: {detail}", fix.label),
            Err(e) => {
                println!("  [ERR] {}: {e}", fix.label);
                all_ok = false;
            }
        }
    }

    if !all_ok {
        return 2;
    }

    println!();
    println!("Re-running doctor to verify …");
    println!();
    let (out2, code2, _, _) = run_diagnosis(&project_path);
    print!("{out2}");
    code2
}

fn run_diagnosis(
    project_path: &Path,
) -> (
    String,
    i32,
    project_diagnosis::ProjectDiagnosis,
    Vec<ConsistencyIssue>,
) {
    let diagnosis = project_diagnosis::diagnose(project_path);
    let loaded_policy: Option<Policy> = match &diagnosis.policy {
        PolicyCheck::Valid { path, .. } => Policy::load(path).ok(),
        _ => None,
    };
    let issues = policy_host_consistency::check(loaded_policy.as_ref(), &diagnosis);
    let (out, code) = render(&diagnosis, &issues);
    (out, code, diagnosis, issues)
}

// ─────────────────────────── --fix support ───────────────────────────

#[derive(Debug, Clone)]
struct AutoFix {
    /// One-line description of what the fix does.
    label: String,
    /// Files / directories the fix will touch.
    targets: Vec<PathBuf>,
    /// Why the fix is being proposed (which issues triggered it).
    reasons: Vec<String>,
    /// What action to take.
    action: FixAction,
}

#[derive(Debug, Clone)]
enum FixAction {
    /// `denyx_host`-style audit-dir + .gitignore preparation.
    /// Mechanically equivalent to what `denyx host-config` does.
    PrepareAuditDir,
    /// Re-run `denyx host-config --policy <P> --host <list>
    /// --existing replace`, regenerating sandbox + lockdown +
    /// MCP entry from the live policy.
    RefreshHostConfig {
        hosts: Vec<String>,
        policy_path: PathBuf,
    },
}

/// Compute the set of mechanical fixes the doctor can safely apply.
/// Skips anything that requires a security / policy decision.
fn plan_fixes(
    diagnosis: &project_diagnosis::ProjectDiagnosis,
    issues: &[ConsistencyIssue],
) -> Vec<AutoFix> {
    let mut out = Vec::new();

    // ── audit dir + gitignore ─────────────────────────────────────
    let audit_drift = matches!(diagnosis.audit_dir, AuditDirCheck::Absent);
    let gi_drift = matches!(diagnosis.gitignore, GitignoreCheck::NotExcluded);
    if audit_drift || gi_drift {
        let mut reasons = Vec::new();
        if audit_drift {
            reasons.push("`.denyx/` audit dir is missing".to_string());
        }
        if matches!(diagnosis.gitignore, GitignoreCheck::NotExcluded) {
            reasons.push("`.gitignore` does not exclude `.denyx/`".to_string());
        }
        let mut targets = Vec::new();
        if audit_drift {
            targets.push(diagnosis.root.join(".denyx"));
        }
        if gi_drift {
            targets.push(diagnosis.root.join(".gitignore"));
        }
        out.push(AutoFix {
            label: "Prepare audit dir and `.gitignore` exclusion".to_string(),
            targets,
            reasons,
            action: FixAction::PrepareAuditDir,
        });
    }

    // ── sandbox / lockdown drift ──────────────────────────────────
    use denyx_host::project_diagnosis::HostName;
    let mut hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut targets: Vec<PathBuf> = Vec::new();

    for issue in issues {
        match issue {
            ConsistencyIssue::SandboxAllowedDomainsStale { missing_hosts } => {
                hosts.insert("claude".to_string());
                reasons.push(format!(
                    "{} host(s) missing from sandbox.allowedDomains: {}",
                    missing_hosts.len(),
                    summarise_list(missing_hosts, 5)
                ));
            }
            ConsistencyIssue::SandboxAllowWriteStale { missing_paths } => {
                hosts.insert("claude".to_string());
                reasons.push(format!(
                    "{} path(s) missing from sandbox.allowWrite: {}",
                    missing_paths.len(),
                    summarise_list(missing_paths, 5)
                ));
            }
            _ => {}
        }
    }
    for hc in &diagnosis.host_configs {
        let host_cli = match hc.host {
            HostName::Claude => "claude",
            HostName::Opencode => "opencode",
            HostName::Cursor => "cursor",
            HostName::Copilot => "copilot",
            HostName::Continue => "continue",
        };
        match &hc.lockdown_state {
            LockdownState::Absent => {
                hosts.insert(host_cli.to_string());
                reasons.push(format!("{} lockdown is absent", hc.host.label()));
                targets.push(hc.path.clone());
            }
            LockdownState::Partial { missing } => {
                hosts.insert(host_cli.to_string());
                reasons.push(format!(
                    "{} lockdown is partial ({} missing: {})",
                    hc.host.label(),
                    missing.len(),
                    summarise_list(missing, 5)
                ));
                targets.push(hc.path.clone());
            }
            _ => {}
        }
    }
    if !hosts.is_empty() {
        // Refresh requires a valid policy file path.
        if let PolicyCheck::Valid { path, .. } = &diagnosis.policy {
            let host_list: Vec<String> = hosts.into_iter().collect();
            // For sandbox drift on Claude, the refresh writes
            // .claude/settings.json; add it to targets.
            if host_list.iter().any(|h| h == "claude") {
                let claude_settings = diagnosis.root.join(".claude").join("settings.json");
                if !targets.contains(&claude_settings) {
                    targets.push(claude_settings);
                }
            }
            out.push(AutoFix {
                label: format!(
                    "Re-emit host config(s) [{}] from policy",
                    host_list.join(", ")
                ),
                targets,
                reasons,
                action: FixAction::RefreshHostConfig {
                    hosts: host_list,
                    policy_path: path.clone(),
                },
            });
        }
        // If policy isn't valid, the operator has to fix that first;
        // we already surface that as a [FAIL] in the regular report.
    }

    out
}

/// Return references to issues that auto-fix can NOT touch (policy
/// decisions, invalid policy, etc.). Used to make the operator
/// aware they'll still need to handle these manually.
fn non_fixable_issues(issues: &[ConsistencyIssue]) -> Vec<&ConsistencyIssue> {
    issues
        .iter()
        .filter(|i| {
            !matches!(
                i,
                ConsistencyIssue::SandboxAllowedDomainsStale { .. }
                    | ConsistencyIssue::SandboxAllowWriteStale { .. }
            )
        })
        .collect()
}

fn summarise_list(items: &[String], head: usize) -> String {
    let preview: Vec<String> = items.iter().take(head).cloned().collect();
    if items.len() > head {
        format!("{}, …(+{} more)", preview.join(", "), items.len() - head)
    } else {
        preview.join(", ")
    }
}

fn render_fix_plan(fixes: &[AutoFix], non_fixable: &[&ConsistencyIssue]) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!(
        "Auto-fixable changes ({} action{}):\n",
        fixes.len(),
        if fixes.len() == 1 { "" } else { "s" }
    ));
    for (i, f) in fixes.iter().enumerate() {
        out.push_str(&format!("  {}. {}\n", i + 1, f.label));
        for t in &f.targets {
            out.push_str(&format!("       target: {}\n", t.display()));
        }
        for r in &f.reasons {
            out.push_str(&format!("       reason: {r}\n"));
        }
    }

    if !non_fixable.is_empty() {
        out.push('\n');
        out.push_str(&format!(
            "Issues that require operator decision (NOT auto-fixed, {}):\n",
            non_fixable.len()
        ));
        for issue in non_fixable {
            out.push_str(&format!("  - {}\n", issue.summary()));
        }
    }
    out.push('\n');
    out
}

/// Read a y/N from stdin. Refuses to apply non-interactively
/// (returns false with a stderr explanation). Operators in CI who
/// genuinely need automated fix-application can call
/// `denyx host-config --existing replace --host …` directly.
fn confirm(prompt: &str) -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "denyx doctor --fix: stdin is not a TTY. Refusing to apply fixes \
             non-interactively to avoid surprising file mutations. \
             Re-run from an interactive terminal, or apply the equivalent \
             commands manually (see the report above)."
        );
        return false;
    }
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut response = String::new();
    if std::io::stdin().read_line(&mut response).is_err() {
        return false;
    }
    let r = response.trim().to_ascii_lowercase();
    r == "y" || r == "yes"
}

fn apply_fix(fix: &AutoFix, project_root: &Path) -> Result<String, String> {
    match &fix.action {
        FixAction::PrepareAuditDir => {
            let (dir_created, gi_updated) = crate::host_config::prepare_audit_dir(project_root)
                .map_err(|e| format!("prepare_audit_dir: {e}"))?;
            let mut parts = Vec::new();
            if dir_created {
                parts.push("created `.denyx/`".to_string());
            }
            if gi_updated {
                parts.push("updated `.gitignore`".to_string());
            }
            if parts.is_empty() {
                Ok("nothing to do (already in place)".to_string())
            } else {
                Ok(parts.join(", "))
            }
        }
        FixAction::RefreshHostConfig { hosts, policy_path } => {
            // Shell out to ourselves: same binary, host-config
            // subcommand. Honest and explicit — operator sees in
            // logs exactly which command was run.
            let denyx_bin =
                std::env::current_exe().map_err(|e| format!("locate current exe: {e}"))?;
            let host_list = hosts.join(",");
            let out = std::process::Command::new(&denyx_bin)
                .args([
                    "host-config",
                    "--policy",
                    policy_path
                        .to_str()
                        .ok_or("policy path is not valid UTF-8")?,
                    "--host",
                    &host_list,
                    "--existing",
                    "replace",
                    "--output-dir",
                    project_root
                        .to_str()
                        .ok_or("project root is not valid UTF-8")?,
                ])
                .output()
                .map_err(|e| format!("spawn `denyx host-config`: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "denyx host-config exit {:?}: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            Ok(format!(
                "regenerated host config(s) for [{host_list}] from policy {}",
                policy_path.display()
            ))
        }
    }
}

/// Render a unified report. Returns the string and the exit code
/// (0 / 1 / 2 mapping ok / warn / fail).
pub fn render(diagnosis: &ProjectDiagnosis, issues: &[ConsistencyIssue]) -> (String, i32) {
    let mut out = String::new();
    let mut worst: i32 = 0;

    out.push_str("denyx doctor\n");
    out.push_str(&format!("  project: {}\n\n", diagnosis.root.display()));

    // ── project_diagnosis section ────────────────────────────────
    render_project_section(&mut out, diagnosis, &mut worst);

    // ── consistency-checker section ──────────────────────────────
    if !issues.is_empty() {
        out.push_str("\nConsistency checks:\n");
        for issue in issues {
            let sev = issue.severity();
            let label = match issue {
                ConsistencyIssue::ToolUrlNotInNetworkAllow { .. } => "tool URL vs network",
                ConsistencyIssue::ToolDeclaresUnsupportedCapability { .. } => {
                    "tool capability vs policy"
                }
                ConsistencyIssue::RequiresApprovalBypassed { .. } => {
                    "requires_approval vs --confirm-mode"
                }
                ConsistencyIssue::ConflictingPolicyPaths { .. } => "conflicting policy paths",
                ConsistencyIssue::PolicyPathsDoNotExist { .. } => "declared paths missing",
                ConsistencyIssue::SubprocessCommandsNotOnPath { .. } => {
                    "commands not on doctor's PATH"
                }
                ConsistencyIssue::SandboxAllowedDomainsStale { .. } => {
                    "sandbox allowedDomains stale"
                }
                ConsistencyIssue::SandboxAllowWriteStale { .. } => "sandbox allowWrite stale",
            };
            match sev {
                Severity::Critical => {
                    write_block(&mut out, "FAIL", label, &issue.summary(), &issue.fix())
                }
                Severity::Warning => {
                    write_block(&mut out, "WARN", label, &issue.summary(), &issue.fix())
                }
                Severity::Info => {
                    write_block(&mut out, "INFO", label, &issue.summary(), &issue.fix())
                }
            }
            worst = worst.max(match sev {
                Severity::Critical => 2,
                Severity::Warning => 1,
                Severity::Info => 0,
            });
        }
    }

    out.push('\n');
    out.push_str(match worst {
        0 => "Ready: project setup looks consistent.\n",
        1 => "Usable, with caveats above. Apply the suggested fixes for stronger guarantees.\n",
        _ => "NOT ready. Apply the fixes above and re-run `denyx doctor`.\n",
    });

    (out, worst)
}

fn render_project_section(out: &mut String, p: &ProjectDiagnosis, worst: &mut i32) {
    // Policy.
    match &p.policy {
        PolicyCheck::Valid {
            name,
            capability_count,
            ..
        } => {
            let label = name.as_deref().unwrap_or("(unnamed)");
            write_ok(
                out,
                "denyx.toml",
                &format!("present, valid — '{label}' ({capability_count} capabilities)"),
            );
        }
        PolicyCheck::Missing => write_info(
            out,
            "denyx.toml",
            "absent — runtime falls back to secure-defaults baseline (deny all)",
            "Safe by design: every fs/net/subprocess/env call denies until you opt in.\n\
             To grant capabilities, run `denyx init --lang <python|node|rust|ruby|go>`.",
        ),
        PolicyCheck::Invalid { reason, .. } => write_fail(
            out,
            "denyx.toml",
            &format!("present but invalid: {reason}"),
            "Run `denyx policy validate ./denyx.toml` for the full diagnostic.",
            worst,
        ),
    }

    // Host-configs (informational from denyx's perspective; the
    // binary-specific doctors carry the per-host opinions).
    if p.host_configs.is_empty() {
        write_info(
            out,
            "host config",
            "no .mcp.json / opencode.json / .cursor/mcp.json / .vscode/settings.json / .continue/config.json in this project",
            "Run `denyx host-config --policy ./denyx.toml --host claude` to wire denyx-mcp as the project's MCP server. (Or set --host to opencode / cursor / copilot / continue / cline.)",
        );
    } else {
        for hc in &p.host_configs {
            let label = format!("{} ({})", hc.host.label(), hc.path.display());
            let denyx_count = hc
                .denyx_servers
                .iter()
                .filter(|s| matches!(s.flavor, DenyxFlavor::DenyxMcp | DenyxFlavor::DenyxLocalMcp))
                .count();
            if denyx_count == 0 {
                write_warn(
                    out,
                    &label,
                    "no Denyx-flavored MCP entry",
                    "Run `denyx host-config --policy ./denyx.toml` to wire denyx-mcp.",
                    worst,
                );
            } else {
                let names: Vec<String> = hc
                    .denyx_servers
                    .iter()
                    .filter(|s| {
                        matches!(s.flavor, DenyxFlavor::DenyxMcp | DenyxFlavor::DenyxLocalMcp)
                    })
                    .map(|s| {
                        let flavor = match s.flavor {
                            DenyxFlavor::DenyxMcp => "denyx-mcp",
                            DenyxFlavor::DenyxLocalMcp => "denyx-local-mcp",
                            _ => "(other)",
                        };
                        format!("{} ({})", s.name, flavor)
                    })
                    .collect();
                write_ok(out, &label, &format!("Denyx wired: {}", names.join(", ")));
            }
            // Lockdown state.
            match &hc.lockdown_state {
                LockdownState::Active => write_ok(
                    out,
                    &format!("  └─ {} lockdown", hc.host.label()),
                    "active",
                ),
                LockdownState::Partial { missing } => write_warn(
                    out,
                    &format!("  └─ {} lockdown", hc.host.label()),
                    &format!("partial — missing: {}", missing.join(", ")),
                    "Re-run `denyx host-config --existing replace --host <X>` to refresh.",
                    worst,
                ),
                LockdownState::Absent => write_warn(
                    out,
                    &format!("  └─ {} lockdown", hc.host.label()),
                    "no deny list configured",
                    "The host's built-in tools can bypass denyx-mcp. Run `denyx host-config --policy ./denyx.toml` to add the deny list.",
                    worst,
                ),
                LockdownState::NotApplicable => write_info(
                    out,
                    &format!("  └─ {} lockdown", hc.host.label()),
                    "no project-local deny mechanism on this host (UI-only)",
                    "",
                ),
            }
        }
    }

    // Audit dir.
    match &p.audit_dir {
        AuditDirCheck::Present { .. } => write_ok(out, ".denyx/", "audit dir present"),
        AuditDirCheck::Absent => write_info(
            out,
            ".denyx/",
            "audit dir not yet created (created on first run if --audit-log writes there)",
            "",
        ),
        AuditDirCheck::NotADirectory { path } => write_fail(
            out,
            ".denyx/",
            &format!(
                "{} exists but is a regular file, not a directory",
                path.display()
            ),
            "Remove the file and recreate as a directory: `rm .denyx && mkdir .denyx`.",
            worst,
        ),
    }

    // Gitignore.
    match &p.gitignore {
        GitignoreCheck::Excluded => write_ok(out, ".gitignore", "audit dir excluded"),
        GitignoreCheck::NotExcluded => write_warn(
            out,
            ".gitignore",
            ".denyx/ is not in .gitignore — audit logs may get committed",
            "Add `.denyx/` to your project's .gitignore.",
            worst,
        ),
        GitignoreCheck::Missing => write_info(
            out,
            ".gitignore",
            "no .gitignore in this project",
            "If this project uses git, add a .gitignore with `.denyx/`.",
        ),
    }
}

fn write_ok(out: &mut String, label: &str, msg: &str) {
    out.push_str(&format!("  [OK]   {label}: {msg}\n"));
}
fn write_info(out: &mut String, label: &str, msg: &str, fix: &str) {
    out.push_str(&format!("  [INFO] {label}: {msg}\n"));
    if !fix.is_empty() {
        for line in fix.lines() {
            out.push_str(&format!("         {line}\n"));
        }
    }
}
fn write_warn(out: &mut String, label: &str, msg: &str, fix: &str, worst: &mut i32) {
    out.push_str(&format!("  [WARN] {label}: {msg}\n"));
    for line in fix.lines() {
        out.push_str(&format!("         {line}\n"));
    }
    if *worst < 1 {
        *worst = 1;
    }
}
fn write_fail(out: &mut String, label: &str, msg: &str, fix: &str, worst: &mut i32) {
    out.push_str(&format!("  [FAIL] {label}: {msg}\n"));
    for line in fix.lines() {
        out.push_str(&format!("         {line}\n"));
    }
    *worst = 2;
}
fn write_block(out: &mut String, level: &str, label: &str, msg: &str, fix: &str) {
    out.push_str(&format!("  [{level}] {label}: {msg}\n"));
    for line in fix.lines() {
        out.push_str(&format!("         {line}\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use denyx_host::project_diagnosis::{HostConfigEntry, HostName};

    fn empty() -> ProjectDiagnosis {
        ProjectDiagnosis {
            root: PathBuf::from("/proj"),
            policy: PolicyCheck::Missing,
            host_configs: vec![],
            audit_dir: AuditDirCheck::Absent,
            gitignore: GitignoreCheck::Missing,
            claude_sandbox: None,
        }
    }

    #[test]
    fn render_empty_project_returns_zero_with_info_for_missing_pieces() {
        let (out, code) = render(&empty(), &[]);
        assert_eq!(code, 0);
        assert!(out.contains("[INFO] denyx.toml: absent"));
        assert!(out.contains("Safe by design"));
        assert!(out.contains("[INFO] host config"));
        assert!(out.contains("Ready"));
    }

    #[test]
    fn render_critical_consistency_issue_returns_two() {
        let issues = vec![ConsistencyIssue::ToolUrlNotInNetworkAllow {
            tool_name: "T".into(),
            host: "evil.com".into(),
            method: "GET".into(),
        }];
        let (out, code) = render(&empty(), &issues);
        assert_eq!(code, 2);
        assert!(out.contains("[FAIL] tool URL vs network"));
        assert!(out.contains("evil.com"));
        assert!(out.contains("Add the host"));
        assert!(out.contains("NOT ready"));
    }

    #[test]
    fn render_warning_returns_one() {
        let issues = vec![ConsistencyIssue::RequiresApprovalBypassed {
            host_config: "Claude (.mcp.json)".into(),
            approval_caps: vec!["fs.delete".into()],
        }];
        let (out, code) = render(&empty(), &issues);
        assert_eq!(code, 1);
        assert!(out.contains("[WARN] requires_approval"));
        assert!(out.contains("Usable, with caveats"));
    }

    #[test]
    fn render_info_only_does_not_bump_exit_code() {
        let issues = vec![ConsistencyIssue::PolicyPathsDoNotExist {
            entries: vec![("read_allow", "./missing.txt".into())],
        }];
        let (out, code) = render(&empty(), &issues);
        assert_eq!(code, 0);
        assert!(out.contains("[INFO] declared paths missing"));
        assert!(out.contains("Ready"));
    }

    #[test]
    fn render_lockdown_active_marked_ok() {
        let mut d = empty();
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from(".mcp.json"),
            host: HostName::Claude,
            denyx_servers: vec![],
            lockdown_state: LockdownState::Active,
        });
        let (out, _) = render(&d, &[]);
        assert!(
            out.contains("[OK]     Claude Code lockdown")
                || out.contains("[OK]   ") && out.contains("Claude Code lockdown")
        );
    }

    // ─────────────────── --fix planning tests ───────────────────

    fn empty_with_root(root: PathBuf) -> ProjectDiagnosis {
        ProjectDiagnosis {
            root,
            policy: PolicyCheck::Missing,
            host_configs: vec![],
            audit_dir: AuditDirCheck::Absent,
            gitignore: GitignoreCheck::Missing,
            claude_sandbox: None,
        }
    }

    #[test]
    fn plan_fixes_returns_empty_when_no_drift() {
        let mut d = empty_with_root(PathBuf::from("/proj"));
        d.audit_dir = AuditDirCheck::Present {
            path: PathBuf::from("/proj/.denyx"),
        };
        d.gitignore = GitignoreCheck::Excluded;
        let issues: Vec<ConsistencyIssue> = vec![];
        assert!(plan_fixes(&d, &issues).is_empty());
    }

    #[test]
    fn plan_fixes_adds_audit_dir_fix_when_dir_absent() {
        let d = empty_with_root(PathBuf::from("/proj"));
        let fixes = plan_fixes(&d, &[]);
        assert_eq!(fixes.len(), 1);
        assert!(matches!(fixes[0].action, FixAction::PrepareAuditDir));
        assert!(fixes[0].targets.iter().any(|p| p.ends_with(".denyx")));
    }

    #[test]
    fn plan_fixes_adds_audit_dir_fix_when_gitignore_does_not_exclude() {
        let mut d = empty_with_root(PathBuf::from("/proj"));
        d.audit_dir = AuditDirCheck::Present {
            path: PathBuf::from("/proj/.denyx"),
        };
        d.gitignore = GitignoreCheck::NotExcluded;
        let fixes = plan_fixes(&d, &[]);
        assert_eq!(fixes.len(), 1);
        match &fixes[0].action {
            FixAction::PrepareAuditDir => {}
            other => panic!("expected PrepareAuditDir, got {other:?}"),
        }
        // Reason should mention .gitignore.
        assert!(fixes[0].reasons.iter().any(|r| r.contains(".gitignore")));
    }

    #[test]
    fn plan_fixes_adds_host_config_refresh_for_sandbox_drift() {
        let mut d = empty_with_root(PathBuf::from("/proj"));
        d.audit_dir = AuditDirCheck::Present {
            path: PathBuf::from("/proj/.denyx"),
        };
        d.gitignore = GitignoreCheck::Excluded;
        d.policy = PolicyCheck::Valid {
            path: PathBuf::from("/proj/denyx.toml"),
            name: None,
            capability_count: 1,
        };
        let issues = vec![ConsistencyIssue::SandboxAllowedDomainsStale {
            missing_hosts: vec!["api.openai.com".into()],
        }];
        let fixes = plan_fixes(&d, &issues);
        assert_eq!(fixes.len(), 1);
        match &fixes[0].action {
            FixAction::RefreshHostConfig { hosts, policy_path } => {
                assert_eq!(hosts, &vec!["claude".to_string()]);
                assert_eq!(policy_path, &PathBuf::from("/proj/denyx.toml"));
            }
            other => panic!("expected RefreshHostConfig, got {other:?}"),
        }
    }

    #[test]
    fn plan_fixes_skips_refresh_when_policy_invalid() {
        let mut d = empty_with_root(PathBuf::from("/proj"));
        d.audit_dir = AuditDirCheck::Present {
            path: PathBuf::from("/proj/.denyx"),
        };
        d.gitignore = GitignoreCheck::Excluded;
        d.policy = PolicyCheck::Invalid {
            path: PathBuf::from("/proj/denyx.toml"),
            reason: "self-writable".into(),
        };
        let issues = vec![ConsistencyIssue::SandboxAllowedDomainsStale {
            missing_hosts: vec!["x.com".into()],
        }];
        // Refresh would re-read denyx.toml, but it's invalid — can't fix.
        let fixes = plan_fixes(&d, &issues);
        assert!(
            fixes.is_empty(),
            "should not propose refresh when policy is invalid: {fixes:?}"
        );
    }

    #[test]
    fn plan_fixes_collects_lockdown_drift_per_host() {
        let mut d = empty_with_root(PathBuf::from("/proj"));
        d.audit_dir = AuditDirCheck::Present {
            path: PathBuf::from("/proj/.denyx"),
        };
        d.gitignore = GitignoreCheck::Excluded;
        d.policy = PolicyCheck::Valid {
            path: PathBuf::from("/proj/denyx.toml"),
            name: None,
            capability_count: 1,
        };
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from("/proj/.mcp.json"),
            host: HostName::Claude,
            denyx_servers: vec![],
            lockdown_state: LockdownState::Absent,
        });
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from("/proj/opencode.json"),
            host: HostName::Opencode,
            denyx_servers: vec![],
            lockdown_state: LockdownState::Partial {
                missing: vec!["bash".into(), "read".into()],
            },
        });
        let fixes = plan_fixes(&d, &[]);
        assert_eq!(fixes.len(), 1);
        match &fixes[0].action {
            FixAction::RefreshHostConfig { hosts, .. } => {
                assert!(hosts.contains(&"claude".to_string()));
                assert!(hosts.contains(&"opencode".to_string()));
                assert_eq!(hosts.len(), 2);
            }
            other => panic!("expected RefreshHostConfig, got {other:?}"),
        }
    }

    #[test]
    fn non_fixable_issues_filters_out_sandbox_drift() {
        let issues = vec![
            ConsistencyIssue::SandboxAllowedDomainsStale {
                missing_hosts: vec!["a".into()],
            },
            ConsistencyIssue::ToolUrlNotInNetworkAllow {
                tool_name: "X".into(),
                host: "y".into(),
                method: "GET".into(),
            },
            ConsistencyIssue::SandboxAllowWriteStale {
                missing_paths: vec!["/p".into()],
            },
            ConsistencyIssue::ConflictingPolicyPaths {
                paths: vec![("a".into(), "b".into())],
            },
        ];
        let nf = non_fixable_issues(&issues);
        // Only the two non-sandbox issues remain.
        assert_eq!(nf.len(), 2);
        for issue in nf {
            assert!(!matches!(
                issue,
                ConsistencyIssue::SandboxAllowedDomainsStale { .. }
                    | ConsistencyIssue::SandboxAllowWriteStale { .. }
            ));
        }
    }

    #[test]
    fn render_fix_plan_lists_actions_targets_and_non_fixable_issues() {
        let fixes = vec![AutoFix {
            label: "Test fix".into(),
            targets: vec![PathBuf::from("/proj/.denyx")],
            reasons: vec!["audit dir missing".into()],
            action: FixAction::PrepareAuditDir,
        }];
        let issue = ConsistencyIssue::ToolUrlNotInNetworkAllow {
            tool_name: "API".into(),
            host: "evil.com".into(),
            method: "GET".into(),
        };
        let nf: Vec<&ConsistencyIssue> = vec![&issue];
        let s = render_fix_plan(&fixes, &nf);
        assert!(s.contains("Auto-fixable changes (1 action)"));
        assert!(s.contains("1. Test fix"));
        assert!(s.contains("target: /proj/.denyx"));
        assert!(s.contains("reason: audit dir missing"));
        assert!(s.contains("Issues that require operator decision"));
        assert!(s.contains("evil.com"));
    }

    #[test]
    fn summarise_list_truncates_with_ellipsis() {
        let items: Vec<String> = (1..=10).map(|i| format!("item{i}")).collect();
        let s = summarise_list(&items, 3);
        assert!(s.starts_with("item1, item2, item3, …(+7 more)"));
    }

    #[test]
    fn summarise_list_does_not_truncate_when_under_head() {
        let items = vec!["a".to_string(), "b".to_string()];
        assert_eq!(summarise_list(&items, 5), "a, b");
    }

    // ─────────────────── apply_fix tests ───────────────────
    //
    // Cover the actual apply path that integration tests can't
    // reach (they refuse non-TTY stdin). PrepareAuditDir is pure
    // filesystem I/O against a tempdir, so it tests cleanly.
    // RefreshHostConfig shells out to `denyx` so we don't unit-
    // test it (the seam is the subprocess); its planning logic
    // is covered by plan_fixes tests above.

    fn fix_tempdir(label: &str) -> PathBuf {
        // CARGO_BIN_EXE_<name> is only set for integration tests
        // under tests/, not for unit tests inside the bin itself.
        // std::env::temp_dir() is fine here: prepare_audit_dir
        // doesn't touch denyx.toml or trip the self-writable guard.
        let p = std::env::temp_dir().join(format!(
            "denyx_doctor_fix_{label}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn apply_fix_prepare_audit_dir_creates_dir_and_gitignore() {
        let tmp = fix_tempdir("apply_audit_fresh");
        let fix = AutoFix {
            label: "test".into(),
            targets: vec![],
            reasons: vec![],
            action: FixAction::PrepareAuditDir,
        };
        let result = apply_fix(&fix, &tmp).expect("apply should succeed");
        assert!(result.contains("created `.denyx/`"));
        assert!(result.contains("updated `.gitignore`"));
        assert!(tmp.join(".denyx").is_dir());
        let gi = std::fs::read_to_string(tmp.join(".gitignore")).unwrap();
        assert!(gi.contains(".denyx/"));
    }

    #[test]
    fn apply_fix_prepare_audit_dir_is_idempotent_when_already_present() {
        let tmp = fix_tempdir("apply_audit_idem");
        std::fs::create_dir_all(tmp.join(".denyx")).unwrap();
        std::fs::write(tmp.join(".gitignore"), ".denyx/\n").unwrap();
        let fix = AutoFix {
            label: "test".into(),
            targets: vec![],
            reasons: vec![],
            action: FixAction::PrepareAuditDir,
        };
        let result = apply_fix(&fix, &tmp).expect("apply should succeed");
        // Already-present case: function returns "nothing to do".
        assert!(
            result.contains("nothing to do") || result.is_empty(),
            "got: {result}"
        );
    }

    #[test]
    fn apply_fix_prepare_audit_dir_appends_to_existing_gitignore() {
        let tmp = fix_tempdir("apply_audit_existing_gi");
        std::fs::write(tmp.join(".gitignore"), "target/\n").unwrap();
        let fix = AutoFix {
            label: "test".into(),
            targets: vec![],
            reasons: vec![],
            action: FixAction::PrepareAuditDir,
        };
        apply_fix(&fix, &tmp).expect("apply should succeed");
        let gi = std::fs::read_to_string(tmp.join(".gitignore")).unwrap();
        assert!(gi.contains("target/"), "should preserve existing entry");
        assert!(gi.contains(".denyx/"), "should add denyx entry");
    }

    // ─────────────────── plan_fixes coverage gaps ───────────────────

    #[test]
    fn plan_fixes_handles_sandbox_allow_write_stale() {
        let mut d = empty_with_root(PathBuf::from("/proj"));
        d.audit_dir = AuditDirCheck::Present {
            path: PathBuf::from("/proj/.denyx"),
        };
        d.gitignore = GitignoreCheck::Excluded;
        d.policy = PolicyCheck::Valid {
            path: PathBuf::from("/proj/denyx.toml"),
            name: None,
            capability_count: 1,
        };
        let issues = vec![ConsistencyIssue::SandboxAllowWriteStale {
            missing_paths: vec!["/var/log/myapp".into(), "/opt/cache".into()],
        }];
        let fixes = plan_fixes(&d, &issues);
        assert_eq!(fixes.len(), 1);
        match &fixes[0].action {
            FixAction::RefreshHostConfig { hosts, .. } => {
                assert_eq!(hosts, &vec!["claude".to_string()]);
            }
            other => panic!("expected RefreshHostConfig, got {other:?}"),
        }
        assert!(fixes[0]
            .reasons
            .iter()
            .any(|r| r.contains("path(s) missing from sandbox.allowWrite")));
    }

    #[test]
    fn plan_fixes_collects_lockdown_drift_for_cursor_copilot_continue() {
        let mut d = empty_with_root(PathBuf::from("/proj"));
        d.audit_dir = AuditDirCheck::Present {
            path: PathBuf::from("/proj/.denyx"),
        };
        d.gitignore = GitignoreCheck::Excluded;
        d.policy = PolicyCheck::Valid {
            path: PathBuf::from("/proj/denyx.toml"),
            name: None,
            capability_count: 1,
        };
        for (path, host) in [
            (".cursor/mcp.json", HostName::Cursor),
            (".vscode/settings.json", HostName::Copilot),
            (".continue/config.json", HostName::Continue),
        ] {
            d.host_configs.push(HostConfigEntry {
                path: PathBuf::from(format!("/proj/{path}")),
                host,
                denyx_servers: vec![],
                lockdown_state: LockdownState::Absent,
            });
        }
        let fixes = plan_fixes(&d, &[]);
        assert_eq!(fixes.len(), 1);
        match &fixes[0].action {
            FixAction::RefreshHostConfig { hosts, .. } => {
                assert!(hosts.contains(&"cursor".to_string()));
                assert!(hosts.contains(&"copilot".to_string()));
                assert!(hosts.contains(&"continue".to_string()));
                assert_eq!(hosts.len(), 3);
            }
            other => panic!("expected RefreshHostConfig, got {other:?}"),
        }
    }

    #[test]
    fn plan_fixes_combines_audit_dir_and_host_config_fixes() {
        // Both kinds of drift simultaneously → two distinct AutoFix
        // entries (one PrepareAuditDir + one RefreshHostConfig).
        let mut d = empty_with_root(PathBuf::from("/proj"));
        // audit_dir + gitignore drift left as default Absent / Missing.
        d.policy = PolicyCheck::Valid {
            path: PathBuf::from("/proj/denyx.toml"),
            name: None,
            capability_count: 1,
        };
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from("/proj/.mcp.json"),
            host: HostName::Claude,
            denyx_servers: vec![],
            lockdown_state: LockdownState::Absent,
        });
        let fixes = plan_fixes(&d, &[]);
        assert_eq!(fixes.len(), 2);
        assert!(fixes
            .iter()
            .any(|f| matches!(f.action, FixAction::PrepareAuditDir)));
        assert!(fixes
            .iter()
            .any(|f| matches!(f.action, FixAction::RefreshHostConfig { .. })));
    }
}
