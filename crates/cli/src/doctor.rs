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

use std::path::PathBuf;

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

    let diagnosis = project_diagnosis::diagnose(&project_path);

    // Load policy if present + valid; only then can the
    // consistency-checker run its policy-side checks.
    let loaded_policy: Option<Policy> = match &diagnosis.policy {
        PolicyCheck::Valid { path, .. } => Policy::load(path).ok(),
        _ => None,
    };
    let issues = policy_host_consistency::check(loaded_policy.as_ref(), &diagnosis);

    let (out, code) = render(&diagnosis, &issues);
    print!("{out}");
    code
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
                ConsistencyIssue::PolicyPathDoesNotExist { .. } => "declared path missing",
                ConsistencyIssue::SubprocessCommandNotOnPath { .. } => "command not on PATH",
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
        let issues = vec![ConsistencyIssue::PolicyPathDoesNotExist {
            section: "[filesystem].read_allow",
            path: "./missing.txt".into(),
        }];
        let (out, code) = render(&empty(), &issues);
        assert_eq!(code, 0);
        assert!(out.contains("[INFO] declared path missing"));
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
}
