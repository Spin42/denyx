//! `denyx-mcp doctor` — read-only project preflight.
//!
//! Inspects a project root and reports on the policy file, host-
//! config wiring, audit-dir setup, and `.gitignore` exclusion. Prints
//! copy-pasteable next-steps; never auto-fixes.
//!
//! Interpretation specific to `denyx-mcp` (the standalone gate):
//!
//! - A host-config wiring `denyx-mcp` directly is OK (this is the
//!   standalone shape the gate is named for).
//! - A host-config wiring `denyx-local-mcp` is also OK — that's the
//!   local-executor bridge, which spawns `denyx-mcp` as its child.
//!   Reported as INFO.
//! - A host-config with no Denyx binary wired anywhere is a WARN:
//!   the project has host-configs but the policy gate isn't engaged.
//! - Missing `denyx.toml` is INFO (not failure): the runtime falls
//!   back to the secure-defaults deny-all baseline. Safe by design.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use denyx_host::project_diagnosis::{
    self, AuditDirCheck, DenyxFlavor, GitignoreCheck, LockdownState, PolicyCheck, ProjectDiagnosis,
};

#[derive(Parser, Debug)]
pub struct DoctorArgs {
    /// Project root to inspect for `denyx.toml`, host-config files,
    /// and audit-dir setup. Defaults to the current working
    /// directory; pass a different path if running doctor from
    /// somewhere other than the project root.
    #[arg(long)]
    pub project_path: Option<PathBuf>,
}

pub fn run(args: DoctorArgs) -> ExitCode {
    let project_path = args
        .project_path
        .clone()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
        });
    let project_path = match project_path {
        Some(p) => p,
        None => {
            eprintln!("denyx-mcp doctor: cannot determine project path");
            return ExitCode::from(2);
        }
    };
    let diag = project_diagnosis::diagnose(&project_path);
    let (out, code) = render(&diag);
    print!("{out}");
    ExitCode::from(code as u8)
}

/// Render a [`ProjectDiagnosis`] from `denyx-mcp`'s perspective.
/// Returns the rendered string and the exit-code level
/// (0 ok / 1 warn / 2 fail).
pub fn render(p: &ProjectDiagnosis) -> (String, i32) {
    let mut out = String::new();
    let mut worst: i32 = 0;

    out.push_str("denyx-mcp doctor\n");
    out.push_str(&format!("  project: {}\n\n", p.root.display()));

    // Policy.
    match &p.policy {
        PolicyCheck::Valid {
            name,
            capability_count,
            ..
        } => {
            let label = name.as_deref().unwrap_or("(unnamed)");
            write_ok(
                &mut out,
                "denyx.toml",
                &format!("present, valid — '{label}' ({capability_count} capabilities)"),
            );
        }
        PolicyCheck::Missing => write_info(
            &mut out,
            "denyx.toml",
            "absent — runtime falls back to secure-defaults baseline (deny all)",
            "Safe by design: every fs / net / subprocess / env call denies until you opt in.\n\
             To grant capabilities, generate a starter policy: `denyx init --lang <lang>`.",
        ),
        PolicyCheck::Invalid { reason, .. } => write_fail(
            &mut out,
            "denyx.toml",
            &format!("present but invalid: {reason}"),
            "Run `denyx policy validate ./denyx.toml` for the full diagnostic.",
            &mut worst,
        ),
    }

    // Host-config wiring.
    if p.host_configs.is_empty() {
        write_info(
            &mut out,
            "host config",
            "no .mcp.json / opencode.json / .cursor/mcp.json / .vscode/settings.json / .continue/config.json in this project",
            "Run `denyx host-config --policy ./denyx.toml --host claude` (or the setup prompt) to wire denyx-mcp as the project's MCP server.",
        );
    } else {
        for hc in &p.host_configs {
            let label = format!("{} ({})", hc.host.label(), hc.path.display());
            let mcp_servers: Vec<&_> = hc
                .denyx_servers
                .iter()
                .filter(|s| s.flavor == DenyxFlavor::DenyxMcp)
                .collect();
            let local_servers: Vec<&_> = hc
                .denyx_servers
                .iter()
                .filter(|s| s.flavor == DenyxFlavor::DenyxLocalMcp)
                .collect();

            if !mcp_servers.is_empty() {
                let names: Vec<&str> = mcp_servers.iter().map(|s| s.name.as_str()).collect();
                let wrappers: Vec<&str> = mcp_servers
                    .iter()
                    .filter_map(|s| s.via_wrapper.as_ref())
                    .map(|w| match w {
                        project_diagnosis::PlatformWrapper::Lima => "lima",
                        project_diagnosis::PlatformWrapper::Wsl => "wsl",
                    })
                    .collect();
                let detail = if wrappers.is_empty() {
                    format!("denyx-mcp wired (entries: {})", names.join(", "))
                } else {
                    format!(
                        "denyx-mcp wired via {} (entries: {})",
                        wrappers.join(", "),
                        names.join(", ")
                    )
                };
                write_ok(&mut out, &label, &detail);
            } else if !local_servers.is_empty() {
                // Local-executor shape: denyx-mcp runs as a child of
                // denyx-local-mcp. Still gated, just nested.
                let names: Vec<&str> = local_servers.iter().map(|s| s.name.as_str()).collect();
                write_info(
                    &mut out,
                    &label,
                    &format!(
                        "denyx-local-mcp wired (entries: {}); denyx-mcp runs as a child",
                        names.join(", ")
                    ),
                    "Local-executor shape: cloud orchestrator → denyx-local-mcp → denyx-mcp (this binary). Policy gate is engaged at the bridge's back end.",
                );
            } else if !hc.denyx_servers.is_empty() {
                let names: Vec<&str> = hc.denyx_servers.iter().map(|s| s.name.as_str()).collect();
                write_warn(
                    &mut out,
                    &label,
                    &format!(
                        "MCP entries present but no Denyx binary wired (names: {})",
                        names.join(", ")
                    ),
                    "If one of these IS supposed to be Denyx, check the command path.",
                    &mut worst,
                );
            } else {
                write_warn(
                    &mut out,
                    &label,
                    "no MCP server entries in this file",
                    "The project has a host-config but no MCP server wired. Run `denyx host-config --policy ./denyx.toml` to add denyx-mcp.",
                    &mut worst,
                );
            }

            // Lockdown state.
            match &hc.lockdown_state {
                LockdownState::Active => write_ok(
                    &mut out,
                    &format!("  └─ {} lockdown", hc.host.label()),
                    "active — built-in deny list in place",
                ),
                LockdownState::Partial { missing } => write_warn(
                    &mut out,
                    &format!("  └─ {} lockdown", hc.host.label()),
                    &format!("partial — missing deny entries for: {}", missing.join(", ")),
                    "Re-run `denyx host-config --existing replace` to refresh the deny list. Without a complete deny list, the model can route around denyx-mcp via the host's built-in tools.",
                    &mut worst,
                ),
                LockdownState::Absent => write_warn(
                    &mut out,
                    &format!("  └─ {} lockdown", hc.host.label()),
                    "no deny list configured",
                    "The host's built-in tools (Bash/Read/Edit/Write/etc.) are still available — the model can bypass denyx-mcp by using them. Run `denyx host-config --policy ./denyx.toml` to add the deny list.",
                    &mut worst,
                ),
                LockdownState::NotApplicable => write_info(
                    &mut out,
                    &format!("  └─ {} lockdown", hc.host.label()),
                    "no project-local deny mechanism on this host (UI-only)",
                    "Disable the host's built-in tools via the host's UI to fully gate the model through denyx-mcp.",
                ),
            }
        }
    }

    // Audit dir.
    match &p.audit_dir {
        AuditDirCheck::Present { .. } => write_ok(&mut out, ".denyx/", "audit dir present"),
        AuditDirCheck::Absent => write_info(
            &mut out,
            ".denyx/",
            "audit dir not yet created (will be created on first run if --audit-log writes there)",
            "",
        ),
        AuditDirCheck::NotADirectory { path } => write_fail(
            &mut out,
            ".denyx/",
            &format!(
                "{} exists but is a regular file, not a directory",
                path.display()
            ),
            "Remove the file and recreate as a directory: `rm .denyx && mkdir .denyx`.",
            &mut worst,
        ),
    }

    // Gitignore.
    match &p.gitignore {
        GitignoreCheck::Excluded => write_ok(&mut out, ".gitignore", "audit dir excluded"),
        GitignoreCheck::NotExcluded => write_warn(
            &mut out,
            ".gitignore",
            ".denyx/ is not in .gitignore — audit logs may get committed",
            "Add `.denyx/` to your project's .gitignore.",
            &mut worst,
        ),
        GitignoreCheck::Missing => write_info(
            &mut out,
            ".gitignore",
            "no .gitignore in this project",
            "If this project uses git, add a .gitignore with `.denyx/` to keep audit logs out of commits.",
        ),
    }

    out.push('\n');
    out.push_str(match worst {
        0 => "Ready: project is wired correctly for denyx-mcp.\n",
        1 => "Usable, but with caveats above. Apply the suggested fixes for stronger guarantees.\n",
        _ => "NOT ready. Apply the fixes above and re-run `denyx-mcp doctor`.\n",
    });

    (out, worst)
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

#[cfg(test)]
mod tests {
    use super::*;
    use denyx_host::project_diagnosis::{
        DetectedDenyxServer, HostConfigEntry, HostName, ProjectDiagnosis,
    };
    use std::path::PathBuf;

    fn empty_diag() -> ProjectDiagnosis {
        ProjectDiagnosis {
            root: PathBuf::from("/some/project"),
            policy: PolicyCheck::Missing,
            host_configs: vec![],
            audit_dir: AuditDirCheck::Absent,
            gitignore: GitignoreCheck::Missing,
            claude_sandbox: None,
        }
    }

    #[test]
    fn render_no_files_is_info_not_failure_and_exits_zero() {
        let d = empty_diag();
        let (out, code) = render(&d);
        assert_eq!(code, 0, "missing files alone shouldn't fail. out:\n{out}");
        assert!(out.contains("[INFO] denyx.toml: absent"));
        assert!(out.contains("secure-defaults baseline"));
        assert!(out.contains("Safe by design"));
        assert!(out.contains("Ready"));
    }

    #[test]
    fn render_warns_when_lockdown_absent_on_claude() {
        let mut d = empty_diag();
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from(".mcp.json"),
            host: HostName::Claude,
            denyx_servers: vec![DetectedDenyxServer {
                name: "denyx".into(),
                flavor: DenyxFlavor::DenyxMcp,
                command: "denyx-mcp".into(),
                args: vec![],
                via_wrapper: None,
            }],
            lockdown_state: LockdownState::Absent,
        });
        let (out, code) = render(&d);
        assert_eq!(code, 1);
        assert!(out.contains("[OK]   Claude Code"));
        assert!(out.contains("denyx-mcp wired"));
        assert!(out.contains("[WARN]"));
        assert!(out.contains("no deny list configured"));
    }

    #[test]
    fn render_info_when_local_executor_shape_is_used() {
        let mut d = empty_diag();
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from(".mcp.json"),
            host: HostName::Claude,
            denyx_servers: vec![DetectedDenyxServer {
                name: "local-executor".into(),
                flavor: DenyxFlavor::DenyxLocalMcp,
                command: "denyx-local-mcp".into(),
                args: vec![],
                via_wrapper: None,
            }],
            lockdown_state: LockdownState::Active,
        });
        let (out, code) = render(&d);
        assert_eq!(code, 0);
        assert!(out.contains("[INFO]"));
        assert!(out.contains("denyx-local-mcp wired"));
        assert!(out.contains("Local-executor shape"));
    }

    #[test]
    fn render_fails_on_invalid_policy() {
        let mut d = empty_diag();
        d.policy = PolicyCheck::Invalid {
            path: PathBuf::from("denyx.toml"),
            reason: "self-writable".into(),
        };
        let (out, code) = render(&d);
        assert_eq!(code, 2);
        assert!(out.contains("[FAIL] denyx.toml"));
        assert!(out.contains("NOT ready"));
    }

    #[test]
    fn render_via_wrapper_label_includes_lima() {
        let mut d = empty_diag();
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from(".mcp.json"),
            host: HostName::Claude,
            denyx_servers: vec![DetectedDenyxServer {
                name: "denyx".into(),
                flavor: DenyxFlavor::DenyxMcp,
                command: "denyx-mcp".into(),
                args: vec![],
                via_wrapper: Some(project_diagnosis::PlatformWrapper::Lima),
            }],
            lockdown_state: LockdownState::Active,
        });
        let (out, _code) = render(&d);
        assert!(out.contains("denyx-mcp wired via lima"));
    }

    #[test]
    fn render_via_wrapper_label_includes_wsl() {
        let mut d = empty_diag();
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from(".mcp.json"),
            host: HostName::Claude,
            denyx_servers: vec![DetectedDenyxServer {
                name: "denyx".into(),
                flavor: DenyxFlavor::DenyxMcp,
                command: "denyx-mcp".into(),
                args: vec![],
                via_wrapper: Some(project_diagnosis::PlatformWrapper::Wsl),
            }],
            lockdown_state: LockdownState::Active,
        });
        let (out, _code) = render(&d);
        assert!(out.contains("denyx-mcp wired via wsl"));
    }

    #[test]
    fn render_valid_policy_shows_name_and_capability_count() {
        let mut d = empty_diag();
        d.policy = PolicyCheck::Valid {
            path: PathBuf::from("/proj/denyx.toml"),
            name: Some("my-project".to_string()),
            capability_count: 7,
        };
        let (out, code) = render(&d);
        assert_eq!(code, 0);
        assert!(out.contains("[OK]   denyx.toml"));
        assert!(out.contains("'my-project'"));
        assert!(out.contains("(7 capabilities)"));
    }

    #[test]
    fn render_warn_when_host_config_has_mcp_entry_but_no_denyx_binary() {
        let mut d = empty_diag();
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from(".mcp.json"),
            host: HostName::Claude,
            denyx_servers: vec![DetectedDenyxServer {
                name: "github".into(),
                // Some other tool the host-config wires — not Denyx.
                flavor: DenyxFlavor::Other("github-mcp".to_string()),
                command: "github-mcp".into(),
                args: vec![],
                via_wrapper: None,
            }],
            lockdown_state: LockdownState::Absent,
        });
        let (out, code) = render(&d);
        // Worst is WARN (missing denyx wiring + lockdown absent).
        assert_eq!(code, 1);
        assert!(out.contains("MCP entries present but no Denyx binary wired"));
        assert!(out.contains("github"));
    }

    #[test]
    fn render_warn_when_host_config_file_has_no_mcp_entries_at_all() {
        let mut d = empty_diag();
        d.host_configs.push(HostConfigEntry {
            path: PathBuf::from("opencode.json"),
            host: HostName::Opencode,
            denyx_servers: vec![],
            lockdown_state: LockdownState::Active,
        });
        let (out, code) = render(&d);
        assert_eq!(code, 1);
        assert!(out.contains("no MCP server entries in this file"));
    }
}
