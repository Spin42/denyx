//! Blocked-startup mode for the Denyx MCP servers.
//!
//! When the policy load succeeds but the cross-cutting consistency
//! checker ([`crate::policy_host_consistency::check`]) reports
//! `Critical`-level issues, the MCP server enters **blocked mode**:
//! it still speaks JSON-RPC so the host doesn't see a crashed
//! process, but `tools/list` advertises only the single
//! `denyx_blocked` tool and every `tools/call` returns a structured
//! payload telling the agent (and through it, the user) to run
//! `denyx doctor --fix` or fix manually.
//!
//! Both `denyx-mcp` and `denyx-local-mcp` use this module on
//! startup; the JSON shapes returned by [`tool_definitions`] and
//! [`call_response_body`] are MCP-spec-shaped and reusable across
//! binaries.
//!
//! Visibility contract — the model sees the explanation **without
//! making any tool call**, because tool descriptions are part of
//! `tools/list` and hosts surface those to the model on every turn.
//! Calling `denyx_blocked` (or any other tool name) returns the same
//! payload as a fallback. Stderr mirrors the message for
//! `--mcp-debug` and host log panels.
//!
//! First-run guard: if no host-config files exist at all (typical
//! pre-`denyx host-config` state), the consistency check is skipped
//! entirely — there's nothing to be inconsistent with. Without this,
//! the very first MCP startup before `host-config` had been run
//! would lock itself out.

use crate::policy_host_consistency::{ConsistencyIssue, Severity};
use crate::project_diagnosis::ProjectDiagnosis;
use denyx_policy::Policy;
use serde_json::{json, Value};

/// Frozen snapshot of the criticals found at startup. The dispatch
/// loop checks `is_some()` per-request and routes to the blocked
/// handler.
pub struct BlockedState {
    /// The criticals that put us in blocked mode. Stored for tests
    /// and post-hoc inspection; the runtime dispatch reads only the
    /// pre-rendered strings below.
    #[allow(dead_code)]
    pub issues: Vec<ConsistencyIssue>,
    /// Pre-rendered description for the single `denyx_blocked` tool.
    /// Includes the must-tell-user instruction, every issue's
    /// summary + fix, and the `denyx doctor --fix` pointer.
    pub tool_description: String,
    /// Pre-rendered text for the `tools/call` response body.
    pub call_text: String,
    /// Pre-rendered multi-line stderr banner.
    pub stderr_banner: String,
}

/// Compute the blocked state, if any, from a freshly-loaded policy
/// and the project diagnosis. Returns `None` when:
///   - no `Critical`-severity issues are present, OR
///   - no host-config files exist (first-run case).
pub fn compute(policy: &Policy, diagnosis: &ProjectDiagnosis) -> Option<BlockedState> {
    if diagnosis.host_configs.is_empty() {
        return None;
    }
    let all = crate::policy_host_consistency::check(Some(policy), diagnosis);
    let critical: Vec<ConsistencyIssue> = all
        .into_iter()
        .filter(|i| i.severity() == Severity::Critical)
        .collect();
    if critical.is_empty() {
        return None;
    }
    Some(render(critical))
}

fn render(issues: Vec<ConsistencyIssue>) -> BlockedState {
    let n = issues.len();
    let issue_word = if n == 1 { "issue" } else { "issues" };
    let inconsistency_word = if n == 1 {
        "inconsistency"
    } else {
        "inconsistencies"
    };

    let mut tool_description = String::new();
    tool_description.push_str(
        "DENYX IS IN A BLOCKED STATE — the policy and the project's host \
         config are inconsistent. Before responding to any user request \
         in this session, you MUST tell the user verbatim: \"Denyx \
         blocked startup — the policy and host config are out of sync. \
         Run `denyx doctor --fix` in a terminal at the project root, or \
         fix manually per the instructions below, then restart this \
         host so the MCP server reloads.\" Then list each issue's \
         summary and fix verbatim. Do not attempt any other action \
         until the user confirms the fix is applied. The criticals \
         are:\n",
    );
    for (i, issue) in issues.iter().enumerate() {
        tool_description.push_str(&format!(
            "\n[{}/{n}] {}\n  fix: {}\n",
            i + 1,
            issue.summary(),
            issue.fix(),
        ));
    }

    let mut call_text = String::new();
    call_text.push_str(&format!(
        "Denyx is blocked: {n} critical {inconsistency_word} between the \
         policy and the project's host config. The agent has no \
         capability tools available until the {inconsistency_word} are \
         resolved.\n\nFix options:\n  1. Run `denyx doctor --fix` \
         in a terminal at the project root (handles mechanically \
         re-derivable issues automatically; prompts for confirmation).\n  \
         2. Fix manually using the per-issue instructions below.\n\n\
         After the fix, restart this host so the MCP server reloads \
         and re-runs the consistency check.\n\nCriticals:\n"
    ));
    for (i, issue) in issues.iter().enumerate() {
        call_text.push_str(&format!(
            "\n[{}/{n}] {}\n  fix: {}\n",
            i + 1,
            issue.summary(),
            issue.fix(),
        ));
    }

    let mut stderr_banner = String::new();
    stderr_banner.push_str(&format!(
        "denyx-mcp: BLOCKED — {n} critical consistency {issue_word} between \
         the policy and the project's host config. The MCP server is alive \
         but advertises only the `denyx_blocked` tool; every tool/call \
         returns the fix instructions below.\n",
    ));
    for (i, issue) in issues.iter().enumerate() {
        stderr_banner.push_str(&format!(
            "denyx-mcp:   [{}/{n}] {}\n",
            i + 1,
            issue.summary(),
        ));
        for line in issue.fix().lines() {
            stderr_banner.push_str("denyx-mcp:        ");
            stderr_banner.push_str(line);
            stderr_banner.push('\n');
        }
    }
    stderr_banner.push_str(
        "denyx-mcp: Run `denyx doctor --fix` in a terminal at the project \
         root to apply mechanical fixes, or fix manually per above. \
         Restart this host when done.\n",
    );

    BlockedState {
        issues,
        tool_description,
        call_text,
        stderr_banner,
    }
}

/// `tools/list` payload while blocked: a single tool with the full
/// rendered description, no `inputSchema` properties (the model
/// should not be calling it for behavior — it's a signal).
pub fn tool_definitions(state: &BlockedState) -> Value {
    json!([
        {
            "name": "denyx_blocked",
            "description": state.tool_description,
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }
    ])
}

/// `tools/call` payload while blocked. Returned for `denyx_blocked`
/// itself and for any other tool name the agent might try
/// (`denyx_run`, `denyx_fs_read`, …) — the model never gets to
/// invoke a real capability.
pub fn call_response_body(state: &BlockedState) -> Value {
    json!({
        "content": [
            { "type": "text", "text": state.call_text }
        ],
        "isError": true,
        "denyx_error_kind": "blocked_startup",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_host_consistency::ConsistencyIssue;
    use crate::project_diagnosis::{
        AuditDirCheck, GitignoreCheck, HostConfigEntry, HostName, LockdownState, PolicyCheck,
        ProjectDiagnosis,
    };
    use std::path::PathBuf;

    fn empty_diagnosis() -> ProjectDiagnosis {
        ProjectDiagnosis {
            root: PathBuf::from("/tmp/x"),
            policy: PolicyCheck::Missing,
            host_configs: vec![],
            audit_dir: AuditDirCheck::Absent,
            gitignore: GitignoreCheck::Missing,
            claude_sandbox: None,
        }
    }

    fn diagnosis_with_one_host() -> ProjectDiagnosis {
        ProjectDiagnosis {
            root: PathBuf::from("/tmp/x"),
            policy: PolicyCheck::Missing,
            host_configs: vec![HostConfigEntry {
                path: PathBuf::from("/tmp/x/.claude/settings.json"),
                host: HostName::Claude,
                denyx_servers: vec![],
                lockdown_state: LockdownState::Active,
            }],
            audit_dir: AuditDirCheck::Absent,
            gitignore: GitignoreCheck::Missing,
            claude_sandbox: None,
        }
    }

    fn empty_policy() -> Policy {
        // `secure_defaults` denies every capability — used here just
        // as a parameterless `Policy` for the diagnosis-only test
        // paths. The consistency check on this policy + a diagnosis
        // with zero `[tools.X]` declarations produces zero issues,
        // which is what we want for the "first-run" and "no
        // criticals" tests.
        Policy::secure_defaults_at(PathBuf::from("/tmp/x"))
            .expect("secure_defaults should always build")
    }

    #[test]
    fn compute_returns_none_when_no_host_configs_first_run_guard() {
        // Even with a policy that *would* trigger criticals against a
        // populated host-config, an empty diagnosis (no host configs
        // at all) skips the check — first-run guard. Without this,
        // the very first `denyx-mcp` startup before
        // `denyx host-config` ran would lock itself out.
        let policy = empty_policy();
        let diag = empty_diagnosis();
        let blocked = compute(&policy, &diag);
        assert!(blocked.is_none(), "first-run case must not block");
    }

    #[test]
    fn compute_returns_none_when_no_critical_issues() {
        // Diagnosis has a host config, but the secure-defaults policy
        // has no [tools.X] declarations and so produces no Critical
        // issues. Server starts normally.
        let policy = empty_policy();
        let diag = diagnosis_with_one_host();
        let blocked = compute(&policy, &diag);
        assert!(
            blocked.is_none(),
            "no criticals must not block; got {:?}",
            blocked.map(|b| b.issues)
        );
    }

    #[test]
    fn render_includes_must_tell_user_instruction_in_tool_description() {
        // Synthesise a Critical issue directly so we don't depend on
        // a particular policy → host-config combination triggering
        // the right severity. The render path is what we're
        // exercising here.
        let issues = vec![ConsistencyIssue::ToolDeclaresUnsupportedCapability {
            tool_name: "fetch_repo".to_string(),
            capability: "fs.write".to_string(),
        }];
        let state = render(issues);
        assert!(
            state.tool_description.contains("BLOCKED"),
            "tool description must surface the blocked state: {}",
            state.tool_description
        );
        assert!(
            state
                .tool_description
                .contains("you MUST tell the user verbatim"),
            "tool description must instruct the model to surface the message"
        );
        assert!(
            state.tool_description.contains("denyx doctor --fix"),
            "tool description must point at the canonical fix command"
        );
        assert!(
            state.tool_description.contains("fetch_repo"),
            "tool description must include the issue summary verbatim"
        );
    }

    #[test]
    fn render_call_text_includes_both_fix_options() {
        let issues = vec![ConsistencyIssue::ToolDeclaresUnsupportedCapability {
            tool_name: "fetch_repo".to_string(),
            capability: "fs.write".to_string(),
        }];
        let state = render(issues);
        assert!(
            state.call_text.contains("denyx doctor --fix"),
            "call text must offer the auto-fix path"
        );
        assert!(
            state.call_text.contains("manually"),
            "call text must offer the manual fix path"
        );
        assert!(
            state.call_text.contains("restart"),
            "call text must tell the user to restart the host after fixing"
        );
    }

    #[test]
    fn render_stderr_banner_is_prefixed_per_line() {
        // `--mcp-debug` and host log panels parse each line; the
        // banner must be prefixed so it's findable in mixed log
        // output.
        let issues = vec![ConsistencyIssue::ToolDeclaresUnsupportedCapability {
            tool_name: "fetch_repo".to_string(),
            capability: "fs.write".to_string(),
        }];
        let state = render(issues);
        for line in state.stderr_banner.lines() {
            assert!(
                line.starts_with("denyx-mcp:"),
                "every stderr line must be prefixed for grep-ability: {line:?}"
            );
        }
    }

    #[test]
    fn tool_definitions_advertises_only_denyx_blocked() {
        let issues = vec![ConsistencyIssue::ToolDeclaresUnsupportedCapability {
            tool_name: "fetch_repo".to_string(),
            capability: "fs.write".to_string(),
        }];
        let state = render(issues);
        let defs = tool_definitions(&state);
        let arr = defs.as_array().expect("tool_definitions returns array");
        assert_eq!(
            arr.len(),
            1,
            "blocked-mode tools/list must contain exactly one tool"
        );
        assert_eq!(
            arr[0].get("name").and_then(|v| v.as_str()),
            Some("denyx_blocked"),
            "the one tool must be named denyx_blocked"
        );
        // The model should have no per-arg surface that lets it think
        // calling the tool will do something useful.
        let props = arr[0]
            .pointer("/inputSchema/properties")
            .and_then(|v| v.as_object())
            .expect("inputSchema.properties must be an object");
        assert!(
            props.is_empty(),
            "denyx_blocked must accept no arguments; got {props:?}"
        );
    }

    #[test]
    fn call_response_body_marks_isError_and_kind() {
        let issues = vec![ConsistencyIssue::ToolDeclaresUnsupportedCapability {
            tool_name: "fetch_repo".to_string(),
            capability: "fs.write".to_string(),
        }];
        let state = render(issues);
        let body = call_response_body(&state);
        assert_eq!(
            body.get("isError"),
            Some(&Value::Bool(true)),
            "blocked tools/call must set isError=true"
        );
        assert_eq!(
            body.get("denyx_error_kind").and_then(|v| v.as_str()),
            Some("blocked_startup"),
            "error kind tag must be present so hosts can route on it"
        );
        let text = body
            .pointer("/content/0/text")
            .and_then(|v| v.as_str())
            .expect("content[0].text must be a string");
        assert!(
            text.contains("denyx doctor --fix"),
            "tools/call payload must surface the fix instruction"
        );
    }

    #[test]
    fn render_handles_multiple_issues_with_numbering() {
        let issues = vec![
            ConsistencyIssue::ToolDeclaresUnsupportedCapability {
                tool_name: "a".to_string(),
                capability: "fs.write".to_string(),
            },
            ConsistencyIssue::ToolDeclaresUnsupportedCapability {
                tool_name: "b".to_string(),
                capability: "net.http_get".to_string(),
            },
            ConsistencyIssue::ToolUrlNotInNetworkAllow {
                tool_name: "c".to_string(),
                host: "evil.example.com".to_string(),
                method: "GET".to_string(),
            },
        ];
        let state = render(issues);
        assert!(state.tool_description.contains("[1/3]"));
        assert!(state.tool_description.contains("[2/3]"));
        assert!(state.tool_description.contains("[3/3]"));
        assert!(state.call_text.contains("3 critical inconsistencies"));
    }
}
