//! `denyx hook` — a `PreToolUse`-shaped authorization endpoint that
//! lets an agentic host (Claude Code today; opencode's
//! `tool.execute.before` plugin hook speaks a different transport
//! but the same idea) delegate its OWN native tool calls (`Bash`,
//! `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch`) to the same
//! policy engine `denyx run` enforces on Starlark scripts — without
//! requiring the model to learn the Starlark DSL or route through
//! MCP at all.
//!
//! This is a genuinely different trust boundary than `denyx run`,
//! and a narrower one. Read this before wiring it in:
//!
//! - **No cross-call information-flow control.** `denyx run`'s
//!   `local_only_*` taint tracking works because one Starlark
//!   script's whole execution stays inside one process's memory.
//!   This hook answers ONE tool call at a time, with no session-
//!   spanning state; it cannot detect "a value read via `Read` two
//!   tool-calls ago is now embedded in this `Bash` command." It
//!   gives you the capability gate (which paths / commands / hosts
//!   are reachable at all), not the redaction layer. See
//!   `docs/security-pentest-r3-argv0-and-chunking.md`'s discussion
//!   of this trade-off.
//! - **`Bash` commands containing shell composition are refused
//!   outright**, not parsed. `;`, `|`, `&`, `` ` ``, `<`, `>`, `$`,
//!   and newlines all trigger an unconditional deny. Denyx's
//!   Starlark `subprocess.exec` has never accepted shell syntax
//!   either — argv arrays only — so this isn't a new restriction,
//!   it's the same one applied to a raw command string instead of
//!   an argv array. A hand-rolled quote-aware shell grammar is
//!   exactly the kind of subtly-wrong parser that turns into a
//!   policy bypass; over-denying is the safe failure mode here.
//! - **Exit-code contract is deliberately narrow, unlike every
//!   other `denyx` subcommand.** Claude Code's `PreToolUse` hooks
//!   fail OPEN on anything other than exit code 2 (a crash, a
//!   timeout, exit code 1, malformed JSON on exit 0 all let the
//!   tool call proceed — this is documented Claude Code behavior,
//!   not a Denyx choice). So `denyx hook` guarantees: exit 0 only
//!   on a confirmed ALLOW with valid JSON on stdout; exit 2 for
//!   every other outcome, including internal errors and panics.
//!   `run_and_exit` wraps its own logic in `catch_unwind` so a bug
//!   in this file can't fail open via Rust's default panic exit
//!   code (101, which Claude Code would treat as non-blocking).
//! - **Field names for `tool_input` are inferred from Claude Code's
//!   documented hook payload shape as of this writing** (`command`
//!   for Bash, `file_path` for Read/Write/Edit, `path` for
//!   Glob/Grep, `url` for WebFetch). Anthropic controls this schema
//!   and can change it; an unrecognized or missing field fails
//!   closed (denies), which is safe but not useful — verify against
//!   a real hook payload on your Claude Code version before relying
//!   on this in production.
//! - **Unmapped tools are denied, not passed through.** `WebSearch`,
//!   `Task`, and any tool this module doesn't explicitly recognize
//!   are refused. Extend `translate_and_check` deliberately; don't
//!   default new tools to allow.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use denyx_host::{AuditEvent, AuditSink, AuditStatus, JsonlAuditSink};
use denyx_policy::Policy;
use serde_json::Value;

#[derive(Parser, Debug)]
pub struct HookArgs {
    /// Path to the policy TOML file. If omitted, falls back to the
    /// built-in `secure-defaults` baseline (denies every fs / net /
    /// subprocess capability) — same fail-closed default as `denyx
    /// run` without `--policy`.
    #[arg(short, long)]
    pub policy: Option<PathBuf>,

    /// Append audit events to this file (JSON Lines). Defaults to
    /// stderr, which most hook configurations discard on a clean
    /// allow — pass an explicit path to keep a real trail across
    /// invocations (each `denyx hook` call is a fresh process; the
    /// audit chain resumes from the file's existing tail, same as
    /// `denyx run --audit-log`).
    #[arg(long)]
    pub audit_log: Option<PathBuf>,

    /// Task id stamped into audit events. Defaults to "hook";
    /// pass the host's session id (available on the hook request as
    /// `session_id`) via a wrapper script if you want per-session
    /// grouping in the audit log.
    #[arg(long, default_value = "hook")]
    pub task_id: String,
}

/// Run `denyx hook` and terminate the process directly. Never
/// returns — this subcommand owns its own exit-code contract (see
/// module doc) and must not flow through the generic CLI
/// exit-code mapper in `main.rs`, which maps errors to codes 1/3/4/
/// 5/6 that Claude Code's hook contract treats as "non-blocking."
pub fn run_and_exit(args: HookArgs) -> ! {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute(&args)));
    match outcome {
        Ok(Ok(())) => std::process::exit(0),
        Ok(Err(reason)) => {
            eprintln!("denyx hook: DENY — {reason}");
            std::process::exit(2);
        }
        Err(panic) => {
            let msg = panic_message(&panic);
            eprintln!("denyx hook: DENY — internal error (panic), failing closed: {msg}");
            std::process::exit(2);
        }
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// One authorization outcome for a translated tool call.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny(String),
}

/// Read one `PreToolUse` request from stdin, translate it into the
/// equivalent Denyx capability check, emit an audit event, and
/// either print an ALLOW decision to stdout (returning `Ok`) or
/// return the deny reason (caller exits 2 without printing JSON —
/// exit code alone is the hard-deny signal; see module doc).
fn execute(args: &HookArgs) -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("failed to read stdin: {e}"))?;
    let request: Value =
        serde_json::from_str(&input).map_err(|e| format!("malformed JSON on stdin: {e}"))?;

    let tool_name = request
        .get("tool_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "request has no \"tool_name\" string field".to_string())?
        .to_string();
    let tool_input = request.get("tool_input").cloned().unwrap_or(Value::Null);

    let policy = load_policy(args.policy.as_deref())?;
    let decision = translate_and_check(&tool_name, &tool_input, &policy);

    emit_audit(args, &policy, &tool_name, &tool_input, &decision);

    match decision {
        Decision::Allow => {
            let output = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": "denyx policy permits this call",
                }
            });
            println!("{output}");
            Ok(())
        }
        Decision::Deny(reason) => Err(reason),
    }
}

fn load_policy(path: Option<&Path>) -> Result<Policy, String> {
    match path {
        Some(p) => Policy::load(p).map_err(|e| format!("failed to load policy {p:?}: {e}")),
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            Policy::secure_defaults_at(cwd)
                .map_err(|e| format!("failed to load secure-defaults baseline: {e}"))
        }
    }
}

/// Map a native tool call onto the Denyx capability it corresponds
/// to and run the same policy check `denyx run`'s Starlark builtins
/// would. Unrecognized tools deny — see module doc on why this list
/// is deliberately not "default allow."
fn translate_and_check(tool_name: &str, tool_input: &Value, policy: &Policy) -> Decision {
    match tool_name {
        "Read" | "NotebookRead" => {
            check_required_path(tool_input, "file_path", |p| policy.check_fs_read(p))
        }
        "Write" | "NotebookEdit" => {
            check_required_path(tool_input, "file_path", |p| policy.check_fs_write(p))
        }
        "Edit" | "MultiEdit" => {
            check_required_path(tool_input, "file_path", |p| policy.check_fs_write(p))
        }
        "Glob" => check_optional_path(tool_input, "path", |p| policy.check_fs_read(p)),
        "Grep" => check_optional_path(tool_input, "path", |p| policy.check_fs_read(p)),
        "WebFetch" => check_url(tool_input, policy),
        "Bash" => check_bash(tool_input, policy),
        other => Decision::Deny(format!(
            "denyx hook has no policy mapping for tool {other:?}; failing closed. \
             Add a mapping in crates/cli/src/hook.rs if this tool should be reachable."
        )),
    }
}

fn check_required_path(
    tool_input: &Value,
    field: &str,
    check: impl Fn(&Path) -> Result<PathBuf, denyx_policy::PolicyError>,
) -> Decision {
    match tool_input.get(field).and_then(|v| v.as_str()) {
        Some(path_str) => match check(Path::new(path_str)) {
            Ok(_) => Decision::Allow,
            Err(e) => Decision::Deny(e.to_string()),
        },
        None => Decision::Deny(format!(
            "tool_input has no string field {field:?}; failing closed"
        )),
    }
}

fn check_optional_path(
    tool_input: &Value,
    field: &str,
    check: impl Fn(&Path) -> Result<PathBuf, denyx_policy::PolicyError>,
) -> Decision {
    let owned_cwd;
    let path: &Path = match tool_input.get(field).and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => {
            owned_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            &owned_cwd
        }
    };
    match check(path) {
        Ok(_) => Decision::Allow,
        Err(e) => Decision::Deny(e.to_string()),
    }
}

fn check_url(tool_input: &Value, policy: &Policy) -> Decision {
    match tool_input.get("url").and_then(|v| v.as_str()) {
        Some(url) => match policy.check_http_get(url) {
            Ok(_) => Decision::Allow,
            Err(e) => Decision::Deny(e.to_string()),
        },
        None => Decision::Deny("tool_input has no string field \"url\"; failing closed".into()),
    }
}

fn check_bash(tool_input: &Value, policy: &Policy) -> Decision {
    let Some(command) = tool_input.get("command").and_then(|v| v.as_str()) else {
        return Decision::Deny("tool_input has no string field \"command\"; failing closed".into());
    };
    if let Some(bad_char) = find_shell_composition(command) {
        return Decision::Deny(format!(
            "denyx hook does not evaluate shell composition (found {bad_char:?} in the \
             command); only single simple commands are supported in hook mode. Denyx's \
             Starlark subprocess.exec model never accepts shell syntax either — this is \
             the same restriction, not a new one."
        ));
    }
    let argv = match tokenize_simple_command(command) {
        Ok(argv) => argv,
        Err(e) => return Decision::Deny(format!("could not parse command as a simple argv: {e}")),
    };
    if argv.is_empty() {
        return Decision::Deny("empty command".into());
    }
    if let Err(e) = policy.check_subprocess_command(&argv[0]) {
        return Decision::Deny(e.to_string());
    }
    if let Err(e) = policy.check_subprocess_args(&argv) {
        return Decision::Deny(e.to_string());
    }
    if let Err(e) = policy.check_subprocess_argv_paths(&argv) {
        return Decision::Deny(e.to_string());
    }
    Decision::Allow
}

/// Conservative shell-metacharacter detector. If ANY of these bytes
/// appear anywhere in the raw command string — including inside
/// quotes — refuse to evaluate it as a policy-checkable argv. Being
/// quote-aware here would require a correct, complete shell
/// grammar; getting that subtly wrong is exactly the kind of bug
/// that turns into a policy bypass, so this deliberately over-denies
/// (a legitimate quoted `;` in a string argument gets refused too)
/// rather than risk under-denying.
fn find_shell_composition(command: &str) -> Option<char> {
    const METACHARACTERS: &[char] = &[';', '|', '&', '`', '<', '>', '$', '\n'];
    command.chars().find(|c| METACHARACTERS.contains(c))
}

/// Split a command into argv, honoring single and double quotes.
/// Only ever called after `find_shell_composition` has confirmed
/// there is no shell syntax to expand, so this only needs to handle
/// literal word-splitting — no variable expansion, no globbing, no
/// backslash escapes outside double quotes.
fn tokenize_simple_command(command: &str) -> Result<Vec<String>, String> {
    let mut argv = Vec::new();
    let mut chars = command.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut word = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                break;
            }
            match c {
                '\'' => {
                    chars.next();
                    loop {
                        match chars.next() {
                            Some('\'') => break,
                            Some(c) => word.push(c),
                            None => return Err("unterminated single quote".into()),
                        }
                    }
                }
                '"' => {
                    chars.next();
                    loop {
                        match chars.next() {
                            Some('"') => break,
                            Some('\\') => match chars.next() {
                                Some(c2) => word.push(c2),
                                None => return Err("unterminated escape in double quote".into()),
                            },
                            Some(c) => word.push(c),
                            None => return Err("unterminated double quote".into()),
                        }
                    }
                }
                _ => {
                    word.push(c);
                    chars.next();
                }
            }
        }
        argv.push(word);
    }
    Ok(argv)
}

fn emit_audit(
    args: &HookArgs,
    policy: &Policy,
    tool_name: &str,
    tool_input: &Value,
    decision: &Decision,
) {
    let sink = build_audit_sink(args, policy);
    let (status, detail) = match decision {
        Decision::Allow => (
            AuditStatus::Allowed,
            serde_json::json!({ "source": "denyx-hook", "tool_input": tool_input }),
        ),
        Decision::Deny(reason) => (
            AuditStatus::Denied,
            serde_json::json!({ "source": "denyx-hook", "tool_input": tool_input, "reason": reason }),
        ),
    };
    sink.emit(AuditEvent {
        ts: chrono::Utc::now().to_rfc3339(),
        task_id: args.task_id.clone(),
        step: 1,
        capability: format!("hook.{tool_name}"),
        status,
        detail,
    });
}

fn build_audit_sink(args: &HookArgs, policy: &Policy) -> Arc<dyn AuditSink> {
    let Some(path) = &args.audit_log else {
        return Arc::new(JsonlAuditSink::stderr());
    };
    // Same posture as `denyx run --audit-log`: refuse to write to a
    // path the policy itself would let the agent reach (an agent
    // that can read/write/delete its own audit trail can forge or
    // erase history). Fall back to stderr rather than silently drop
    // the event.
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
    if policy.guard_audit_log(&canon).is_err() {
        return Arc::new(JsonlAuditSink::stderr());
    }
    match JsonlAuditSink::file(path) {
        Ok(sink) => Arc::new(sink),
        Err(_) => Arc::new(JsonlAuditSink::stderr()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(toml: &str) -> Policy {
        let file = denyx_policy::PolicyFile::from_toml_str(toml).unwrap();
        Policy::from_file(file, std::env::temp_dir()).unwrap()
    }

    // ---- tokenize_simple_command ------------------------------------

    #[test]
    fn tokenize_splits_on_whitespace() {
        assert_eq!(
            tokenize_simple_command("cat file.txt").unwrap(),
            vec!["cat", "file.txt"]
        );
    }

    #[test]
    fn tokenize_handles_single_quotes() {
        assert_eq!(
            tokenize_simple_command("cat 'my file.txt'").unwrap(),
            vec!["cat", "my file.txt"]
        );
    }

    #[test]
    fn tokenize_handles_double_quotes_with_escape() {
        assert_eq!(
            tokenize_simple_command(r#"git commit -m "say \"hi\"""#).unwrap(),
            vec!["git", "commit", "-m", "say \"hi\""]
        );
    }

    #[test]
    fn tokenize_errors_on_unterminated_quote() {
        assert!(tokenize_simple_command("cat 'unterminated").is_err());
    }

    #[test]
    fn tokenize_empty_command_yields_empty_argv() {
        assert_eq!(
            tokenize_simple_command("   ").unwrap(),
            Vec::<String>::new()
        );
    }

    // ---- find_shell_composition --------------------------------------

    #[test]
    fn shell_composition_detects_each_metacharacter() {
        for sample in [
            "cat a; rm -rf /",
            "cat a | grep b",
            "cat a && echo done",
            "echo `whoami`",
            "cat < secret",
            "cat a > /etc/passwd",
            "echo $(whoami)",
            "cat a\nrm -rf /",
        ] {
            assert!(
                find_shell_composition(sample).is_some(),
                "expected shell composition to be detected in {sample:?}"
            );
        }
    }

    #[test]
    fn shell_composition_allows_simple_commands() {
        for sample in ["cat file.txt", "git status", "echo hello world"] {
            assert!(
                find_shell_composition(sample).is_none(),
                "did not expect shell composition in {sample:?}"
            );
        }
    }

    // ---- translate_and_check: per-tool mapping -------------------------

    #[test]
    fn read_allowed_path_is_allow() {
        let dir = std::env::temp_dir().join(format!("denyx_hook_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ok.txt");
        std::fs::write(&file, "x").unwrap();
        let abs = dir.to_string_lossy().replace('\\', "/");
        let p = policy(&format!(
            r#"
[filesystem]
read_allow = ["{abs}/**"]
"#
        ));
        let input = serde_json::json!({ "file_path": file.to_string_lossy() });
        assert_eq!(translate_and_check("Read", &input, &p), Decision::Allow);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_denied_path_is_deny() {
        let p = policy(
            r#"
[filesystem]
read_allow = ["/tmp/nowhere/**"]
"#,
        );
        let input = serde_json::json!({ "file_path": "/etc/passwd" });
        assert!(matches!(
            translate_and_check("Read", &input, &p),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn read_missing_file_path_field_is_deny() {
        let p = policy("");
        let input = serde_json::json!({ "not_file_path": "/etc/passwd" });
        assert!(matches!(
            translate_and_check("Read", &input, &p),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn write_and_edit_use_check_fs_write() {
        let dir = std::env::temp_dir().join(format!("denyx_hook_test_w_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let abs = dir.to_string_lossy().replace('\\', "/");
        let p = policy(&format!(
            r#"
[filesystem]
write_allow = ["{abs}/**"]
"#
        ));
        let target = dir.join("new.txt");
        let input = serde_json::json!({ "file_path": target.to_string_lossy() });
        assert_eq!(translate_and_check("Write", &input, &p), Decision::Allow);
        assert_eq!(translate_and_check("Edit", &input, &p), Decision::Allow);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn glob_without_path_field_falls_back_to_cwd() {
        // No [filesystem] section at all -> secure-defaults-shaped
        // empty policy denies everything, including cwd. This just
        // confirms the fallback path is exercised (denies, doesn't
        // panic) rather than skipping the check for a missing field.
        let p = policy("");
        let input = serde_json::json!({ "pattern": "*.rs" });
        assert!(matches!(
            translate_and_check("Glob", &input, &p),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn webfetch_checks_against_http_get_allow() {
        let p = policy(
            r#"
[network]
http_get_allow = ["api.github.com"]
"#,
        );
        let ok = serde_json::json!({ "url": "https://api.github.com/repos/x" });
        let bad = serde_json::json!({ "url": "https://evil.example.com/" });
        assert_eq!(translate_and_check("WebFetch", &ok, &p), Decision::Allow);
        assert!(matches!(
            translate_and_check("WebFetch", &bad, &p),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn bash_simple_allowed_command_is_allow() {
        let p = policy(
            r#"
[subprocess]
allow_commands = ["echo"]
"#,
        );
        let input = serde_json::json!({ "command": "echo hello world" });
        assert_eq!(translate_and_check("Bash", &input, &p), Decision::Allow);
    }

    #[test]
    fn bash_command_not_in_allowlist_is_deny() {
        let p = policy(
            r#"
[subprocess]
allow_commands = ["echo"]
"#,
        );
        let input = serde_json::json!({ "command": "cat /etc/passwd" });
        assert!(matches!(
            translate_and_check("Bash", &input, &p),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn bash_shell_composition_is_always_deny_even_if_commands_allowed() {
        let p = policy(
            r#"
[subprocess]
allow_commands = ["cat", "rm"]
"#,
        );
        for cmd in [
            "cat /tmp/x; rm -rf /",
            "cat /tmp/x | rm -rf /",
            "cat $(echo /etc/passwd)",
        ] {
            let input = serde_json::json!({ "command": cmd });
            assert!(
                matches!(translate_and_check("Bash", &input, &p), Decision::Deny(_)),
                "expected deny for composed command: {cmd:?}"
            );
        }
    }

    #[test]
    fn bash_argv0_path_shadow_is_still_caught_via_argv_paths_check() {
        // Regression guard for the round-3 argv[0] finding: hook mode
        // reuses check_subprocess_argv_paths, so a path-shaped argv[0]
        // outside the filesystem allow list must still be denied.
        let p = policy(
            r#"
[subprocess]
allow_commands = ["cat"]
"#,
        );
        let input = serde_json::json!({ "command": "/tmp/evil/cat /tmp/x" });
        assert!(matches!(
            translate_and_check("Bash", &input, &p),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn unmapped_tool_is_deny_not_allow() {
        let p = policy(
            r#"
[network]
http_get_allow = ["*"]
"#,
        );
        let input = serde_json::json!({ "query": "anything" });
        assert!(matches!(
            translate_and_check("WebSearch", &input, &p),
            Decision::Deny(_)
        ));
    }
}
