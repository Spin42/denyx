//! Integration tests for `denyx hook` — invoking the real binary
//! with a piped stdin request, to pin the exit-code contract
//! (0 = allow, 2 = deny for ANY reason) against the compiled
//! program, not just the in-process translation logic.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_denyx");

fn unique_tempdir(label: &str) -> PathBuf {
    let workspace_target = PathBuf::from(BIN)
        .parent()
        .expect("denyx parent")
        .to_path_buf();
    let base = workspace_target.join("hook-tmp").join(format!(
        "{label}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn run_hook(policy_path: &std::path::Path, stdin_json: &str) -> std::process::Output {
    let mut child = Command::new(BIN)
        .args(["hook", "--policy", policy_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn denyx hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_json.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait for denyx hook")
}

#[test]
fn allowed_read_exits_zero_with_allow_json() {
    let dir = unique_tempdir("allow_read");
    let file = dir.join("ok.txt");
    std::fs::write(&file, "hello").unwrap();
    let policy = dir.join("denyx.toml");
    std::fs::write(
        &policy,
        format!(
            "[filesystem]\nread_allow = [\"{}/**\"]\n",
            dir.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();

    let req = serde_json::json!({
        "tool_name": "Read",
        "tool_input": { "file_path": file.to_string_lossy() },
        "session_id": "test-session",
    });
    let out = run_hook(&policy, &req.to_string());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(stdout.contains("\"permissionDecision\":\"allow\""));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn denied_read_exits_two() {
    let dir = unique_tempdir("deny_read");
    let policy = dir.join("denyx.toml");
    std::fs::write(
        &policy,
        "[filesystem]\nread_allow = [\"/tmp/nowhere-near/**\"]\n",
    )
    .unwrap();

    let req = serde_json::json!({
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/passwd" },
    });
    let out = run_hook(&policy, &req.to_string());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(out.stdout.is_empty(), "deny path must not print allow JSON");
    assert!(stderr.contains("DENY"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_stdin_json_fails_closed_exits_two() {
    let dir = unique_tempdir("malformed");
    let policy = dir.join("denyx.toml");
    std::fs::write(&policy, "").unwrap();

    let out = run_hook(&policy, "{ this is not valid json");
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_policy_file_fails_closed_exits_two() {
    let dir = unique_tempdir("missing_policy");
    let policy = dir.join("does-not-exist.toml");

    let req = serde_json::json!({
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/passwd" },
    });
    let out = run_hook(&policy, &req.to_string());
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unmapped_tool_fails_closed_exits_two() {
    let dir = unique_tempdir("unmapped_tool");
    let policy = dir.join("denyx.toml");
    std::fs::write(&policy, "[network]\nhttp_get_allow = [\"*\"]\n").unwrap();

    let req = serde_json::json!({
        "tool_name": "WebSearch",
        "tool_input": { "query": "anything" },
    });
    let out = run_hook(&policy, &req.to_string());
    assert_eq!(out.status.code(), Some(2));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shell_composed_bash_command_fails_closed_even_with_broad_allow_commands() {
    let dir = unique_tempdir("bash_composed");
    let policy = dir.join("denyx.toml");
    std::fs::write(
        &policy,
        "[subprocess]\nallow_commands = [\"cat\", \"rm\"]\n",
    )
    .unwrap();

    let req = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": "cat /tmp/x; rm -rf /" },
    });
    let out = run_hook(&policy, &req.to_string());
    assert_eq!(out.status.code(), Some(2));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowed_simple_bash_command_exits_zero() {
    let dir = unique_tempdir("bash_simple");
    let policy = dir.join("denyx.toml");
    std::fs::write(&policy, "[subprocess]\nallow_commands = [\"echo\"]\n").unwrap();

    let req = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": "echo hello world" },
    });
    let out = run_hook(&policy, &req.to_string());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_log_records_both_allow_and_deny_and_chains() {
    let dir = unique_tempdir("audit");
    let policy = dir.join("denyx.toml");
    std::fs::write(
        &policy,
        "[network]\nhttp_get_allow = [\"api.github.com\"]\n",
    )
    .unwrap();
    let audit_log = dir.join("audit.jsonl");

    let mut child = Command::new(BIN)
        .args([
            "hook",
            "--policy",
            policy.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn denyx hook");
    let ok_req = serde_json::json!({
        "tool_name": "WebFetch",
        "tool_input": { "url": "https://api.github.com/x" },
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(ok_req.to_string().as_bytes())
        .unwrap();
    let out1 = child.wait_with_output().unwrap();
    assert_eq!(out1.status.code(), Some(0));

    let mut child2 = Command::new(BIN)
        .args([
            "hook",
            "--policy",
            policy.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn denyx hook");
    let bad_req = serde_json::json!({
        "tool_name": "WebFetch",
        "tool_input": { "url": "https://evil.example.com/" },
    });
    child2
        .stdin
        .take()
        .unwrap()
        .write_all(bad_req.to_string().as_bytes())
        .unwrap();
    let out2 = child2.wait_with_output().unwrap();
    assert_eq!(out2.status.code(), Some(2));

    let log = std::fs::read_to_string(&audit_log).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected one audit line per invocation: {log}"
    );
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(first["status"], "allowed");
    assert_eq!(second["status"], "denied");
    // Chain continuity across the two separate process invocations.
    assert_eq!(first["denyx_seq"], 1);
    assert_eq!(second["denyx_seq"], 2);
    assert_eq!(second["denyx_prev_hash"].as_str().unwrap().len(), 64);

    let _ = std::fs::remove_dir_all(&dir);
}
