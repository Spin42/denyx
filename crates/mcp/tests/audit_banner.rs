//! Startup-banner tests for `denyx-mcp`.
//!
//! Real bug report from a user setting up Denyx in opencode: "the
//! audit log wasn't created by the prompt." The audit log was, in
//! fact, being written — to stderr, the default. opencode (like
//! Claude Code) captures the MCP server's stderr into its own
//! MCP-server log directory, mixing Denyx audit events with every
//! other server's noise. From the operator's perspective the audit
//! feature looks broken.
//!
//! Fix: print a single banner line to stderr at startup so the
//! operator can see where audit events are going. Three cases:
//!
//!   1. `--audit-log <path>` — banner says `audit -> file <path>`
//!   2. `DENYX_AUDIT_URL=<url>` — banner says `audit -> POST <url>`
//!   3. neither set — banner is a WARNING that audit goes to
//!      stderr, mentions the recommended fix
//!
//! These tests spawn the real `denyx-mcp` binary, give it just
//! enough input to start the main loop, kill it, then assert on
//! the captured stderr.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_denyx-mcp");

/// Spawn denyx-mcp with the given env vars and CLI args, send one
/// initialize message so the binary is past audit-sink setup, kill
/// it, and return whatever it wrote to stderr.
fn spawn_and_capture_stderr(env: &[(&str, &str)], args: &[&str]) -> String {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("HOME"); // avoid loading per-user dotenv from CI homedirs
    cmd.env_remove("DENYX_AUDIT_URL");
    cmd.env_remove("DENYX_POLICY_URL");
    cmd.env_remove("DENYX_AUTH_TOKEN");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn denyx-mcp");
    let mut stdin = child.stdin.take().unwrap();
    // Send a single initialize so the binary reaches main-loop
    // territory; it will have printed the banner before this point.
    let _ = writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}}}}}}"#
    );
    let _ = stdin.flush();
    drop(stdin);
    // Give the banner a moment to flush, then kill.
    thread::sleep(Duration::from_millis(200));
    let _ = child.kill();
    let _ = child.wait();
    let mut stderr = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut stderr);
    }
    stderr
}

#[test]
fn banner_announces_audit_log_file_when_path_provided() {
    // Use an in-tree throwaway audit log path. The path doesn't have
    // to exist; denyx-mcp creates it.
    let dir = std::env::temp_dir().join(format!("denyx_banner_file_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("audit.jsonl");
    let log_str = log_path.to_string_lossy().to_string();

    let stderr = spawn_and_capture_stderr(
        &[],
        &["--audit-log", &log_str, "--confirm-mode", "auto-deny"],
    );

    assert!(
        stderr.contains("audit -> file"),
        "expected 'audit -> file' banner; got stderr:\n{stderr}"
    );
    // The exact path printed is the canonicalised form, which on
    // Linux preserves /tmp; we check the basename to avoid being
    // brittle to /tmp vs /private/tmp / symlink resolution.
    assert!(
        stderr.contains("audit.jsonl"),
        "expected the audit-log basename in the banner; got stderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn banner_announces_audit_post_when_url_set() {
    // Use a URL that obviously isn't a real server. denyx-mcp doesn't
    // contact the audit URL at startup (only on first event), so the
    // unreachable URL is fine for testing the banner.
    let stderr = spawn_and_capture_stderr(
        &[("DENYX_AUDIT_URL", "https://audit.example.invalid/v1/events")],
        &["--confirm-mode", "auto-deny"],
    );

    assert!(
        stderr.contains("audit -> POST"),
        "expected 'audit -> POST' banner; got stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("https://audit.example.invalid/v1/events"),
        "expected the audit URL in the banner; got stderr:\n{stderr}"
    );
}

#[test]
fn banner_warns_when_neither_audit_log_nor_url_set() {
    // No --audit-log, no DENYX_AUDIT_URL. The banner must loudly
    // tell the operator that audit is going to stderr and how to
    // fix it.
    let stderr = spawn_and_capture_stderr(&[], &["--confirm-mode", "auto-deny"]);

    assert!(
        stderr.contains("WARNING"),
        "stderr-default banner must include WARNING; got stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--audit-log"),
        "warning must mention --audit-log as the fix; got stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("DENYX_AUDIT_URL"),
        "warning must mention DENYX_AUDIT_URL as the alternative; got stderr:\n{stderr}"
    );
    // Sanity: the warning shouldn't be confused for one of the
    // success banners.
    assert!(
        !stderr.contains("audit -> file"),
        "stderr-default path must not pretend audit is going to a file; got stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("audit -> POST"),
        "stderr-default path must not pretend audit is going to a URL; got stderr:\n{stderr}"
    );
}

#[test]
fn banner_url_takes_precedence_over_file_when_both_set() {
    // CLI sets --audit-log, env sets DENYX_AUDIT_URL. The code's
    // documented precedence is URL > file > stderr default. Banner
    // should reflect the chosen sink.
    let dir = std::env::temp_dir().join(format!("denyx_banner_prec_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("audit.jsonl");
    let log_str = log_path.to_string_lossy().to_string();

    let stderr = spawn_and_capture_stderr(
        &[(
            "DENYX_AUDIT_URL",
            "https://audit.example.invalid/take-precedence",
        )],
        &["--audit-log", &log_str, "--confirm-mode", "auto-deny"],
    );

    assert!(
        stderr.contains("audit -> POST"),
        "URL must win over --audit-log; got stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("audit -> file"),
        "should not also announce the file sink when URL wins; got stderr:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
