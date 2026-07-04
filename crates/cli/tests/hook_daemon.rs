//! Integration tests for `denyx hook-daemon` — spawning the real
//! binary as a background daemon and driving `denyx hook
//! --daemon-socket <path>` against it, to pin the wire protocol and
//! the fallback-when-unreachable behavior against the compiled
//! program, not just the in-process client/server functions.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_denyx");

fn unique_tempdir(label: &str) -> PathBuf {
    let workspace_target = PathBuf::from(BIN)
        .parent()
        .expect("denyx parent")
        .to_path_buf();
    let base = workspace_target.join("hook-daemon-tmp").join(format!(
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

/// Short, deterministic socket path under the system temp dir — kept
/// separate from `unique_tempdir` (which nests under the workspace
/// target dir and can be too long for a Unix socket's `SUN_LEN`
/// limit, unlike the real default-socket-path derivation which always
/// hashes down to a short name regardless of how long the policy path
/// is).
fn short_socket_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "denyx-hook-daemon-test-{label}-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// A running daemon child process, killed on drop so a test failure
/// (assert panic) doesn't leak an orphaned daemon holding a socket.
struct DaemonGuard {
    child: Child,
    socket: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(self.socket.with_extension("pid"));
    }
}

fn start_daemon(policy_path: &Path, socket_path: &Path) -> DaemonGuard {
    let child = Command::new(BIN)
        .args([
            "hook-daemon",
            "start",
            "--policy",
            policy_path.to_str().unwrap(),
            "--socket",
            socket_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn denyx hook-daemon start");

    // Poll for the socket file rather than a blind sleep — bind()
    // happens very early in cmd_start, but process scheduling under
    // load can still take a few ms.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket_path.exists() {
        if Instant::now() > deadline {
            panic!("daemon did not create socket {socket_path:?} within 5s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    DaemonGuard {
        child,
        socket: socket_path.to_path_buf(),
    }
}

fn run_hook_via_daemon(
    policy_path: &Path,
    socket_path: &Path,
    stdin_json: &str,
) -> std::process::Output {
    let mut child = Command::new(BIN)
        .args([
            "hook",
            "--policy",
            policy_path.to_str().unwrap(),
            "--daemon-socket",
            socket_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn denyx hook --daemon-socket");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_json.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait for denyx hook")
}

#[test]
fn daemon_serves_allow_and_deny_across_multiple_requests() {
    let dir = unique_tempdir("allow_deny");
    let allowed_file = dir.join("ok.txt");
    std::fs::write(&allowed_file, "hello").unwrap();
    let policy_path = dir.join("denyx.toml");
    std::fs::write(
        &policy_path,
        format!(
            "[filesystem]\nread_allow = [\"{}\"]\n",
            allowed_file.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    let socket_path = short_socket_path("allow_deny");
    let _daemon = start_daemon(&policy_path, &socket_path);

    let allow_input = serde_json::json!({
        "tool_name": "Read",
        "tool_input": { "file_path": allowed_file.to_string_lossy() }
    })
    .to_string();
    let out = run_hook_via_daemon(&policy_path, &socket_path, &allow_input);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"permissionDecision\":\"allow\""));

    let deny_input = serde_json::json!({
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/passwd" }
    })
    .to_string();
    let out = run_hook_via_daemon(&policy_path, &socket_path, &deny_input);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("DENY"));

    // A third request proves the daemon is still alive and serving
    // after the first two — it didn't exit or wedge after one call.
    let out = run_hook_via_daemon(&policy_path, &socket_path, &allow_input);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn daemon_stays_resident_policy_not_reparsed_per_call() {
    // Indirect but real signal: the daemon's audit log accumulates a
    // continuous denyx_seq/denyx_prev_hash chain across requests, which
    // only happens if the same AuditSink (and therefore the same
    // long-lived process) served every request — a fresh process per
    // call would each start its own chain at denyx_seq 1 with the
    // genesis prev_hash.
    let dir = unique_tempdir("resident");
    let policy_path = dir.join("denyx.toml");
    std::fs::write(&policy_path, "[environment]\nallow_vars = [\"PATH\"]\n").unwrap();
    let socket_path = short_socket_path("resident");
    let audit_log = dir.join("audit.jsonl");
    let child = Command::new(BIN)
        .args([
            "hook-daemon",
            "start",
            "--policy",
            policy_path.to_str().unwrap(),
            "--socket",
            socket_path.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn denyx hook-daemon start");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket_path.exists() {
        if Instant::now() > deadline {
            panic!("daemon did not create socket within 5s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut guard = DaemonGuard {
        child,
        socket: socket_path.clone(),
    };

    // Two requests against a capability with no matching mapping
    // (Bash without an allow-listed command) — content doesn't
    // matter, only that two audit events get appended by the SAME
    // process.
    let input = serde_json::json!({
        "tool_name": "Grep",
        "tool_input": { "path": dir.to_string_lossy() }
    })
    .to_string();
    run_hook_via_daemon(&policy_path, &socket_path, &input);
    run_hook_via_daemon(&policy_path, &socket_path, &input);

    let _ = guard.child.kill();
    let _ = guard.child.wait();

    let log = std::fs::read_to_string(&audit_log).unwrap_or_default();
    let lines: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "expected exactly 2 audit lines, got: {log}");
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(first["denyx_seq"], 1);
    assert_eq!(second["denyx_seq"], 2);
    assert_eq!(
        second["denyx_prev_hash"].as_str().unwrap().len(),
        64,
        "second event's prev_hash should chain from the first event's real hash, \
         not the genesis hash a fresh process would start from"
    );
}

#[test]
fn hook_falls_back_to_direct_evaluation_when_daemon_unreachable() {
    let dir = unique_tempdir("fallback");
    let allowed_file = dir.join("ok.txt");
    std::fs::write(&allowed_file, "hello").unwrap();
    let policy_path = dir.join("denyx.toml");
    std::fs::write(
        &policy_path,
        format!(
            "[filesystem]\nread_allow = [\"{}\"]\n",
            allowed_file.to_string_lossy().replace('\\', "/")
        ),
    )
    .unwrap();
    // No daemon started at all — this socket path was never bound.
    let socket_path = short_socket_path("fallback_never_started");

    let allow_input = serde_json::json!({
        "tool_name": "Read",
        "tool_input": { "file_path": allowed_file.to_string_lossy() }
    })
    .to_string();
    let out = run_hook_via_daemon(&policy_path, &socket_path, &allow_input);
    assert_eq!(
        out.status.code(),
        Some(0),
        "an unreachable daemon must not change the outcome vs. direct evaluation; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"permissionDecision\":\"allow\""));
}

#[test]
fn daemon_lifecycle_start_status_stop() {
    let dir = unique_tempdir("lifecycle");
    let policy_path = dir.join("denyx.toml");
    std::fs::write(&policy_path, "").unwrap();
    let socket_path = short_socket_path("lifecycle");

    let status_before = Command::new(BIN)
        .args([
            "hook-daemon",
            "status",
            "--socket",
            socket_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&status_before.stdout).contains("not running"));

    let daemon = start_daemon(&policy_path, &socket_path);

    let status_during = Command::new(BIN)
        .args([
            "hook-daemon",
            "status",
            "--socket",
            socket_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&status_during.stdout).contains("reachable"));

    let stop = Command::new(BIN)
        .args([
            "hook-daemon",
            "stop",
            "--socket",
            socket_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        stop.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&stop.stderr)
    );

    // Give the killed process a moment to actually exit and release
    // the socket before checking status again.
    std::thread::sleep(Duration::from_millis(200));
    let status_after = Command::new(BIN)
        .args([
            "hook-daemon",
            "status",
            "--socket",
            socket_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&status_after.stdout).contains("not running"),
        "expected 'not running' after stop, got: {}",
        String::from_utf8_lossy(&status_after.stdout)
    );

    // Prevent the DaemonGuard's Drop from trying to kill an
    // already-stopped process (harmless either way, but avoids a
    // confusing "no such process" in test output).
    std::mem::forget(daemon);
}
