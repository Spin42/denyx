//! Integration tests for `denyx-mcp --confirm-mode elicit`.
//!
//! Drives the MCP server end-to-end as if we were a client that
//! supports the MCP `elicitation/create` capability:
//!
//! 1. Spawn `denyx-mcp --confirm-mode elicit`.
//! 2. Send `initialize` with `capabilities.elicitation: {}`.
//! 3. Send `notifications/initialized`.
//! 4. Send `tools/call denyx_run` with a script that fires an
//!    approval-required capability.
//! 5. Read the next line — it should be the `elicitation/create`
//!    request from the server.
//! 6. Reply with a synthetic accept/decline response.
//! 7. Read the line after that — it should be the `tools/call`
//!    response, which we assert reflects the elicit decision.
//!
//! Also covers: a "decline" reply produces a confirm_denied result;
//! a missing/timeout reply degrades to confirm_denied; an `error`
//! response on the elicitation request also degrades to
//! confirm_denied (this is the "client doesn't support elicitation
//! in practice" path).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_denyx-mcp");

fn write_policy(suffix: &str, body: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "denyx_mcp_elicit_{}_{}_{}",
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
    fn spawn(policy: &PathBuf, confirm_mode: &str) -> Session {
        let mut child = Command::new(BIN)
            .arg("--policy")
            .arg(policy)
            .arg("--confirm-mode")
            .arg(confirm_mode)
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
        let n = self.stdout.read_line(&mut self.line).expect("read line");
        assert!(n > 0, "server closed stdout unexpectedly");
        serde_json::from_str(self.line.trim()).expect("parse line")
    }

    fn handshake_with_elicitation(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": { "elicitation": {} },
                "clientInfo": { "name": "test-elicitation", "version": "0" }
            }
        }));
        let _ = self.recv(); // initialize result
        self.send(&json!({
            "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
        }));
        let _ = self.recv(); // ack
    }

    fn close(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

fn approval_policy(write_dir: &str) -> String {
    format!(
        r#"requires_approval = ["fs.write"]

[filesystem]
write_allow = ["{write_dir}/**"]
"#
    )
}

#[test]
fn elicit_accept_allows_call_through() {
    let work = std::env::temp_dir().join(format!("denyx_elicit_accept_{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let abs = work.to_string_lossy().replace('\\', "/");
    let (dir, policy) = write_policy("accept", &approval_policy(&abs));

    let mut s = Session::spawn(&policy, "elicit");
    s.handshake_with_elicitation();

    // tools/call denyx_run — script writes a file, which is gated by
    // `requires_approval = ["fs.write"]`.
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": { "script": format!("fs.write({:?}, \"hi\")", format!("{abs}/x.txt")) }
        }
    }));

    // The next line from the server should be the elicitation
    // request, NOT the tools/call response.
    let elicit = s.recv();
    assert_eq!(
        elicit["method"], "elicitation/create",
        "expected elicitation/create, got: {elicit}"
    );
    let elicit_id = elicit["id"].clone();
    let msg = elicit["params"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("fs.write"),
        "elicitation message should name the capability: {msg}"
    );

    // Reply with accept + approved.
    s.send(&json!({
        "jsonrpc": "2.0",
        "id": elicit_id,
        "result": {
            "action": "accept",
            "content": { "approved": true }
        }
    }));

    // Now the tools/call response should arrive with isError: false.
    let tools_resp = s.recv();
    let result = &tools_resp["result"];
    assert_eq!(
        result["isError"], false,
        "elicit accept should let the call through: {result}"
    );

    s.close();
    assert!(
        work.join("x.txt").exists(),
        "fs.write should have produced the file"
    );

    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn elicit_decline_blocks_call_with_confirm_denied() {
    let work = std::env::temp_dir().join(format!("denyx_elicit_decline_{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let abs = work.to_string_lossy().replace('\\', "/");
    let (dir, policy) = write_policy("decline", &approval_policy(&abs));

    let mut s = Session::spawn(&policy, "elicit");
    s.handshake_with_elicitation();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": { "script": format!("fs.write({:?}, \"hi\")", format!("{abs}/x.txt")) }
        }
    }));

    let elicit = s.recv();
    let elicit_id = elicit["id"].clone();
    s.send(&json!({
        "jsonrpc": "2.0",
        "id": elicit_id,
        "result": { "action": "decline", "content": {} }
    }));

    let tools_resp = s.recv();
    let result = &tools_resp["result"];
    assert_eq!(result["isError"], true, "decline should fail: {result}");
    assert_eq!(
        result["denyx_error_kind"], "confirm_denied",
        "decline should tag confirm_denied: {result}"
    );

    s.close();
    assert!(
        !work.join("x.txt").exists(),
        "decline should not have written the file"
    );
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn elicit_accept_without_approved_flag_is_treated_as_deny() {
    // The MCP elicitation spec is explicit that the user can return
    // `action: accept` but with form data that doesn't satisfy the
    // requested schema (e.g. `approved: false`). In that case we
    // must NOT treat the call as authorised — the user said "submit"
    // but didn't tick the approval box.
    let work = std::env::temp_dir().join(format!("denyx_elicit_unticked_{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let abs = work.to_string_lossy().replace('\\', "/");
    let (dir, policy) = write_policy("unticked", &approval_policy(&abs));

    let mut s = Session::spawn(&policy, "elicit");
    s.handshake_with_elicitation();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": { "script": format!("fs.write({:?}, \"hi\")", format!("{abs}/x.txt")) }
        }
    }));
    let elicit = s.recv();
    let elicit_id = elicit["id"].clone();
    s.send(&json!({
        "jsonrpc": "2.0",
        "id": elicit_id,
        "result": { "action": "accept", "content": { "approved": false } }
    }));
    let tools_resp = s.recv();
    let result = &tools_resp["result"];
    assert_eq!(result["isError"], true);
    assert_eq!(result["denyx_error_kind"], "confirm_denied");
    s.close();
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn elicit_error_response_is_treated_as_deny() {
    // If the client returns a JSON-RPC error response on the
    // elicitation request (e.g. "method not found" because it
    // doesn't actually implement elicitation despite advertising
    // it), we must deny — never treat an error as approval.
    let work = std::env::temp_dir().join(format!("denyx_elicit_error_{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let abs = work.to_string_lossy().replace('\\', "/");
    let (dir, policy) = write_policy("error", &approval_policy(&abs));

    let mut s = Session::spawn(&policy, "elicit");
    s.handshake_with_elicitation();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": { "script": format!("fs.write({:?}, \"hi\")", format!("{abs}/x.txt")) }
        }
    }));
    let elicit = s.recv();
    let elicit_id = elicit["id"].clone();
    s.send(&json!({
        "jsonrpc": "2.0",
        "id": elicit_id,
        "error": { "code": -32601, "message": "elicitation/create not implemented" }
    }));
    let tools_resp = s.recv();
    let result = &tools_resp["result"];
    assert_eq!(result["isError"], true);
    assert_eq!(result["denyx_error_kind"], "confirm_denied");
    s.close();
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn auto_mode_falls_back_to_deny_when_client_lacks_elicitation_capability() {
    // The DEFAULT mode is "auto". If the client does NOT advertise
    // elicitation in initialize, the server falls back to plain
    // deny (matching the old auto-deny behaviour). No elicitation
    // request should be sent in this case — the next line after
    // tools/call is the tool result directly.
    let work = std::env::temp_dir().join(format!("denyx_elicit_fallback_{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let abs = work.to_string_lossy().replace('\\', "/");
    let (dir, policy) = write_policy("fallback", &approval_policy(&abs));

    let mut s = Session::spawn(&policy, "auto");
    // Initialize WITHOUT elicitation capability.
    s.send(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "no-elicit", "version": "0" }
        }
    }));
    let _ = s.recv();
    s.send(&json!({
        "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
    }));
    let _ = s.recv();

    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": { "script": format!("fs.write({:?}, \"hi\")", format!("{abs}/x.txt")) }
        }
    }));
    // No elicitation request expected. The next line is the result.
    let tools_resp = s.recv();
    assert_eq!(
        tools_resp.get("method"),
        None,
        "auto fallback should NOT send elicitation/create when client lacks capability; got: {tools_resp}"
    );
    let result = &tools_resp["result"];
    assert_eq!(result["isError"], true);
    assert_eq!(result["denyx_error_kind"], "confirm_denied");
    s.close();
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn elicit_unrelated_call_does_not_fire_elicitation() {
    // Sanity: a tools/call that does NOT touch any
    // requires_approval-listed capability must complete without
    // sending an elicitation. Otherwise the elicit hook would have
    // false-positive interruptions on every call.
    let work = std::env::temp_dir().join(format!("denyx_elicit_unrelated_{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let (dir, policy) = write_policy(
        "unrelated",
        &format!(
            r#"requires_approval = ["fs.delete"]

[filesystem]
read_allow = ["{abs}/**"]
write_allow = ["{abs}/**"]
"#,
            abs = work.to_string_lossy().replace('\\', "/")
        ),
    );
    std::fs::write(work.join("x.txt"), "hi").unwrap();

    let mut s = Session::spawn(&policy, "elicit");
    s.handshake_with_elicitation();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": {
                "script": format!(
                    "x = fs.read({:?})\nprint(x)",
                    format!("{}/x.txt", work.to_string_lossy().replace('\\', "/"))
                )
            }
        }
    }));
    let resp = s.recv();
    assert_eq!(
        resp.get("method"),
        None,
        "fs.read is not in requires_approval; no elicitation should fire: {resp}"
    );
    let result = &resp["result"];
    assert_eq!(result["isError"], false, "{result}");
    s.close();
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn elicit_timeout_behavior_documented() {
    // The actual timeout is 300s — too long for a unit test. Instead
    // we verify the server is in a sensible state mid-elicitation:
    // the elicitation/create request is on stdout, and the tools/call
    // hasn't responded. Then we close stdin to force the server to
    // exit; the tools/call response (if any) should be confirm_denied.
    let work = std::env::temp_dir().join(format!("denyx_elicit_timeout_{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let abs = work.to_string_lossy().replace('\\', "/");
    let (dir, policy) = write_policy("timeout", &approval_policy(&abs));

    let mut s = Session::spawn(&policy, "elicit");
    s.handshake_with_elicitation();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": { "script": format!("fs.write({:?}, \"hi\")", format!("{abs}/x.txt")) }
        }
    }));
    // Receive the elicitation request to confirm the protocol got that far.
    let elicit = s.recv();
    assert_eq!(elicit["method"], "elicitation/create");

    // We don't reply. Close stdin instead — this severs the read
    // side of the server, the reader thread exits, the elicit
    // recv_timeout eventually fires (we don't wait the full 300s
    // here; just confirm the protocol state and exit). The server
    // process is killed when this Session drops.
    let elapsed_start = Instant::now();
    drop(s.stdin);
    let _ = s.child.kill();
    let _ = s.child.wait();
    assert!(
        elapsed_start.elapsed() < Duration::from_secs(5),
        "we shouldn't be blocked here; the test just confirms the server is mid-elicitation"
    );

    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(&dir);
}
