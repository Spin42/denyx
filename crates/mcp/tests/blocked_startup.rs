//! End-to-end tests for the blocked-startup contract.
//!
//! Drives the `denyx-mcp` binary in a temp-dir project where the
//! `denyx.toml` and the project's host-config files are inconsistent
//! enough to produce `Critical`-level findings from
//! `policy_host_consistency::check`. Verifies that:
//!
//! 1. The server still completes the JSON-RPC handshake (the host
//!    must see a live server, not a crashed one).
//! 2. `tools/list` advertises only `denyx_blocked`.
//! 3. `tools/call` for any tool name returns the blocked payload
//!    (`isError=true`, `denyx_error_kind="blocked_startup"`).
//! 4. The first-run guard: a project with no host-config files at
//!    all skips the check and starts normally.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_denyx-mcp");

/// `denyx.toml` declaring a `[tools.WebSearch]` that requires
/// `net.http_get`, but with no `[network]` section at all → the
/// capability isn't granted → cross-cutting Critical issue
/// (`ToolDeclaresUnsupportedCapability`).
const POLICY_WITH_UNGRANTED_CAP: &str = r#"
[filesystem]
read_allow = ["./src/**"]

[tools.WebSearch]
capabilities = ["net.http_get"]
backend_url  = "https://searx.be/search"
"#;

/// Minimal `.mcp.json` just so `host_configs` is non-empty. The
/// content is irrelevant to the consistency check — we only need
/// the *presence* of a host config so the first-run guard doesn't
/// kick in.
const MINIMAL_MCP_JSON: &str = r#"{"mcpServers": {}}"#;

/// Driver mirroring `tests/server_mode.rs`'s `Session` but simpler —
/// no env-var injection, but needs `current_dir` so the binary's
/// `std::env::current_dir()` (which the consistency check uses)
/// resolves to our scratch project.
struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    line: String,
}

impl Session {
    fn spawn(scratch: &PathBuf, policy_path: &PathBuf) -> Session {
        let mut cmd = Command::new(BIN);
        cmd.current_dir(scratch)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("--policy")
            .arg(policy_path)
            .arg("--confirm-mode")
            .arg("auto-allow")
            .env_remove("HOME")
            .env_remove("DENYX_POLICY_URL")
            .env_remove("DENYX_AUDIT_URL")
            .env_remove("DENYX_AUTH_TOKEN");
        let mut child = cmd.spawn().expect("spawn denyx-mcp");
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

    fn handshake(&mut self) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
        }));
        let resp = self.recv();
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        let _ = self.recv();
        resp
    }

    fn close(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

fn make_scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("denyx_blocked_{name}_{}", std::process::id()));
    if p.exists() {
        let _ = std::fs::remove_dir_all(&p);
    }
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn blocked_mode_advertises_only_denyx_blocked_in_tools_list() {
    let scratch = make_scratch("tools_list");
    let policy_path = scratch.join("denyx.toml");
    std::fs::write(&policy_path, POLICY_WITH_UNGRANTED_CAP).unwrap();
    std::fs::write(scratch.join(".mcp.json"), MINIMAL_MCP_JSON).unwrap();

    let mut s = Session::spawn(&scratch, &policy_path);
    let init_resp = s.handshake();
    assert!(
        init_resp["result"]["protocolVersion"].is_string(),
        "initialize must succeed even in blocked mode: {init_resp}"
    );

    s.send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let resp = s.recv();
    let tools = resp["result"]["tools"]
        .as_array()
        .expect("tools/list result must have a tools array");
    assert_eq!(
        tools.len(),
        1,
        "blocked mode must advertise exactly one tool, got: {tools:?}"
    );
    assert_eq!(
        tools[0]["name"].as_str(),
        Some("denyx_blocked"),
        "the one advertised tool must be denyx_blocked"
    );
    let desc = tools[0]["description"]
        .as_str()
        .expect("description must be a string");
    assert!(
        desc.contains("BLOCKED"),
        "description must surface the BLOCKED state to the model"
    );
    assert!(
        desc.contains("denyx doctor --fix"),
        "description must point at the canonical fix command"
    );

    s.close();
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn blocked_mode_returns_blocked_payload_on_any_tools_call() {
    let scratch = make_scratch("tools_call");
    let policy_path = scratch.join("denyx.toml");
    std::fs::write(&policy_path, POLICY_WITH_UNGRANTED_CAP).unwrap();
    std::fs::write(scratch.join(".mcp.json"), MINIMAL_MCP_JSON).unwrap();

    let mut s = Session::spawn(&scratch, &policy_path);
    s.handshake();

    // Calling `denyx_run` (the would-be primary tool) returns the
    // blocked payload instead of running anything.
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_run", "arguments": {"script": "print(1)"}}
    }));
    let resp = s.recv();
    let result = &resp["result"];
    assert_eq!(
        result["isError"], true,
        "blocked tools/call must mark isError=true: {resp}"
    );
    assert_eq!(
        result["denyx_error_kind"].as_str(),
        Some("blocked_startup"),
        "error kind tag must be present so hosts can route on it"
    );
    let text = result["content"][0]["text"]
        .as_str()
        .expect("blocked payload must include a text content block");
    assert!(
        text.contains("denyx doctor --fix"),
        "blocked payload text must include the auto-fix instruction"
    );
    assert!(
        text.contains("manually"),
        "blocked payload text must include the manual-fix instruction"
    );

    // Calling `denyx_blocked` itself returns the same payload.
    s.send(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "denyx_blocked", "arguments": {}}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(
        resp["result"]["denyx_error_kind"].as_str(),
        Some("blocked_startup"),
    );

    s.close();
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn first_run_guard_no_host_configs_starts_normally() {
    // A project with a denyx.toml that *would* trigger criticals,
    // but no host-config files at all (simulating the first run
    // before `denyx host-config` was invoked). The first-run guard
    // skips the consistency check, and the server starts normally
    // — meaning `tools/list` returns the full set, not just
    // `denyx_blocked`.
    let scratch = make_scratch("first_run");
    let policy_path = scratch.join("denyx.toml");
    std::fs::write(&policy_path, POLICY_WITH_UNGRANTED_CAP).unwrap();
    // No .mcp.json / opencode.json / .cursor/ / .vscode/ /
    // .continue/ — host_configs is empty.

    let mut s = Session::spawn(&scratch, &policy_path);
    s.handshake();

    s.send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let resp = s.recv();
    let tools = resp["result"]["tools"].as_array().unwrap();
    assert!(
        tools.len() > 1,
        "first-run case must advertise the full tool set, not just denyx_blocked. Got: {}",
        tools
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        names.contains(&"denyx_run"),
        "first-run tools/list must include denyx_run. Got: {names:?}"
    );
    assert!(
        !names.contains(&"denyx_blocked"),
        "first-run tools/list must not include denyx_blocked. Got: {names:?}"
    );

    s.close();
    let _ = std::fs::remove_dir_all(&scratch);
}
