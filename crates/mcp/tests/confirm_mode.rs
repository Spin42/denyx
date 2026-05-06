//! Integration tests for `aegis-mcp --confirm-mode`.
//!
//! Spawns the compiled `aegis-mcp` binary, hands it a policy with
//! `requires_approval = ["fs.write"]`, drives the JSON-RPC protocol
//! enough to issue an `aegis_run` of a `fs.write` script, and
//! asserts on the response shape:
//!
//! - `auto-allow` (default): the call goes through, isError=false.
//! - `auto-deny`: the call fails with isError=true and a tagged
//!   `aegis_error_kind: "confirm_denied"` so the orchestrator can
//!   branch on it programmatically.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_aegis-mcp");

fn write_policy(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aegis_mcp_confirm_{}_{}_{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("aegis.toml");
    std::fs::write(&path, body).unwrap();
    path
}

/// Send three JSON-RPC messages — `initialize`, the
/// `notifications/initialized` notice, and `tools/call` for
/// `aegis_run` — to a freshly-spawned aegis-mcp; return the parsed
/// response to the `tools/call`.
fn drive_aegis_run(policy: &PathBuf, confirm_mode: &str, script: &str) -> serde_json::Value {
    let mut child = Command::new(BIN)
        .arg("--policy")
        .arg(policy)
        .arg("--confirm-mode")
        .arg(confirm_mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aegis-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion":"2024-11-05","capabilities":{}},
    });
    writeln!(stdin, "{init}").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    line.clear();

    let init_done = serde_json::json!({
        "jsonrpc":"2.0","method":"notifications/initialized","params":{}
    });
    writeln!(stdin, "{init_done}").unwrap();
    reader.read_line(&mut line).unwrap();
    line.clear();

    let call = serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"aegis_run","arguments":{"script": script}},
    });
    writeln!(stdin, "{call}").unwrap();
    reader.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).expect("parse response");

    drop(stdin);
    let _ = child.wait();
    resp
}

#[test]
fn auto_allow_lets_confirm_gated_call_through() {
    let dir_for_writes =
        std::env::temp_dir().join(format!("aegis_mcp_writes_{}_a", std::process::id()));
    std::fs::create_dir_all(&dir_for_writes).unwrap();
    let abs = dir_for_writes.to_string_lossy().replace('\\', "/");
    let body = format!(
        r#"
requires_approval = ["fs.write"]

[filesystem]
write_allow = ["{abs}/**"]
"#
    );
    let policy = write_policy("auto_allow", &body);
    let script = format!(r#"fs.write("{abs}/x.txt", "hello")"#);

    let resp = drive_aegis_run(&policy, "auto-allow", &script);
    let result = &resp["result"];
    assert_eq!(
        result["isError"], false,
        "auto-allow should let confirm-gated calls through, got: {result}"
    );

    let _ = std::fs::remove_dir_all(&dir_for_writes);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(policy.parent().unwrap());
}

#[test]
fn auto_deny_blocks_confirm_gated_call_with_tagged_error() {
    let dir_for_writes =
        std::env::temp_dir().join(format!("aegis_mcp_writes_{}_d", std::process::id()));
    std::fs::create_dir_all(&dir_for_writes).unwrap();
    let abs = dir_for_writes.to_string_lossy().replace('\\', "/");
    let body = format!(
        r#"
requires_approval = ["fs.write"]

[filesystem]
write_allow = ["{abs}/**"]
"#
    );
    let policy = write_policy("auto_deny", &body);
    let script = format!(r#"fs.write("{abs}/y.txt", "hello")"#);

    let resp = drive_aegis_run(&policy, "auto-deny", &script);
    let result = &resp["result"];
    assert_eq!(result["isError"], true, "auto-deny should fail: {result}");
    // The structured kind tag is what the orchestrator branches on.
    assert_eq!(
        result["aegis_error_kind"], "confirm_denied",
        "auto-deny on confirm-gated call should tag confirm_denied: {result}"
    );
    // The text mentions the capability so a UI can show it to the user.
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("fs.write"),
        "error text should name the capability: {text}"
    );

    // Confirm the file was NOT written (denial happened before action).
    assert!(!dir_for_writes.join("y.txt").exists());

    let _ = std::fs::remove_dir_all(&dir_for_writes);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_dir(policy.parent().unwrap());
}
