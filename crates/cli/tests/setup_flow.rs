//! End-to-end setup-flow test. Mirrors the steps the install prompt
//! drives in `examples/denyx-setup-prompt.md`:
//!
//!   1. `denyx init --lang rust --output denyx.toml`
//!   2. `denyx host-config --policy denyx.toml --host claude --platform native`
//!   3. spawn `denyx-mcp` with the *exact* command + args from the
//!      generated `.mcp.json`, send an MCP `initialize` JSON-RPC, then
//!      `tools/call denyx_run`, and verify the policy gate is alive
//!      (one allowed call succeeds, one denied call returns an error).
//!
//! This is a regression guard: if any step of the setup flow stops
//! producing a working server, this test fails. It complements the
//! per-piece unit/integration tests by asserting the *composition*
//! still works.
//!
//! Locating `denyx-mcp`: `CARGO_BIN_EXE_<name>` is only set for the
//! crate that defines the binary; this test lives in `denyx-cli`'s
//! integration tests, so we get `CARGO_BIN_EXE_denyx` for free, then
//! derive `<target_dir>/denyx-mcp` from it. If that binary doesn't
//! exist (e.g. running `cargo test -p denyx-cli` without a prior
//! workspace build), we shell out to `cargo build --bin denyx-mcp`
//! once. Under the standard `cargo test --workspace` invocation the
//! binary is already there.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

const DENYX: &str = env!("CARGO_BIN_EXE_denyx");

fn denyx_mcp_path() -> PathBuf {
    let denyx = PathBuf::from(DENYX);
    let target_dir = denyx.parent().expect("denyx binary has a parent dir");
    let mcp = target_dir.join(if cfg!(windows) {
        "denyx-mcp.exe"
    } else {
        "denyx-mcp"
    });
    if !mcp.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "--bin", "denyx-mcp", "--quiet"])
            .status()
            .expect("spawn cargo build for denyx-mcp");
        assert!(
            status.success(),
            "cargo build --bin denyx-mcp failed; cannot run setup-flow test"
        );
    }
    mcp
}

fn tempdir() -> PathBuf {
    // Deliberately NOT under `/tmp` on Linux: every `denyx init`
    // language template includes `/tmp/**` in `write_allow`, which the
    // self-writable guard would (correctly) flag against any
    // `denyx.toml` written inside `/tmp/...`. Using a directory under
    // the cargo target tree sidesteps that — it's transient (cleaned
    // by `cargo clean`), unique-per-run, and outside any glob the
    // starter templates ship.
    let target_dir = PathBuf::from(DENYX)
        .parent()
        .expect("denyx binary parent dir")
        .to_path_buf();
    let base = target_dir.join("setup-flow-tmp").join(format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn run_denyx(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
    Command::new(DENYX)
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn denyx")
}

fn read_json(path: &std::path::Path) -> Value {
    let body = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&body).expect("json")
}

/// Drive a `denyx-mcp` subprocess via JSON-RPC. Mirrors the `Session`
/// helper in `crates/mcp/tests/server_mode.rs` — kept local so this
/// crate doesn't depend on test fixtures from another crate.
struct Session {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    line: String,
}

impl Session {
    fn spawn(bin: &std::path::Path, args: &[String], cwd: &std::path::Path) -> Self {
        let mut child = Command::new(bin)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn denyx-mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            line: String::new(),
        }
    }
    fn send(&mut self, msg: &Value) {
        let line = serde_json::to_string(msg).unwrap();
        writeln!(self.stdin, "{line}").expect("write stdin");
    }
    fn recv(&mut self) -> Value {
        self.line.clear();
        let n = self.stdout.read_line(&mut self.line).expect("read line");
        assert!(n > 0, "denyx-mcp closed stdout unexpectedly");
        serde_json::from_str(self.line.trim()).expect("parse line")
    }
    fn handshake(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
        }));
        let _ = self.recv();
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        let _ = self.recv();
    }
    fn close(mut self) {
        drop(self.stdin);
        let _ = self.child.wait_timeout(Duration::from_secs(3));
    }
}

// std::process::Child has no `wait_timeout`; provide one so close() can
// give up after a few seconds rather than hanging the test forever if
// denyx-mcp doesn't exit on stdin EOF for some reason.
trait WaitTimeoutExt {
    fn wait_timeout(&mut self, dur: Duration) -> Option<()>;
}

impl WaitTimeoutExt for std::process::Child {
    fn wait_timeout(&mut self, dur: Duration) -> Option<()> {
        let start = std::time::Instant::now();
        loop {
            match self.try_wait() {
                Ok(Some(_)) => return Some(()),
                Ok(None) if start.elapsed() >= dur => {
                    let _ = self.kill();
                    return None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => return None,
            }
        }
    }
}

#[test]
fn setup_flow_init_then_host_config_then_mcp_handshake() {
    let tmp = tempdir();

    // Step 1: `denyx init`
    let out = run_denyx(&["init", "--lang", "rust", "--output", "denyx.toml"], &tmp);
    assert!(
        out.status.success(),
        "denyx init failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let policy_path = tmp.join("denyx.toml");
    assert!(policy_path.exists(), "denyx.toml not written");

    // Step 2: `denyx host-config` (claude only, sandbox off so the test
    // doesn't depend on bubblewrap on the CI host).
    let out = run_denyx(
        &[
            "host-config",
            "--policy",
            "denyx.toml",
            "--host",
            "claude",
            "--platform",
            "native",
            "--sandbox",
            "off",
        ],
        &tmp,
    );
    assert!(
        out.status.success(),
        "host-config failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(tmp.join(".mcp.json").exists(), ".mcp.json not written");
    assert!(
        tmp.join(".claude").join("settings.json").exists(),
        ".claude/settings.json not written"
    );

    // Step 3: read the generated .mcp.json, extract the exact command
    // + args, spawn denyx-mcp.
    let mcp = read_json(&tmp.join(".mcp.json"));
    let entry = &mcp["mcpServers"]["denyx"];
    let command = entry["command"].as_str().expect("command string");
    assert_eq!(command, "denyx-mcp", "expected bare denyx-mcp command");
    let args: Vec<String> = entry["args"]
        .as_array()
        .expect("args array")
        .iter()
        .map(|v| v.as_str().expect("string arg").to_string())
        .collect();
    // Sanity: the args must carry --policy + --audit-log + --confirm-mode.
    assert!(args.iter().any(|a| a == "--policy"));
    assert!(args.iter().any(|a| a == "--audit-log"));
    assert!(args.iter().any(|a| a == "--confirm-mode"));

    let mcp_bin = denyx_mcp_path();
    let mut s = Session::spawn(&mcp_bin, &args, &tmp);
    s.handshake();

    // List tools — should include denyx_run + the sugar fs tools.
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));
    let resp = s.recv();
    let tools = resp["result"]["tools"]
        .as_array()
        .expect("tools array in tools/list response");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        names.contains(&"denyx_run"),
        "expected denyx_run tool, got: {names:?}"
    );

    // Allowed call: a no-op script that touches no capability. The
    // policy is the rust template (inherits secure-defaults); a bare
    // `print` doesn't hit any gate.
    s.send(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": { "script": "print('setup-flow ok')" }
        }
    }));
    let allowed = s.recv();
    assert_eq!(
        allowed["result"]["isError"], false,
        "no-op script should succeed: {allowed}"
    );

    // Denied call: read a path the secure-defaults preset blocks
    // (`/etc/passwd` is outside read_allow). MUST produce an error
    // result — that's how we know the gate is live.
    s.send(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {
            "name": "denyx_run",
            "arguments": { "script": "print(fs.read('/etc/passwd'))" }
        }
    }));
    let denied = s.recv();
    let body = serde_json::to_string(&denied).unwrap();
    let lc = body.to_lowercase();
    assert!(
        denied["result"]["isError"] == true
            || lc.contains("policy")
            || lc.contains("denied")
            || lc.contains("not allowed"),
        "expected gate to deny /etc/passwd; got: {body}"
    );

    s.close();
}
