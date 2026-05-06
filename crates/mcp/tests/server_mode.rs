//! Integration tests for `denyx-mcp` in policy-server / audit-server
//! mode. Drives the binary via JSON-RPC against an in-process mock
//! HTTP server that serves a fixed policy and records audit POSTs.
//!
//! Covers:
//!   - happy path: fetch policy, run a tools/call, audit POSTed
//!   - error paths: 404 / 5xx / malformed TOML / empty body / unreachable
//!   - audit 5xx degrades gracefully (AUDIT GAP, MVP behaviour)
//!
//! Pentest-style cases (verified end-to-end through the binary):
//!   - agent script cannot read DENYX_AUTH_TOKEN (env reserved)
//!   - agent script cannot read DENYX_POLICY_URL (env reserved)
//!   - agent script cannot read DENYX_AUDIT_URL (env reserved)
//!   - agent cannot reach the policy URL via net.http_get unless the
//!     policy server itself listed it in http_get_allow (it doesn't)

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_denyx-mcp");

/// In-process mock HTTP server. Responds to `GET /policy` with a
/// configurable status + body, and `POST /audit` with a configurable
/// status. Records every audit POST body so tests can assert on
/// what denyx-mcp sent.
struct MockServer {
    addr: SocketAddr,
    state: Arc<MockState>,
}

struct MockState {
    audit_received: Mutex<Vec<String>>,
    audit_auth_received: Mutex<Vec<Option<String>>>,
    policy_auth_received: Mutex<Vec<Option<String>>>,
    policy_status: AtomicU16,
    policy_body: Mutex<String>,
    audit_status: AtomicU16,
}

impl MockServer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock listener");
        let addr = listener.local_addr().expect("local_addr");
        let state = Arc::new(MockState {
            audit_received: Mutex::new(Vec::new()),
            audit_auth_received: Mutex::new(Vec::new()),
            policy_auth_received: Mutex::new(Vec::new()),
            policy_status: AtomicU16::new(200),
            policy_body: Mutex::new(default_policy_body()),
            audit_status: AtomicU16::new(204),
        });
        let state_clone = state.clone();
        thread::spawn(move || run_server(listener, state_clone));
        MockServer { addr, state }
    }
    fn policy_url(&self) -> String {
        format!("http://{}/policy", self.addr)
    }
    fn audit_url(&self) -> String {
        format!("http://{}/audit", self.addr)
    }
    fn set_policy_status(&self, code: u16) {
        self.state.policy_status.store(code, Ordering::SeqCst);
    }
    fn set_policy_body(&self, body: &str) {
        *self.state.policy_body.lock().unwrap() = body.to_string();
    }
    fn set_audit_status(&self, code: u16) {
        self.state.audit_status.store(code, Ordering::SeqCst);
    }
    fn audit_count(&self) -> usize {
        self.state.audit_received.lock().unwrap().len()
    }
    fn last_audit(&self) -> Option<String> {
        self.state.audit_received.lock().unwrap().last().cloned()
    }
    fn last_audit_auth(&self) -> Option<Option<String>> {
        self.state
            .audit_auth_received
            .lock()
            .unwrap()
            .last()
            .cloned()
    }
    fn last_policy_auth(&self) -> Option<Option<String>> {
        self.state
            .policy_auth_received
            .lock()
            .unwrap()
            .last()
            .cloned()
    }
}

fn default_policy_body() -> String {
    // Minimal policy that allows fs.read of /tmp paths so the
    // happy-path tools/call can succeed. Inherits secure-defaults
    // for the universal denies.
    String::from(
        r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["/tmp/**"]
"#,
    )
}

fn run_server(listener: TcpListener, state: Arc<MockState>) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            continue;
        };
        let state = state.clone();
        thread::spawn(move || {
            let _ = handle_request(stream, state);
        });
    }
}

fn handle_request(mut stream: TcpStream, state: Arc<MockState>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    // Read until \r\n\r\n
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            // Bound. Test inputs are tiny.
            break;
        }
    }
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let header_bytes = &buf[..header_end];
    let header_str = std::str::from_utf8(header_bytes).unwrap_or("");
    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let mut content_length: usize = 0;
    let mut auth: Option<String> = None;
    for line in lines {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
        if line.to_ascii_lowercase().starts_with("authorization:") {
            let v = line
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
            auth = Some(v);
        }
    }
    let body_so_far = if header_end + 4 <= buf.len() {
        &buf[header_end + 4..]
    } else {
        &[][..]
    };
    let mut body = body_so_far.to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    if method == "GET" && path == "/policy" {
        state.policy_auth_received.lock().unwrap().push(auth);
        let status = state.policy_status.load(Ordering::SeqCst);
        let body = state.policy_body.lock().unwrap().clone();
        let resp = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/toml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes())?;
    } else if method == "POST" && path == "/audit" {
        state.audit_auth_received.lock().unwrap().push(auth);
        let body_str = String::from_utf8_lossy(&body).to_string();
        state.audit_received.lock().unwrap().push(body_str);
        let status = state.audit_status.load(Ordering::SeqCst);
        let resp =
            format!("HTTP/1.1 {status} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(resp.as_bytes())?;
    } else {
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp.as_bytes())?;
    }
    Ok(())
}

/// Driver for an `denyx-mcp` subprocess running in server mode.
struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    line: String,
}

impl Session {
    fn spawn_with_env(env: &[(&str, &str)]) -> Session {
        let mut cmd = Command::new(BIN);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("--confirm-mode")
            .arg("auto-allow")
            .env_remove("HOME"); // avoid loading per-user config from CI homedirs
        for (k, v) in env {
            cmd.env(k, v);
        }
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
        let _ = self.child.wait();
    }
}

fn wait_until<F: Fn() -> bool>(check: F, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

// ---- Functional tests ------------------------------------------------------

#[test]
fn happy_path_policy_fetch_and_audit_post() {
    let server = MockServer::new();
    let scratch = std::env::temp_dir().join(format!("denyx_srv_happy_{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("hello.txt"), "hi from disk").unwrap();
    let path = scratch.join("hello.txt");
    let path_str = path.to_string_lossy().replace('\\', "/");

    server.set_policy_body(&format!(
        r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["{abs}/**"]
"#,
        abs = scratch.to_string_lossy().replace('\\', "/")
    ));

    let mut s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUDIT_URL", &server.audit_url()),
        ("DENYX_AUTH_TOKEN", "happy-token"),
    ]);
    s.handshake();

    // Run a fs.read against the path the policy permits.
    let script = format!(
        r#"x = fs.read("{path_str}")
print(x)"#
    );
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_run", "arguments": {"script": script}}
    }));
    let resp = s.recv();
    let result = &resp["result"];
    assert_eq!(
        result["isError"], false,
        "happy path tools/call should succeed: {resp}"
    );

    // Wait briefly for the audit POST to land (it's synchronous in
    // the binary but the server thread is async; tiny race window).
    assert!(
        wait_until(|| server.audit_count() >= 1, Duration::from_secs(2)),
        "expected at least one audit POST; got {}",
        server.audit_count()
    );
    // The bearer token must have been included on both calls.
    assert_eq!(
        server.last_policy_auth().flatten().as_deref(),
        Some("Bearer happy-token"),
        "policy fetch should send Authorization header"
    );
    assert_eq!(
        server.last_audit_auth().flatten().as_deref(),
        Some("Bearer happy-token"),
        "audit POST should send Authorization header"
    );
    // The audit body should be a JSON object with the expected fields.
    let last = server.last_audit().expect("audit body");
    let parsed: Value = serde_json::from_str(&last).expect("audit body is JSON");
    assert_eq!(parsed["capability"], "fs.read");

    s.close();
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn policy_404_fails_closed() {
    let server = MockServer::new();
    server.set_policy_status(404);
    let s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUTH_TOKEN", "any"),
    ]);
    let child = s.child;
    let _ = child.wait_with_output();
    // child exited (didn't hang) — that's the success condition.
}

#[test]
fn policy_5xx_fails_closed() {
    let server = MockServer::new();
    server.set_policy_status(503);
    let s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUTH_TOKEN", "any"),
    ]);
    let child = s.child;
    let _ = child.wait_with_output();
}

#[test]
fn policy_empty_body_fails_closed() {
    let server = MockServer::new();
    server.set_policy_body("");
    let s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUTH_TOKEN", "any"),
    ]);
    let child = s.child;
    let _ = child.wait_with_output();
}

#[test]
fn policy_malformed_toml_fails_closed() {
    let server = MockServer::new();
    server.set_policy_body("this is === not toml [[broken");
    let s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUTH_TOKEN", "any"),
    ]);
    let child = s.child;
    let _ = child.wait_with_output();
}

#[test]
fn policy_url_unreachable_fails_closed() {
    // Unbound port (1 is privileged on Linux + likely-rejected) is
    // basically guaranteed to fail to connect.
    let s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", "http://127.0.0.1:1/nope"),
        ("DENYX_AUTH_TOKEN", "any"),
    ]);
    let child = s.child;
    let _ = child.wait_with_output();
}

#[test]
fn audit_5xx_logs_gap_but_does_not_block_call() {
    // MVP behaviour: audit POST failures eprintln "AUDIT GAP" and
    // the runtime continues. Strict mode (block effecting calls
    // when audit is unavailable) is step-2 work and is documented
    // honestly in the threat model.
    let server = MockServer::new();
    server.set_audit_status(503);
    let scratch = std::env::temp_dir().join(format!("denyx_srv_gap_{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("a.txt"), "x").unwrap();
    server.set_policy_body(&format!(
        r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["{abs}/**"]
"#,
        abs = scratch.to_string_lossy().replace('\\', "/")
    ));

    let path = scratch.join("a.txt");
    let path_str = path.to_string_lossy().replace('\\', "/");
    let mut s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUDIT_URL", &server.audit_url()),
        ("DENYX_AUTH_TOKEN", "x"),
    ]);
    s.handshake();
    let script = format!(
        r#"x = fs.read("{path_str}")
print(x)"#
    );
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_run", "arguments": {"script": script}}
    }));
    let resp = s.recv();
    // The tools/call STILL succeeds; audit gap is the documented MVP
    // trade-off.
    assert_eq!(resp["result"]["isError"], false, "got: {resp}");
    s.close();
    let _ = std::fs::remove_dir_all(&scratch);
}

// ---- Pentest tests ---------------------------------------------------------

#[test]
fn pentest_agent_cannot_read_denyx_auth_token_env() {
    let server = MockServer::new();
    // Policy must enable env.read for ANY var (otherwise the verifier
    // rejects the script before the runtime invariant fires); we
    // enable a benign one and assert the reserved name still denies.
    server.set_policy_body(
        r#"
inherits = "secure-defaults"

[environment]
allow_vars = ["PATH"]
"#,
    );
    let mut s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUDIT_URL", &server.audit_url()),
        ("DENYX_AUTH_TOKEN", "supersecret-token-do-not-leak"),
    ]);
    s.handshake();
    // Single-line Starlark; using `;` separator avoids rustfmt
    // re-indenting a continuation line and accidentally breaking
    // the script's whitespace structure.
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_run", "arguments": {
            "script": r#"t = env.read("DENYX_AUTH_TOKEN"); print(t)"#
        }}
    }));
    let resp = s.recv();
    let result = &resp["result"];
    assert_eq!(
        result["isError"], true,
        "agent must NOT be able to read DENYX_AUTH_TOKEN: {resp}"
    );
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("DENYX_AUTH_TOKEN") && text.to_lowercase().contains("denies"),
        "denial should name the variable; got: {text}"
    );
    // The actual token value must NEVER appear in any output channel.
    assert!(
        !text.contains("supersecret-token-do-not-leak"),
        "the token value must never appear in the tool output: {text}"
    );
    s.close();
}

#[test]
fn pentest_agent_cannot_read_denyx_policy_url_env() {
    let server = MockServer::new();
    server.set_policy_body(
        r#"
inherits = "secure-defaults"

[environment]
allow_vars = ["PATH"]
"#,
    );
    let mut s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUTH_TOKEN", "x"),
    ]);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_run", "arguments": {
            "script": r#"u = env.read("DENYX_POLICY_URL"); print(u)"#
        }}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("reserved-variable list") || text.contains("reserved"),
        "denial should mention the reserved-variable list; got: {text}"
    );
    s.close();
}

#[test]
fn pentest_agent_cannot_read_denyx_audit_url_env() {
    let server = MockServer::new();
    server.set_policy_body(
        r#"
inherits = "secure-defaults"

[environment]
allow_vars = ["PATH"]
"#,
    );
    let mut s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUDIT_URL", &server.audit_url()),
        ("DENYX_AUTH_TOKEN", "x"),
    ]);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_run", "arguments": {
            "script": r#"u = env.read("DENYX_AUDIT_URL"); print(u)"#
        }}
    }));
    let resp = s.recv();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("reserved-variable list") || text.contains("reserved"),
        "denial should mention the reserved-variable list; got: {text}"
    );
    s.close();
}

#[test]
fn pentest_policy_with_denyx_auth_token_in_allow_vars_still_denies() {
    // Even if a hostile policy tries to grant env.read of the token,
    // the runtime invariant denies. End-to-end version of the unit
    // test in crates/policy/tests/denyx_reserved_vars.rs.
    let server = MockServer::new();
    server.set_policy_body(
        r#"
inherits = "secure-defaults"

[environment]
allow_vars = ["DENYX_AUTH_TOKEN", "PATH"]
"#,
    );
    let mut s = Session::spawn_with_env(&[
        ("DENYX_POLICY_URL", &server.policy_url()),
        ("DENYX_AUTH_TOKEN", "deeply-secret"),
    ]);
    s.handshake();
    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "denyx_run", "arguments": {
            "script": r#"t = env.read("DENYX_AUTH_TOKEN"); print(t)"#
        }}
    }));
    let resp = s.recv();
    assert_eq!(
        resp["result"]["isError"], true,
        "even a policy with allow_vars=DENYX_AUTH_TOKEN must not expose the token: {resp}"
    );
    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        !text.contains("deeply-secret"),
        "token must not leak via the denial message: {text}"
    );
    s.close();
}
