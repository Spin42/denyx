//! End-to-end integration test for `denyx-local-mcp`.
//!
//! Spawns the real binary, with:
//!   - a real `denyx-mcp` child (resolved from the workspace target/
//!     dir; built on demand if missing — same trick as
//!     `crates/cli/tests/setup_flow.rs`),
//!   - an in-process mock HTTP server playing the OpenAI v1 API
//!     (`/chat/completions`, `/embeddings`) — the same shape every
//!     supported local server exposes (Ollama via `/v1`, llama.cpp,
//!     LM Studio, vLLM, LocalAI, etc.).
//!
//! Exercises the full pipeline: orchestrator → `delegate_to_local`
//! → mock chat returns a Starlark program → child denyx-mcp runs it
//! under policy → outcome flows back. Also covers the retry path
//! (first chat returns bad code, mock returns good code on retry).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_denyx-local-mcp");

// ─────────────────────── helpers ───────────────────────

fn workspace_target_dir() -> PathBuf {
    PathBuf::from(BIN)
        .parent()
        .expect("denyx-local-mcp parent dir")
        .to_path_buf()
}

/// Resolve denyx-mcp; build on demand if missing under the workspace
/// target/. Mirrors the pattern in `crates/cli/tests/setup_flow.rs`.
fn ensure_denyx_mcp() -> PathBuf {
    let target = workspace_target_dir();
    let mcp = target.join(if cfg!(windows) {
        "denyx-mcp.exe"
    } else {
        "denyx-mcp"
    });
    if !mcp.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "--bin", "denyx-mcp", "--quiet"])
            .status()
            .expect("spawn cargo build --bin denyx-mcp");
        assert!(
            status.success(),
            "failed to build denyx-mcp; cannot run end-to-end test"
        );
    }
    mcp
}

fn unique_tempdir(prefix: &str) -> PathBuf {
    // Use the workspace target dir, NOT /tmp, to avoid the
    // self-writable guard hitting on policies whose write_allow
    // covers `/tmp/**`.
    let base = workspace_target_dir().join("local-mcp-tmp").join(format!(
        "{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

/// Write a minimal policy that allows `print(...)` and basic stdlib
/// usage, but nothing else. This is enough for the test programs we
/// use (which only print a string).
fn write_minimal_policy(dir: &std::path::Path) -> PathBuf {
    let body = r#"
inherits = "secure-defaults"

# Pure-print scripts don't need any allowlists, but we explicitly
# avoid /tmp/** in write_allow because the tempdir lives under
# target/ — keeping the self-writable guard happy.
[filesystem]
write_allow = ["/opt/myproj/**"]
"#;
    let p = dir.join("denyx.toml");
    std::fs::write(&p, body).unwrap();
    p
}

// ─────────────────────── mock Ollama server ───────────────────────

struct MockOllama {
    addr: SocketAddr,
    state: Arc<MockState>,
}

struct MockState {
    /// Chat responses to return, in order. Each entry's `String` is
    /// what the mock puts in `message.content`.
    chat_queue: Mutex<Vec<String>>,
    chat_calls: AtomicUsize,
    embed_calls: AtomicUsize,
}

impl MockOllama {
    fn new(chat_responses: Vec<&str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let addr = listener.local_addr().expect("addr");
        let state = Arc::new(MockState {
            chat_queue: Mutex::new(chat_responses.into_iter().map(String::from).collect()),
            chat_calls: AtomicUsize::new(0),
            embed_calls: AtomicUsize::new(0),
        });
        let s_clone = state.clone();
        thread::spawn(move || run_mock_server(listener, s_clone));
        Self { addr, state }
    }
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    fn chat_calls(&self) -> usize {
        self.state.chat_calls.load(Ordering::SeqCst)
    }
    fn embed_calls(&self) -> usize {
        self.state.embed_calls.load(Ordering::SeqCst)
    }
}

fn run_mock_server(listener: TcpListener, state: Arc<MockState>) {
    listener.set_nonblocking(false).ok();
    for stream in listener.incoming().flatten() {
        let s = state.clone();
        thread::spawn(move || {
            let _ = handle_client(stream, s);
        });
    }
}

fn handle_client(mut stream: TcpStream, state: Arc<MockState>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = [0u8; 16 * 1024];
    let mut all = Vec::new();
    // Read until we have headers + content-length bytes.
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        all.extend_from_slice(&buf[..n]);
        // Quick check: do we have \r\n\r\n yet?
        if let Some(headers_end) = find_subseq(&all, b"\r\n\r\n") {
            let header_str = std::str::from_utf8(&all[..headers_end]).unwrap_or("");
            let cl = parse_content_length(header_str).unwrap_or(0);
            let body_start = headers_end + 4;
            if all.len() >= body_start + cl {
                break;
            }
        }
    }
    let headers_end = find_subseq(&all, b"\r\n\r\n").unwrap_or(0);
    let header_str = std::str::from_utf8(&all[..headers_end]).unwrap_or("");
    let body_start = headers_end + 4;
    let body = if body_start < all.len() {
        &all[body_start..]
    } else {
        &[][..]
    };

    let request_line = header_str.lines().next().unwrap_or("");
    // Doctor-side endpoints (Ollama-native + OpenAI-compat /models).
    if request_line.starts_with("GET /api/version") {
        let resp_body = serde_json::to_string(&json!({
            "version": "0.5.7-mock"
        }))
        .unwrap();
        write_json_response(&mut stream, 200, &resp_body)?;
        return Ok(());
    }
    if request_line.starts_with("POST /api/show") {
        // Echo back a fixed parameters blob with num_ctx=8192 so the
        // doctor's Ollama context check passes by default.
        let resp_body = serde_json::to_string(&json!({
            "parameters": "num_ctx 8192\nstop \"<|im_start|>\"\n",
        }))
        .unwrap();
        write_json_response(&mut stream, 200, &resp_body)?;
        return Ok(());
    }
    if request_line.starts_with("GET /models") || request_line.starts_with("GET /v1/models") {
        // OpenAI-shape models list; advertise the ones the test
        // configures via --model and --embed-model.
        let resp_body = serde_json::to_string(&json!({
            "object": "list",
            "data": [
                { "id": "qwen2.5-coder:7b", "object": "model" },
                { "id": "nomic-embed-text", "object": "model" }
            ]
        }))
        .unwrap();
        write_json_response(&mut stream, 200, &resp_body)?;
        return Ok(());
    }
    if request_line.contains("/chat/completions") {
        state.chat_calls.fetch_add(1, Ordering::SeqCst);
        let mut q = state.chat_queue.lock().unwrap();
        let canned = if q.is_empty() {
            "print('default')".to_string()
        } else {
            q.remove(0)
        };
        // OpenAI shape: `{choices: [{message: {content, role}}]}`
        let resp_body = serde_json::to_string(&json!({
            "id": "test-1",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": canned },
                "finish_reason": "stop"
            }]
        }))
        .unwrap();
        write_json_response(&mut stream, 200, &resp_body)?;
    } else if request_line.contains("/embeddings") {
        state.embed_calls.fetch_add(1, Ordering::SeqCst);
        // Deterministic pseudo-embedding from the request body length.
        let dim = 16;
        let seed = body.len() as f32;
        let v: Vec<f32> = (0..dim).map(|i| (seed + i as f32) * 0.01).collect();
        // OpenAI shape: `{data: [{embedding: [...]}]}`.
        let resp_body = serde_json::to_string(&json!({
            "object": "list",
            "data": [{
                "object": "embedding",
                "index": 0,
                "embedding": v
            }]
        }))
        .unwrap();
        write_json_response(&mut stream, 200, &resp_body)?;
    } else {
        write_json_response(&mut stream, 404, "{}")?;
    }
    Ok(())
}

fn write_json_response(stream: &mut TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream.write_all(resp.as_bytes())
}

fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some(rest) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            return rest.trim().parse::<usize>().ok();
        }
    }
    None
}

// ─────────────────────── JSON-RPC session driver ───────────────────────

struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    line: String,
}

impl Session {
    fn spawn(args: &[String]) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn denyx-local-mcp");
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
        writeln!(self.stdin, "{line}").expect("write");
    }
    fn recv(&mut self) -> Value {
        self.line.clear();
        let n = self
            .stdout
            .read_line(&mut self.line)
            .expect("read line from denyx-local-mcp");
        assert!(n > 0, "denyx-local-mcp closed stdout unexpectedly");
        serde_json::from_str(self.line.trim()).expect("parse line")
    }
    fn handshake(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}}
        }));
        let _ = self.recv();
    }
    fn close(mut self) {
        drop(self.stdin);
        let start = std::time::Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if start.elapsed() >= Duration::from_secs(5) => {
                    let _ = self.child.kill();
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
        }
    }
}

// ─────────────────────── Tests ───────────────────────

#[test]
fn end_to_end_delegate_to_local_runs_program_and_returns_output() {
    let mcp_bin = ensure_denyx_mcp();
    let tmp = unique_tempdir("e2e_basic");
    let policy = write_minimal_policy(&tmp);
    let mock = MockOllama::new(vec!["print('hello from local')"]);

    let args = vec![
        "serve".into(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--mcp-bin".into(),
        mcp_bin.to_string_lossy().into_owned(),
        "--endpoint".into(),
        mock.url(),
        "--no-precompute".into(),
    ];

    let mut s = Session::spawn(&args);
    s.handshake();

    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }));
    let listed = s.recv();
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "delegate_to_local");

    s.send(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "delegate_to_local",
            "arguments": { "step": "print a hello message" }
        }
    }));
    let resp = s.recv();
    let result = &resp["result"];
    let body = result["content"][0]["text"].as_str().unwrap();
    assert!(
        body.contains("--- Starlark program executed ---"),
        "missing program section in: {body}"
    );
    assert!(
        body.contains("print('hello from local')"),
        "expected program text in: {body}"
    );
    assert!(
        body.contains("--- Denyx result ---"),
        "missing denyx result section: {body}"
    );
    assert!(
        body.contains("hello from local"),
        "expected program output in: {body}"
    );
    assert_eq!(result["isError"], false);
    assert!(mock.chat_calls() >= 1);

    s.close();
}

#[test]
fn end_to_end_retries_on_parse_error_then_succeeds() {
    let mcp_bin = ensure_denyx_mcp();
    let tmp = unique_tempdir("e2e_retry");
    let policy = write_minimal_policy(&tmp);
    // First response: top-level for-loop (Denyx rejects: not allowed
    // at module level). Second: a valid print.
    let mock = MockOllama::new(vec![
        "for x in [1,2,3]:\n    print(x)",
        "print('after retry')",
    ]);

    let args = vec![
        "serve".into(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--mcp-bin".into(),
        mcp_bin.to_string_lossy().into_owned(),
        "--endpoint".into(),
        mock.url(),
        "--no-precompute".into(),
    ];

    let mut s = Session::spawn(&args);
    s.handshake();

    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "delegate_to_local",
            "arguments": { "step": "iterate over a list" }
        }
    }));
    let resp = s.recv();
    let body = resp["result"]["content"][0]["text"].as_str().unwrap();
    // Should report retries=1 in the header.
    assert!(
        body.contains("retries=1"),
        "expected retries=1 header in: {body}"
    );
    assert!(
        body.contains("after retry"),
        "expected post-retry program output in: {body}"
    );
    assert_eq!(resp["result"]["isError"], false);
    assert_eq!(
        mock.chat_calls(),
        2,
        "exactly 1 initial chat + 1 retry chat"
    );

    s.close();
}

#[test]
fn end_to_end_policy_violation_does_not_retry() {
    let mcp_bin = ensure_denyx_mcp();
    let tmp = unique_tempdir("e2e_policy_deny");
    let policy = write_minimal_policy(&tmp);
    // Mock returns a script that tries to read a file outside the
    // allowed read paths — that's a policy violation, not a parse
    // error, so we should NOT retry.
    let mock = MockOllama::new(vec!["print(fs.read('/etc/passwd'))"]);

    let args = vec![
        "serve".into(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--mcp-bin".into(),
        mcp_bin.to_string_lossy().into_owned(),
        "--endpoint".into(),
        mock.url(),
        "--no-precompute".into(),
    ];

    let mut s = Session::spawn(&args);
    s.handshake();

    s.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "delegate_to_local",
            "arguments": { "step": "read a system file" }
        }
    }));
    let resp = s.recv();
    let body = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        body.contains("retries=0"),
        "policy violations are terminal; expected retries=0 in: {body}"
    );
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(
        mock.chat_calls(),
        1,
        "policy violation must not trigger a chat retry"
    );

    s.close();
}

#[test]
fn end_to_end_fails_fast_when_mcp_bin_missing() {
    let tmp = unique_tempdir("e2e_no_mcp");
    let policy = write_minimal_policy(&tmp);
    // Point at a path that definitely doesn't exist.
    let bogus = tmp.join("not-here-denyx-mcp");
    let mock = MockOllama::new(vec![]);
    let args = vec![
        "serve".into(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--mcp-bin".into(),
        bogus.to_string_lossy().into_owned(),
        "--endpoint".into(),
        mock.url(),
        "--no-precompute".into(),
    ];
    let out = Command::new(BIN).args(&args).output().expect("spawn");
    assert!(
        !out.status.success(),
        "should exit non-zero when --mcp-bin doesn't exist"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("denyx-mcp binary not found"),
        "expected explicit error; got: {stderr}"
    );
}

#[test]
fn end_to_end_precompute_warms_embedding_cache() {
    let mcp_bin = ensure_denyx_mcp();
    let tmp = unique_tempdir("e2e_precompute");
    let policy = write_minimal_policy(&tmp);
    let mock = MockOllama::new(vec!["print('ok')"]);

    let args = vec![
        "serve".into(),
        "--policy".into(),
        policy.to_string_lossy().into_owned(),
        "--mcp-bin".into(),
        mcp_bin.to_string_lossy().into_owned(),
        "--endpoint".into(),
        mock.url(),
        // NOT passing --no-precompute, so precompute should fire.
    ];

    let mut s = Session::spawn(&args);
    s.handshake();
    // After init, there should already have been EXAMPLES.len()
    // embedding calls from the precompute step.
    let lib_size = denyx_local_mcp::rag::EXAMPLES.len();
    // Allow some slack for races; precompute runs before stdin loop.
    let calls_after_init = mock.embed_calls();
    assert!(
        calls_after_init >= lib_size,
        "expected at least {lib_size} embed calls after precompute; got {calls_after_init}"
    );
    s.close();
}

// ─────────────────────── Doctor subcommand ───────────────────────

fn run_doctor(endpoint: &str, model: &str, embed_model: &str) -> std::process::Output {
    Command::new(BIN)
        .args([
            "doctor",
            "--endpoint",
            endpoint,
            "--model",
            model,
            "--embed-model",
            embed_model,
        ])
        .output()
        .expect("spawn denyx-local-mcp doctor")
}

#[test]
fn doctor_passes_when_models_present_and_num_ctx_ok() {
    let mock = MockOllama::new(vec![]);
    // Mock identifies as Ollama (via /api/version), serves the
    // configured chat + embed models in /models, and returns
    // num_ctx=8192 from /api/show.
    let out = run_doctor(&mock.url(), "qwen2.5-coder:7b", "nomic-embed-text");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "doctor exit {:?}, stdout:\n{stdout}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("Ollama"));
    assert!(stdout.contains("[OK]   chat model"));
    assert!(stdout.contains("[OK]   embed model"));
    assert!(stdout.contains("[OK]   embed call"));
    assert!(stdout.contains("[OK]   ollama num_ctx"));
    assert!(stdout.contains("Ready to use"));
}

#[test]
fn doctor_fails_with_pull_instructions_when_chat_model_missing() {
    let mock = MockOllama::new(vec![]);
    // Ask for a model the mock doesn't advertise.
    let out = run_doctor(&mock.url(), "missing-model:1b", "nomic-embed-text");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing-chat-model should produce exit code 2 (Fail). stdout:\n{stdout}"
    );
    assert!(stdout.contains("[FAIL] chat model"));
    assert!(
        stdout.contains("ollama pull missing-model:1b"),
        "expected pull instruction; stdout:\n{stdout}"
    );
    assert!(stdout.contains("NOT ready"));
}

#[test]
fn doctor_fails_when_endpoint_unreachable() {
    // Bind a port and immediately close it to get a definitively
    // unreachable address. Use 127.0.0.1:1 (port 1 is reserved and
    // typically rejected). 0 picks a free port; we then drop the
    // listener so connecting fails.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let bogus = format!("http://{addr}");
    let out = run_doctor(&bogus, "qwen2.5-coder:7b", "nomic-embed-text");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "unreachable endpoint should exit 2. stdout:\n{stdout}"
    );
    assert!(stdout.contains("(unreachable)") || stdout.contains("[FAIL]"));
    assert!(stdout.contains("NOT ready"));
}
