//! Outer MCP server. Speaks newline-delimited JSON-RPC 2.0 over the
//! given reader/writer (typically stdin/stdout) and exposes one tool,
//! `delegate_to_local`. Each `tools/call` invocation runs through
//! [`crate::pipeline::execute_step`].
//!
//! The server is stream-driven (loop-over-lines), single-threaded —
//! same shape as `local_mcp.py`. Concurrent tool calls aren't
//! supported because the shared `denyx-mcp` subprocess speaks a
//! one-request-at-a-time JSON-RPC protocol.

use std::io::{BufRead, Write};
use std::sync::Mutex;

use anyhow::Result;
use serde_json::{json, Value};

use crate::pipeline::{execute_step, DenyxRunner, StepConfig};
use crate::provider::ChatProvider;
use crate::rag::EmbedProvider;

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "local-executor";
const SERVER_VERSION: &str = "0.1.0";

/// Trace event emitted on every step. The CLI optionally appends
/// these to a JSONL trace file for post-hoc analysis.
#[derive(Debug, Clone)]
pub struct TraceEvent {
    pub ts: f64,
    pub step: String,
    pub script: String,
    pub result: String,
    pub is_error: bool,
    pub retries: u32,
    pub duration_ms: u64,
}

impl TraceEvent {
    pub fn to_json(&self) -> Value {
        json!({
            "ts": self.ts,
            "step": self.step,
            "script": self.script,
            "result": self.result,
            "is_error": self.is_error,
            "retries": self.retries,
            "duration_ms": self.duration_ms,
        })
    }
}

/// Optional sink for trace events. `()` is the no-op default. The
/// method takes `&self` (no `&mut`) so a `Box<dyn TraceSink>` can be
/// shared without a Mutex; impls that need internal mutation (e.g.
/// caching a file handle) can use interior mutability.
pub trait TraceSink: Send + Sync {
    fn emit(&self, event: &TraceEvent);
}

impl TraceSink for () {
    fn emit(&self, _event: &TraceEvent) {}
}

/// Blanket: `Box<dyn TraceSink>` is itself a `TraceSink`.
impl<T: ?Sized + TraceSink> TraceSink for Box<T> {
    fn emit(&self, event: &TraceEvent) {
        (**self).emit(event)
    }
}

/// Append-to-file sink. Opens, appends, closes on every call. POSIX
/// guarantees small writes are atomic, so concurrent emits don't
/// interleave at the line level. Best-effort: I/O errors are
/// swallowed because a trace failure shouldn't break the
/// orchestrator's tool call.
pub struct FileTraceSink {
    path: std::path::PathBuf,
}

impl FileTraceSink {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl TraceSink for FileTraceSink {
    fn emit(&self, event: &TraceEvent) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{}", event.to_json());
        }
    }
}

/// Run the JSON-RPC server loop. Reads requests from `input` line by
/// line, writes responses to `output`, returns when `input` reaches
/// EOF or an unrecoverable error occurs.
///
/// Returning Ok means the server shut down cleanly (EOF on stdin).
/// Returning Err means write failures on `output` — the orchestrator
/// likely went away.
#[allow(clippy::too_many_arguments)]
pub fn run<I, O, C, E, R, T>(
    mut input: I,
    output: &Mutex<O>,
    chat: &C,
    embed: &E,
    denyx: &R,
    cfg: &StepConfig,
    counter: &Mutex<u64>,
    trace: &T,
) -> Result<()>
where
    I: BufRead,
    O: Write,
    C: ChatProvider + ?Sized,
    E: EmbedProvider + ?Sized,
    R: DenyxRunner + ?Sized,
    T: TraceSink + ?Sized,
{
    let mut line = String::new();
    loop {
        line.clear();
        let n = input.read_line(&mut line)?;
        if n == 0 {
            break; // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                write_response(
                    output,
                    &make_response(
                        Value::Null,
                        None,
                        Some(json!({"code": -32700, "message": format!("parse error: {e}")})),
                    ),
                )?;
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!({}));

        let resp = match method {
            "initialize" => make_response(
                id,
                Some(json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                })),
                None,
            ),
            "initialized" | "notifications/initialized" => make_response(id, Some(json!({})), None),
            "tools/list" => make_response(id, Some(json!({"tools": tool_definitions()})), None),
            "tools/call" => handle_tool_call(id, &params, chat, embed, denyx, cfg, counter, trace),
            "ping" => make_response(id, Some(json!({})), None),
            other => make_response(
                id,
                None,
                Some(json!({
                    "code": -32601,
                    "message": format!("method not found: {other}"),
                })),
            ),
        };
        write_response(output, &resp)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_tool_call<C, E, R, T>(
    id: Value,
    params: &Value,
    chat: &C,
    embed: &E,
    denyx: &R,
    cfg: &StepConfig,
    counter: &Mutex<u64>,
    trace: &T,
) -> Value
where
    C: ChatProvider + ?Sized,
    E: EmbedProvider + ?Sized,
    R: DenyxRunner + ?Sized,
    T: TraceSink + ?Sized,
{
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    if name != "delegate_to_local" {
        return make_response(
            id,
            None,
            Some(json!({"code": -32601, "message": format!("unknown tool: {name}")})),
        );
    }
    let step = args
        .get("step")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if step.trim().is_empty() {
        return make_response(
            id,
            Some(json!({
                "content": [{"type": "text", "text": "missing or empty 'step' argument"}],
                "isError": true,
            })),
            None,
        );
    }

    let t0 = std::time::Instant::now();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let outcome = execute_step(chat, embed, denyx, &step, cfg, counter);
    let dur_ms = t0.elapsed().as_millis() as u64;

    let (text, is_error, retries, script) = match outcome {
        Ok(o) => (o.text, o.is_error, o.retries, o.script),
        Err(e) => (format!("local-executor crash: {e}"), true, 0, String::new()),
    };

    let event = TraceEvent {
        ts: now_secs,
        step: step.clone(),
        script: script.clone(),
        result: text.clone(),
        is_error,
        retries,
        duration_ms: dur_ms,
    };
    trace.emit(&event);

    let header = format!(
        "[local-executor model={model} retries={retries} duration={dur_ms}ms]",
        model = cfg.model,
    );
    let body = format!(
        "{header}\n\n--- Starlark program executed ---\n{script}\n\n--- Denyx result ---\n{text}"
    );
    make_response(
        id,
        Some(json!({
            "content": [{"type": "text", "text": body}],
            "isError": is_error,
        })),
        None,
    )
}

fn write_response<O: Write>(output: &Mutex<O>, resp: &Value) -> Result<()> {
    let mut o = output.lock().expect("output mutex");
    let line = serde_json::to_string(resp)?;
    o.write_all(line.as_bytes())?;
    o.write_all(b"\n")?;
    o.flush()?;
    Ok(())
}

fn make_response(id: Value, result: Option<Value>, error: Option<Value>) -> Value {
    let mut out = json!({"jsonrpc": "2.0", "id": id});
    if let Some(e) = error {
        out["error"] = e;
    } else {
        out["result"] = result.unwrap_or(json!({}));
    }
    out
}

/// MCP `tools/list` definitions. Single tool: `delegate_to_local`.
pub fn tool_definitions() -> Vec<Value> {
    vec![json!({
        "name": "delegate_to_local",
        "description": (
            "Delegate a single step to a local 7B-class executor model \
             (qwen2.5-coder:7b by default) running under the Denyx \
             policy-enforced runtime. The local executor synthesises a \
             Starlark program from your step description and runs it. \
             The program has access to fs.read/write/delete, \
             net.http_get/post, subprocess.exec, env.read, \
             json.encode/decode — every effecting call goes through \
             the Denyx policy (filesystem deny patterns, network \
             host/IP checks, subprocess command and arg gates, env \
             var allow/deny). Returns the program's printed output on \
             success, or the Denyx diagnostic on failure (policy \
             denial, parse error, runtime crash).\n\n\
             Pass ONE atomic step per call. Decompose multi-step \
             plans yourself and dispatch sequentially — each call is \
             independent (no shared state across calls except whatever \
             the program persists to disk)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "step": {
                    "type": "string",
                    "description": "Natural-language description of the single step to execute.",
                }
            },
            "required": ["step"],
        }
    })]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::DenyxRunner;
    use crate::provider::{ChatMessage, ChatProvider};
    use crate::rag::EmbedProvider;
    use std::io::Cursor;
    use std::sync::Mutex;

    struct StubChat(Mutex<Vec<String>>);
    impl ChatProvider for StubChat {
        fn call_chat(&self, _model: &str, _messages: &[ChatMessage]) -> anyhow::Result<String> {
            let mut q = self.0.lock().unwrap();
            if q.is_empty() {
                Err(anyhow::anyhow!("StubChat empty"))
            } else {
                Ok(q.remove(0))
            }
        }
    }
    struct StubEmbed;
    impl EmbedProvider for StubEmbed {
        fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
            Ok(vec![1.0; 4])
        }
    }
    struct StubDenyx(Mutex<Vec<Value>>);
    impl DenyxRunner for StubDenyx {
        fn run(&self, _script: &str, _task_id: &str) -> anyhow::Result<Value> {
            let mut q = self.0.lock().unwrap();
            if q.is_empty() {
                Err(anyhow::anyhow!("StubDenyx empty"))
            } else {
                Ok(q.remove(0))
            }
        }
    }

    fn parse_lines(out: &[u8]) -> Vec<Value> {
        std::str::from_utf8(out)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<Value>(l).expect("valid JSON line"))
            .collect()
    }

    fn run_with_inputs(input: &str, chat: StubChat, denyx: StubDenyx) -> Vec<Value> {
        let reader = Cursor::new(input.as_bytes().to_vec());
        let writer: Vec<u8> = Vec::new();
        let writer = Mutex::new(writer);
        let counter = Mutex::new(0u64);
        let trace: () = ();
        let cfg = StepConfig::default();
        let embed = StubEmbed;
        run(
            reader, &writer, &chat, &embed, &denyx, &cfg, &counter, &trace,
        )
        .unwrap();
        let buf = writer.into_inner().unwrap();
        parse_lines(&buf)
    }

    #[test]
    fn initialize_returns_protocol_version_and_server_info() {
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
"#;
        let chat = StubChat(Mutex::new(vec![]));
        let denyx = StubDenyx(Mutex::new(vec![]));
        let resps = run_with_inputs(input, chat, denyx);
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(resps[0]["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn tools_list_returns_delegate_to_local() {
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
"#;
        let resps = run_with_inputs(
            input,
            StubChat(Mutex::new(vec![])),
            StubDenyx(Mutex::new(vec![])),
        );
        let tools = resps[0]["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "delegate_to_local");
        assert_eq!(tools[0]["inputSchema"]["required"][0], "step");
    }

    #[test]
    fn tools_call_delegate_to_local_runs_pipeline_and_returns_output() {
        let input = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delegate_to_local","arguments":{"step":"say hi"}}}
"#;
        let chat = StubChat(Mutex::new(vec!["print('hi')".into()]));
        let denyx = StubDenyx(Mutex::new(vec![json!({
            "result": {
                "content": [{"type": "text", "text": "hi"}],
                "isError": false
            }
        })]));
        let resps = run_with_inputs(input, chat, denyx);
        assert_eq!(resps.len(), 1);
        let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("--- Starlark program executed ---"));
        assert!(text.contains("print('hi')"));
        assert!(text.contains("--- Denyx result ---"));
        assert!(text.contains("hi"));
        assert_eq!(resps[0]["result"]["isError"], false);
    }

    #[test]
    fn tools_call_unknown_tool_errors() {
        let input = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bogus","arguments":{}}}
"#;
        let resps = run_with_inputs(
            input,
            StubChat(Mutex::new(vec![])),
            StubDenyx(Mutex::new(vec![])),
        );
        assert!(resps[0]["error"].is_object());
        assert!(resps[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown tool"));
    }

    #[test]
    fn tools_call_empty_step_returns_is_error_true() {
        let input = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delegate_to_local","arguments":{"step":"   "}}}
"#;
        let resps = run_with_inputs(
            input,
            StubChat(Mutex::new(vec![])),
            StubDenyx(Mutex::new(vec![])),
        );
        assert_eq!(resps[0]["result"]["isError"], true);
    }

    #[test]
    fn unknown_method_returns_method_not_found_error() {
        let input = r#"{"jsonrpc":"2.0","id":5,"method":"frobnicate","params":{}}
"#;
        let resps = run_with_inputs(
            input,
            StubChat(Mutex::new(vec![])),
            StubDenyx(Mutex::new(vec![])),
        );
        assert!(resps[0]["error"].is_object());
        assert_eq!(resps[0]["error"]["code"], -32601);
    }

    #[test]
    fn malformed_json_returns_parse_error() {
        let input = "{this is not json\n";
        let resps = run_with_inputs(
            input,
            StubChat(Mutex::new(vec![])),
            StubDenyx(Mutex::new(vec![])),
        );
        assert_eq!(resps[0]["error"]["code"], -32700);
    }

    #[test]
    fn ping_returns_empty_result() {
        let input = r#"{"jsonrpc":"2.0","id":6,"method":"ping","params":{}}
"#;
        let resps = run_with_inputs(
            input,
            StubChat(Mutex::new(vec![])),
            StubDenyx(Mutex::new(vec![])),
        );
        assert!(resps[0]["result"].is_object());
    }

    #[test]
    fn pipeline_crash_surfaces_as_error_response_not_panic() {
        let input = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delegate_to_local","arguments":{"step":"go"}}}
"#;
        // Empty chat queue → execute_step will error out.
        let chat = StubChat(Mutex::new(vec![]));
        let denyx = StubDenyx(Mutex::new(vec![]));
        let resps = run_with_inputs(input, chat, denyx);
        assert_eq!(resps[0]["result"]["isError"], true);
        let text = resps[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("local-executor crash"));
    }

    #[test]
    fn trace_event_to_json_includes_all_fields() {
        let e = TraceEvent {
            ts: 1.5,
            step: "s".into(),
            script: "p".into(),
            result: "r".into(),
            is_error: true,
            retries: 2,
            duration_ms: 42,
        };
        let v = e.to_json();
        assert_eq!(v["ts"], 1.5);
        assert_eq!(v["step"], "s");
        assert_eq!(v["is_error"], true);
        assert_eq!(v["retries"], 2);
        assert_eq!(v["duration_ms"], 42);
    }
}
