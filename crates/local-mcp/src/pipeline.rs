//! The local-executor pipeline: step → chat → run → maybe-retry.
//!
//! Mirrors `local_mcp.py`'s `execute_step` with the same retry-on-
//! syntax-error loop. The chat side is abstracted behind
//! [`ChatProvider`] so unit tests can inject a stub that returns a
//! pre-canned program. The Denyx side is abstracted behind
//! [`DenyxRunner`] so unit tests can replace the subprocess with an
//! in-memory fake — same reason.

use anyhow::Result;
use serde_json::Value;

use crate::denyx_client::DenyxMcpClient;
use crate::provider::{strip_fences, ChatMessage, ChatProvider};
use crate::rag::{render_examples, retrieve, EmbedProvider};

/// Hook for "given a Starlark script + task id, return the JSON-RPC
/// response from denyx-mcp." Implemented by [`DenyxMcpClient`] for
/// the production path; unit tests provide a fake.
pub trait DenyxRunner: Send + Sync {
    fn run(&self, script: &str, task_id: &str) -> Result<Value>;
}

impl DenyxRunner for DenyxMcpClient {
    fn run(&self, script: &str, task_id: &str) -> Result<Value> {
        self.denyx_run(script, task_id)
    }
}

/// Result of one step. `text` is what gets surfaced to the orchestrator;
/// `is_error` mirrors the MCP `isError` flag from the Denyx response;
/// `retries` counts the fix-it attempts used (0..=max_retries); `script`
/// is the final script that was sent (post-strip-fences, post-retry).
#[derive(Debug, Clone)]
pub struct StepOutcome {
    pub text: String,
    pub is_error: bool,
    pub retries: u32,
    pub script: String,
}

/// Decide whether a Denyx error is worth retrying. Terminal categories
/// (the model rephrasing the program won't change the outcome):
///
/// - `policy violation: …` — capability denied by policy
/// - `verifier rejected script: …` — capability has no resources
///   allowlisted (verifier blocks the call before exec)
/// - `confirm hook denied …` — interactive denial; rephrasing doesn't
///   affect the operator's decision
/// - `runtime cap exceeded: …` — wall-time / call-stack cap; a fix-it
///   likely loops the same way
///
/// Retryable: `starlark error: …` (parse/eval) and anything else —
/// the model gets one chance to correct syntax it didn't realise was
/// rejected by the strict-subset rules.
pub fn is_retryable(output_text: &str) -> bool {
    let head = output_text.trim_start();
    if head.starts_with("policy violation") {
        return false;
    }
    if head.starts_with("verifier rejected") {
        return false;
    }
    if head.contains("confirm hook denied") {
        return false;
    }
    if head.starts_with("runtime cap exceeded") {
        return false;
    }
    true
}

/// Build the user-message content for a fix-it retry. Truncates the
/// error to 600 chars so a long Starlark traceback doesn't crowd out
/// the model's actual reasoning.
pub fn build_retry_message(error_text: &str, step: &str) -> String {
    let mut snippet = error_text.trim().to_string();
    if snippet.chars().count() > 600 {
        let truncated: String = snippet.chars().take(597).collect();
        snippet = format!("{truncated}...");
    }
    format!(
        "Your previous Starlark program produced this error from the \
         Denyx runtime:\n\n\
         {snippet}\n\n\
         Common fixes:\n\
         \x20 - top-level `for`/`if` → wrap in `def helper(): ...` and call it.\n\
         \x20 - `import ...` → DELETE the line; modules are pre-loaded.\n\
         \x20 - f-strings `f\"...\"` → use `\"...\" + str(x)` or `\"...\".format(x)`.\n\
         \x20 - `|` between calls (shell-pipe) → use SEPARATE statements.\n\
         \x20 - `try`/`except` → DELETE; let errors propagate.\n\n\
         Rewrite the WHOLE program. Output ONLY the corrected Starlark \
         code, starting at column 0.\n\n\
         Step: {step}"
    )
}

/// Pull the text from a Denyx-MCP `tools/call` response.
fn extract_text(resp: &Value) -> (bool, String) {
    let result = resp.get("result").cloned().unwrap_or(Value::Null);
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let content = result
        .get("content")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let text = content
        .first()
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    (is_error, text)
}

/// Configuration passed to [`execute_step`]. Held separately from the
/// trait objects so test wiring is straightforward.
pub struct StepConfig {
    pub model: String,
    pub tools_routing: String,
    pub max_retries: u32,
    pub retrieve_k: usize,
}

impl Default for StepConfig {
    fn default() -> Self {
        Self {
            model: "qwen2.5-coder:7b".to_string(),
            tools_routing: String::new(),
            max_retries: 1,
            retrieve_k: 4,
        }
    }
}

/// Run one delegated step end-to-end. `counter` is a shared in-memory
/// monotonic id used in audit `task_id` strings; pass `&Mutex<u64>`
/// owned by the outer server so multiple concurrent steps don't
/// collide.
pub fn execute_step<C, E, R>(
    chat: &C,
    embed: &E,
    denyx: &R,
    step: &str,
    cfg: &StepConfig,
    counter: &std::sync::Mutex<u64>,
) -> Result<StepOutcome>
where
    C: ChatProvider + ?Sized,
    E: EmbedProvider + ?Sized,
    R: DenyxRunner + ?Sized,
{
    // 1. Retrieve K examples.
    let picked = retrieve(embed, step, cfg.retrieve_k)?;
    let rendered = render_examples(&picked);

    // 2. Build the system prompt.
    let system_prompt = crate::prompt::render_system_prompt(&cfg.tools_routing, &rendered);

    // 3. First chat call.
    let mut messages = vec![
        ChatMessage::system(system_prompt),
        ChatMessage::user(step.to_string()),
    ];
    let mut raw = chat.call_chat(&cfg.model, &messages)?;
    let mut script = strip_fences(&raw);

    // 4. First denyx-mcp call.
    let task_id = next_task_id(counter, 0);
    let resp = denyx.run(&script, &task_id)?;
    let (mut is_error, mut text) = extract_text(&resp);

    // 5. Retry loop.
    let mut retries = 0u32;
    while retries < cfg.max_retries && is_error && is_retryable(&text) {
        retries += 1;
        let retry_msg = build_retry_message(&text, step);
        messages.push(ChatMessage::assistant(raw.clone()));
        messages.push(ChatMessage::user(retry_msg));
        raw = chat.call_chat(&cfg.model, &messages)?;
        script = strip_fences(&raw);
        let task_id = next_task_id(counter, retries);
        let resp = denyx.run(&script, &task_id)?;
        let (e, t) = extract_text(&resp);
        is_error = e;
        text = t;
    }

    Ok(StepOutcome {
        text,
        is_error,
        retries,
        script,
    })
}

fn next_task_id(counter: &std::sync::Mutex<u64>, retry: u32) -> String {
    let mut g = counter.lock().expect("step counter mutex");
    *g += 1;
    let n = *g;
    drop(g);
    if retry == 0 {
        format!("orchestrated-{n}")
    } else {
        format!("orchestrated-{n}-r{retry}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    #[test]
    fn is_retryable_skips_policy_violations() {
        assert!(!is_retryable("policy violation: fs.read is not allowed"));
        assert!(!is_retryable("  policy violation: foo  "));
    }

    #[test]
    fn is_retryable_skips_confirm_hook_denials() {
        assert!(!is_retryable(
            "Operation denied: confirm hook denied the call"
        ));
    }

    #[test]
    fn is_retryable_treats_parse_errors_as_retryable() {
        assert!(is_retryable("Parse error: unexpected token at line 3"));
        assert!(is_retryable("Eval error: name 'foo' is not defined"));
    }

    #[test]
    fn is_retryable_treats_verifier_rejection_as_terminal() {
        assert!(!is_retryable(
            "verifier rejected script: fs.read called but [filesystem].read_allow is empty"
        ));
    }

    #[test]
    fn is_retryable_treats_runtime_cap_as_terminal() {
        assert!(!is_retryable(
            "runtime cap exceeded: wall-time deadline 30s"
        ));
    }

    #[test]
    fn is_retryable_treats_starlark_error_as_retryable() {
        assert!(is_retryable("starlark error: unexpected token 'import'"));
    }

    #[test]
    fn build_retry_message_truncates_long_errors() {
        let long = "X".repeat(2000);
        let msg = build_retry_message(&long, "the step");
        assert!(msg.contains("..."), "should truncate");
        // The full 2000-char body must NOT appear verbatim.
        assert!(!msg.contains(&"X".repeat(700)));
        assert!(msg.contains("Step: the step"));
    }

    #[test]
    fn build_retry_message_includes_common_fixes_block() {
        let m = build_retry_message("oops", "step");
        assert!(m.contains("Common fixes:"));
        assert!(m.contains("top-level `for`/`if`"));
        assert!(m.contains("`import ...`"));
        assert!(m.contains("f-strings"));
    }

    #[test]
    fn extract_text_reads_tool_call_response() {
        let resp = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "hello"}],
                "isError": false
            }
        });
        let (e, t) = extract_text(&resp);
        assert!(!e);
        assert_eq!(t, "hello");
    }

    #[test]
    fn extract_text_handles_error_response() {
        let resp = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "policy violation"}],
                "isError": true
            }
        });
        let (e, t) = extract_text(&resp);
        assert!(e);
        assert_eq!(t, "policy violation");
    }

    #[test]
    fn extract_text_handles_missing_content() {
        let resp = json!({"result": {}});
        let (e, t) = extract_text(&resp);
        assert!(!e);
        assert_eq!(t, "");
    }

    // ── Stub providers for execute_step tests ─────────────────────

    struct StubChat {
        responses: Mutex<Vec<String>>,
        calls: Mutex<Vec<Vec<ChatMessage>>>,
    }

    impl StubChat {
        fn new(responses: Vec<&str>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().map(String::from).collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl ChatProvider for StubChat {
        fn call_chat(&self, _model: &str, messages: &[ChatMessage]) -> Result<String> {
            self.calls.lock().unwrap().push(messages.to_vec());
            let mut q = self.responses.lock().unwrap();
            if q.is_empty() {
                Err(anyhow::anyhow!("StubChat ran out of canned responses"))
            } else {
                Ok(q.remove(0))
            }
        }
    }

    struct StubEmbed;
    impl EmbedProvider for StubEmbed {
        fn embed(&self, text: &str) -> Result<Vec<f32>> {
            // Deterministic 4-d vector based on text length & first char.
            let len = text.len() as f32;
            let first = text.chars().next().map(|c| c as u32 as f32).unwrap_or(0.0);
            Ok(vec![len, first, 1.0, 1.0])
        }
    }

    struct StubDenyx {
        responses: Mutex<Vec<Value>>,
        scripts: Mutex<Vec<String>>,
    }

    impl StubDenyx {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                responses: Mutex::new(responses),
                scripts: Mutex::new(Vec::new()),
            }
        }
        fn scripts(&self) -> Vec<String> {
            self.scripts.lock().unwrap().clone()
        }
    }

    impl DenyxRunner for StubDenyx {
        fn run(&self, script: &str, _task_id: &str) -> Result<Value> {
            self.scripts.lock().unwrap().push(script.to_string());
            let mut q = self.responses.lock().unwrap();
            if q.is_empty() {
                Err(anyhow::anyhow!("StubDenyx ran out of canned responses"))
            } else {
                Ok(q.remove(0))
            }
        }
    }

    fn ok_resp(text: &str) -> Value {
        json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {"content": [{"type": "text", "text": text}], "isError": false}
        })
    }
    fn err_resp(text: &str) -> Value {
        json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {"content": [{"type": "text", "text": text}], "isError": true}
        })
    }

    #[test]
    fn execute_step_happy_path_no_retry() {
        let chat = StubChat::new(vec!["print('hi')"]);
        let embed = StubEmbed;
        let denyx = StubDenyx::new(vec![ok_resp("hi")]);
        let counter = Mutex::new(0u64);
        let cfg = StepConfig::default();
        let out = execute_step(&chat, &embed, &denyx, "say hi", &cfg, &counter).unwrap();
        assert_eq!(out.script, "print('hi')");
        assert_eq!(out.text, "hi");
        assert!(!out.is_error);
        assert_eq!(out.retries, 0);
        assert_eq!(chat.call_count(), 1, "no retry, exactly one chat call");
    }

    #[test]
    fn execute_step_strips_markdown_fences() {
        let chat = StubChat::new(vec!["```python\nprint('x')\n```"]);
        let embed = StubEmbed;
        let denyx = StubDenyx::new(vec![ok_resp("x")]);
        let counter = Mutex::new(0u64);
        let out = execute_step(
            &chat,
            &embed,
            &denyx,
            "test",
            &StepConfig::default(),
            &counter,
        )
        .unwrap();
        assert_eq!(out.script, "print('x')");
        assert_eq!(denyx.scripts()[0], "print('x')");
    }

    #[test]
    fn execute_step_retries_once_on_parse_error() {
        let chat = StubChat::new(vec![
            "import json\nprint(1)", // bad: import
            "print(1)",              // good
        ]);
        let embed = StubEmbed;
        let denyx = StubDenyx::new(vec![err_resp("Parse error: import"), ok_resp("1")]);
        let counter = Mutex::new(0u64);
        let cfg = StepConfig::default();
        let out = execute_step(&chat, &embed, &denyx, "step", &cfg, &counter).unwrap();
        assert_eq!(out.retries, 1);
        assert!(!out.is_error);
        assert_eq!(out.script, "print(1)");
        assert_eq!(out.text, "1");
        assert_eq!(chat.call_count(), 2, "one initial + one retry");
    }

    #[test]
    fn execute_step_does_not_retry_on_policy_violation() {
        let chat = StubChat::new(vec!["fs.read('/etc/passwd')"]);
        let embed = StubEmbed;
        let denyx = StubDenyx::new(vec![err_resp("policy violation: fs.read denied")]);
        let counter = Mutex::new(0u64);
        let cfg = StepConfig::default();
        let out = execute_step(&chat, &embed, &denyx, "step", &cfg, &counter).unwrap();
        assert_eq!(out.retries, 0, "policy denial is terminal");
        assert!(out.is_error);
        assert_eq!(chat.call_count(), 1);
    }

    #[test]
    fn execute_step_respects_max_retries() {
        // chat keeps emitting bad code; denyx keeps returning parse errors.
        let chat = StubChat::new(vec!["bad1", "bad2", "bad3"]);
        let embed = StubEmbed;
        let denyx = StubDenyx::new(vec![err_resp("Parse error 1"), err_resp("Parse error 2")]);
        let counter = Mutex::new(0u64);
        let cfg = StepConfig {
            max_retries: 1,
            ..StepConfig::default()
        };
        let out = execute_step(&chat, &embed, &denyx, "step", &cfg, &counter).unwrap();
        assert_eq!(out.retries, 1, "stops after max_retries=1");
        assert!(out.is_error);
        assert_eq!(chat.call_count(), 2);
    }

    #[test]
    fn execute_step_includes_examples_in_first_system_prompt() {
        let chat = StubChat::new(vec!["print(1)"]);
        let embed = StubEmbed;
        let denyx = StubDenyx::new(vec![ok_resp("1")]);
        let counter = Mutex::new(0u64);
        execute_step(
            &chat,
            &embed,
            &denyx,
            "step",
            &StepConfig::default(),
            &counter,
        )
        .unwrap();
        let calls = chat.calls.lock().unwrap();
        let first = &calls[0];
        let sys = &first[0].content;
        assert_eq!(first[0].role, "system");
        assert!(sys.contains("WORKED EXAMPLES"));
        assert!(sys.contains("--- Example 1: "));
    }

    #[test]
    fn execute_step_carries_assistant_and_retry_msg_into_second_call() {
        let chat = StubChat::new(vec!["bad", "good"]);
        let embed = StubEmbed;
        let denyx = StubDenyx::new(vec![err_resp("Parse error oops"), ok_resp("ok")]);
        let counter = Mutex::new(0u64);
        execute_step(
            &chat,
            &embed,
            &denyx,
            "step",
            &StepConfig::default(),
            &counter,
        )
        .unwrap();
        let calls = chat.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        let second = &calls[1];
        // Must have system + initial user + assistant + retry user.
        assert_eq!(second.len(), 4);
        assert_eq!(second[2].role, "assistant");
        assert_eq!(second[2].content, "bad");
        assert_eq!(second[3].role, "user");
        assert!(second[3].content.contains("Common fixes:"));
        assert!(second[3].content.contains("Step: step"));
    }

    #[test]
    fn next_task_id_increments_and_includes_retry_suffix() {
        let counter = Mutex::new(0u64);
        assert_eq!(next_task_id(&counter, 0), "orchestrated-1");
        assert_eq!(next_task_id(&counter, 0), "orchestrated-2");
        assert_eq!(next_task_id(&counter, 1), "orchestrated-3-r1");
    }
}
