//! `denyx-local-mcp doctor` — diagnostic preflight.
//!
//! Probes the configured `--endpoint`, fingerprints the server
//! (Ollama vs generic OpenAI-compat), verifies the configured chat
//! and embed models are served, and on Ollama additionally reads
//! `num_ctx` to flag the common "default 2048 too small for our
//! prompt" pitfall. Prints copy-pasteable next-steps for every
//! failure — never auto-fixes.
//!
//! The doctor is intentionally read-only. It does not pull models,
//! create Modelfiles, or restart anything. Its job is "tell the
//! operator what's wrong and how to fix it."

use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::openai_compat::OpenAiCompatEmbed;
use crate::rag::EmbedProvider;

/// What kind of server is on the other end. Affects the advice we
/// print on failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerKind {
    /// Detected via a `/api/version` Ollama-native probe.
    Ollama { version: Option<String> },
    /// Anything else that responds to `/v1/models`. Could be
    /// llama.cpp, LM Studio, vLLM, LocalAI, Text Gen WebUI, etc. —
    /// we lump them together because the fix instructions are the
    /// same shape ("set context size at server-launch time").
    OpenAiCompat,
    /// Endpoint didn't respond on either probe.
    Unreachable,
}

impl ServerKind {
    pub fn label(&self) -> String {
        match self {
            Self::Ollama { version: Some(v) } => format!("Ollama v{v}"),
            Self::Ollama { version: None } => "Ollama".to_string(),
            Self::OpenAiCompat => "OpenAI-compat server".to_string(),
            Self::Unreachable => "(unreachable)".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// All good — short success message.
    Ok(String),
    /// Soft warning — works but the operator should know.
    Warn { msg: String, fix: String },
    /// Hard failure — gate's not usable until this is resolved.
    Fail { msg: String, fix: String },
}

#[derive(Debug)]
pub struct Report {
    pub endpoint: String,
    pub server: ServerKind,
    pub chat_model: String,
    pub embed_model: String,
    pub chat_model_check: CheckOutcome,
    pub embed_model_check: CheckOutcome,
    pub embed_call_check: CheckOutcome,
    /// Only populated on Ollama (where `/api/show` exposes num_ctx).
    pub context_check: Option<CheckOutcome>,
}

/// Inputs to [`run`]. Mirrors the CLI flags.
#[derive(Debug, Clone)]
pub struct DoctorArgs {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub chat_model: String,
    pub embed_model: String,
}

/// Fingerprint the server, then run every check that applies to it.
pub fn run(args: &DoctorArgs) -> Report {
    let server = fingerprint(&args.endpoint);

    let (chat_model_check, embed_model_check) = match server {
        ServerKind::Unreachable => (
            CheckOutcome::Fail {
                msg: "endpoint unreachable; cannot list models".to_string(),
                fix: format!(
                    "Verify the server is running and listening at {ep}. \
                     For Ollama: `ollama serve` (it's usually a systemd unit). \
                     For llama.cpp: `llama-server -m <model.gguf> -c 8192 --port 8080`. \
                     For LM Studio: open the app and start the local server in the UI.",
                    ep = args.endpoint
                ),
            },
            CheckOutcome::Fail {
                msg: "endpoint unreachable".to_string(),
                fix: "(see chat-model fix above)".to_string(),
            },
        ),
        _ => match list_models(&args.endpoint, args.api_key.as_deref()) {
            Ok(ids) => (
                check_model_present(&ids, &args.chat_model, "chat", &server),
                check_model_present(&ids, &args.embed_model, "embed", &server),
            ),
            Err(e) => {
                let fail = CheckOutcome::Fail {
                    msg: format!("could not list models: {e}"),
                    fix: format!(
                        "Try `curl {ep}/models` from the same machine to confirm \
                         the server is reachable and returning the OpenAI v1 \
                         /models shape.",
                        ep = args.endpoint
                    ),
                };
                (fail.clone(), fail)
            }
        },
    };

    let embed_call_check = match server {
        ServerKind::Unreachable => CheckOutcome::Fail {
            msg: "skipped (server unreachable)".to_string(),
            fix: "Resolve the connectivity issue above first.".to_string(),
        },
        _ => check_embed_call(&args.endpoint, args.api_key.as_deref(), &args.embed_model),
    };

    let context_check = match &server {
        ServerKind::Ollama { .. } => Some(check_ollama_context(&args.endpoint, &args.chat_model)),
        _ => None,
    };

    Report {
        endpoint: args.endpoint.clone(),
        server,
        chat_model: args.chat_model.clone(),
        embed_model: args.embed_model.clone(),
        chat_model_check,
        embed_model_check,
        embed_call_check,
        context_check,
    }
}

// ─────────────────────── server fingerprinting ───────────────────────

#[derive(Deserialize)]
struct OllamaVersion {
    version: String,
}

/// Strip a trailing `/v1`-shaped path off the endpoint to get the
/// base host URL Ollama-native probes can use.
fn base_url(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if let Some(stripped) = trimmed.strip_suffix("/v1") {
        return stripped.to_string();
    }
    trimmed.to_string()
}

/// Try the Ollama-native `/api/version` probe; if it succeeds, this
/// is Ollama. Otherwise try the generic `/v1/models` probe — if
/// that works, it's some OpenAI-compat server. Otherwise unreachable.
pub fn fingerprint(endpoint: &str) -> ServerKind {
    let base = base_url(endpoint);
    // Ollama: GET <base>/api/version returns `{"version": "0.5.7"}`.
    if let Ok(body) = http_get(&format!("{base}/api/version"), None, 3) {
        match serde_json::from_str::<OllamaVersion>(&body) {
            Ok(v) => {
                return ServerKind::Ollama {
                    version: Some(v.version),
                }
            }
            Err(_) => return ServerKind::Ollama { version: None },
        }
    }
    // Generic OpenAI-compat probe.
    if http_get(
        &format!("{}/models", endpoint.trim_end_matches('/')),
        None,
        3,
    )
    .is_ok()
    {
        return ServerKind::OpenAiCompat;
    }
    ServerKind::Unreachable
}

// ─────────────────────── /v1/models check ───────────────────────

#[derive(Deserialize)]
struct ModelsResp {
    data: Vec<ModelEntry>,
}
#[derive(Deserialize)]
struct ModelEntry {
    id: String,
}

/// Call `GET /v1/models` and return the list of model ids.
pub fn list_models(endpoint: &str, api_key: Option<&str>) -> Result<Vec<String>> {
    let body = http_get(
        &format!("{}/models", endpoint.trim_end_matches('/')),
        api_key,
        5,
    )?;
    let parsed: ModelsResp = serde_json::from_str(&body).context("decode /v1/models response")?;
    Ok(parsed.data.into_iter().map(|m| m.id).collect())
}

fn check_model_present(
    ids: &[String],
    wanted: &str,
    role: &str,
    server: &ServerKind,
) -> CheckOutcome {
    if ids.iter().any(|id| id == wanted) {
        return CheckOutcome::Ok(format!("{role} model `{wanted}` is available"));
    }
    let fix = match server {
        ServerKind::Ollama { .. } => format!(
            "Pull it with: `ollama pull {wanted}`. Or pick one from the list above \
             and pass it via --{flag}-model.",
            flag = if role == "chat" { "" } else { "embed-" }
        ),
        ServerKind::OpenAiCompat => format!(
            "Most local servers serve a fixed set of models loaded at launch. \
             Either restart the server with this model loaded, or pick one from \
             the list above and pass it via --{flag}-model.",
            flag = if role == "chat" { "" } else { "embed-" }
        ),
        ServerKind::Unreachable => "(server unreachable)".to_string(),
    };
    CheckOutcome::Fail {
        msg: format!(
            "{role} model `{wanted}` is NOT in the served list ({n} models served): {sample}",
            n = ids.len(),
            sample = ids.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                + if ids.len() > 5 { ", …" } else { "" }
        ),
        fix,
    }
}

// ─────────────────────── embed round-trip check ───────────────────────

/// Send one small string through the embed endpoint and verify a
/// non-empty vector comes back. Catches "/v1/embeddings is wired but
/// the loaded model doesn't support embeddings" cases that
/// /v1/models alone can't see.
pub fn check_embed_call(endpoint: &str, api_key: Option<&str>, model: &str) -> CheckOutcome {
    let embed = OpenAiCompatEmbed::new(endpoint.to_string(), model.to_string())
        .with_api_key(api_key.map(|s| s.to_string()));
    match embed.embed("test") {
        Ok(v) if !v.is_empty() => CheckOutcome::Ok(format!(
            "embed call returned a {dim}-dim vector",
            dim = v.len()
        )),
        Ok(_) => CheckOutcome::Fail {
            msg: "embed call returned an empty vector".to_string(),
            fix: format!(
                "The configured embed model `{model}` may not actually be an \
                 embedding model. Pick one (Ollama: `ollama pull \
                 nomic-embed-text`)."
            ),
        },
        Err(e) => CheckOutcome::Fail {
            msg: format!("embed call failed: {e}"),
            fix: format!(
                "Verify the model `{model}` is loaded as an embedding model. \
                 On Ollama: `ollama pull nomic-embed-text` (or whatever you \
                 picked) and pass --embed-model with that exact name."
            ),
        },
    }
}

// ─────────────────────── Ollama num_ctx check ───────────────────────

#[derive(Deserialize)]
struct OllamaShowResp {
    /// Multi-line string. Includes lines like `num_ctx 2048`.
    parameters: Option<String>,
}

/// Read `POST /api/show` for the chat model and look for `num_ctx`.
/// Flags any value below 8192 with a Modelfile fix.
pub fn check_ollama_context(endpoint: &str, model: &str) -> CheckOutcome {
    let base = base_url(endpoint);
    let body = serde_json::to_string(&serde_json::json!({ "name": model })).unwrap();
    let url = format!("{base}/api/show");
    let resp = match http_post_json(&url, &body, 5) {
        Ok(r) => r,
        Err(e) => {
            return CheckOutcome::Warn {
                msg: format!("could not read num_ctx via /api/show: {e}"),
                fix: "Skipping context-size check; the embedding test above \
                      catches most setup issues regardless."
                    .to_string(),
            };
        }
    };
    let parsed: OllamaShowResp = match serde_json::from_str(&resp) {
        Ok(p) => p,
        Err(_) => {
            return CheckOutcome::Warn {
                msg: "/api/show returned an unexpected shape".to_string(),
                fix: "Ollama version may be too old to surface model parameters.".to_string(),
            };
        }
    };
    let params = parsed.parameters.unwrap_or_default();
    let num_ctx = parse_num_ctx(&params);
    match num_ctx {
        Some(n) if n >= 8192 => CheckOutcome::Ok(format!("num_ctx = {n} (>= 8192)")),
        Some(n) => CheckOutcome::Warn {
            msg: format!(
                "num_ctx = {n}, smaller than the 8192 our system prompt + RAG \
                 examples typically need. Long delegations will be truncated."
            ),
            fix: format!(
                "Build a custom variant with a larger context:\n\
                 \n\
                 \x20 cat <<'EOF' > Modelfile\n\
                 \x20 FROM {model}\n\
                 \x20 PARAMETER num_ctx 8192\n\
                 \x20 EOF\n\
                 \x20 ollama create {model}-denyx -f Modelfile\n\
                 \x20 # Then pass --model {model}-denyx to denyx-local-mcp."
            ),
        },
        None => CheckOutcome::Warn {
            msg: "num_ctx not declared in this model's parameters".to_string(),
            fix: format!(
                "Ollama defaults num_ctx to 2048, which is too small. Build \
                 a Modelfile variant:\n\
                 \n\
                 \x20 cat <<'EOF' > Modelfile\n\
                 \x20 FROM {model}\n\
                 \x20 PARAMETER num_ctx 8192\n\
                 \x20 EOF\n\
                 \x20 ollama create {model}-denyx -f Modelfile"
            ),
        },
    }
}

/// Parse a `num_ctx` line out of an Ollama-shaped `parameters` blob.
/// The blob looks like `"num_ctx 4096\nstop \"<|im_start|>\"\n…"`.
pub fn parse_num_ctx(parameters: &str) -> Option<u32> {
    for line in parameters.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("num_ctx") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

// ─────────────────────── output rendering ───────────────────────

/// Render a [`Report`] as a human-readable diagnostic. Returns the
/// string AND the exit code the doctor should propagate (0 if all
/// checks were Ok, 1 if any Warn, 2 if any Fail).
pub fn render(report: &Report) -> (String, i32) {
    let mut out = String::new();
    let mut worst: i32 = 0; // 0 ok, 1 warn, 2 fail

    out.push_str("denyx-local-mcp doctor\n");
    out.push_str(&format!("  endpoint: {}\n", report.endpoint));
    out.push_str(&format!("  server:   {}\n\n", report.server.label()));

    write_check(&mut out, "chat model", &report.chat_model_check, &mut worst);
    write_check(
        &mut out,
        "embed model",
        &report.embed_model_check,
        &mut worst,
    );
    write_check(&mut out, "embed call", &report.embed_call_check, &mut worst);
    if let Some(c) = &report.context_check {
        write_check(&mut out, "ollama num_ctx", c, &mut worst);
    }

    out.push('\n');
    out.push_str(match worst {
        0 => "Ready to use. Start denyx-local-mcp with the same flags.\n",
        1 => {
            "Usable, but with caveats above. Apply the suggested fixes \
              before relying on this for non-trivial work.\n"
        }
        _ => "NOT ready. Apply the fixes above and re-run `denyx-local-mcp doctor`.\n",
    });

    (out, worst)
}

fn write_check(out: &mut String, label: &str, c: &CheckOutcome, worst: &mut i32) {
    match c {
        CheckOutcome::Ok(msg) => {
            out.push_str(&format!("  [OK]   {label}: {msg}\n"));
        }
        CheckOutcome::Warn { msg, fix } => {
            out.push_str(&format!("  [WARN] {label}: {msg}\n"));
            for line in fix.lines() {
                out.push_str(&format!("         {line}\n"));
            }
            if *worst < 1 {
                *worst = 1;
            }
        }
        CheckOutcome::Fail { msg, fix } => {
            out.push_str(&format!("  [FAIL] {label}: {msg}\n"));
            for line in fix.lines() {
                out.push_str(&format!("         {line}\n"));
            }
            *worst = 2;
        }
    }
}

// ─────────────────────── HTTP helpers ───────────────────────

fn http_get(url: &str, api_key: Option<&str>, timeout_secs: u64) -> Result<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .build();
    let mut r = agent.get(url);
    if let Some(k) = api_key {
        r = r.set("Authorization", &format!("Bearer {k}"));
    }
    let resp = r.call().with_context(|| format!("GET {url}"))?;
    let body = resp.into_string().context("read body")?;
    Ok(body)
}

fn http_post_json(url: &str, body: &str, timeout_secs: u64) -> Result<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .build();
    let resp = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(body)
        .with_context(|| format!("POST {url}"))?;
    let body = resp.into_string().context("read body")?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_strips_v1_suffix() {
        assert_eq!(
            base_url("http://localhost:11434/v1"),
            "http://localhost:11434"
        );
        assert_eq!(
            base_url("http://localhost:11434/v1/"),
            "http://localhost:11434"
        );
        assert_eq!(base_url("http://localhost:11434"), "http://localhost:11434");
        assert_eq!(
            base_url("http://localhost:8080/v1"),
            "http://localhost:8080"
        );
    }

    #[test]
    fn parse_num_ctx_pulls_value_out_of_ollama_params_blob() {
        let blob = "num_ctx                    8192\nstop                       \"<|im_start|>\"\nstop                       \"<|im_end|>\"\n";
        assert_eq!(parse_num_ctx(blob), Some(8192));
    }

    #[test]
    fn parse_num_ctx_returns_none_when_absent() {
        let blob = "stop                       \"<|im_start|>\"\n";
        assert_eq!(parse_num_ctx(blob), None);
    }

    #[test]
    fn parse_num_ctx_handles_irregular_whitespace() {
        assert_eq!(parse_num_ctx("num_ctx 4096"), Some(4096));
        assert_eq!(parse_num_ctx("num_ctx\t16384"), Some(16384));
    }

    #[test]
    fn check_model_present_ok_when_id_in_list() {
        let ids = vec!["qwen2.5-coder:7b".to_string(), "other".to_string()];
        let r = check_model_present(
            &ids,
            "qwen2.5-coder:7b",
            "chat",
            &ServerKind::Ollama { version: None },
        );
        assert!(matches!(r, CheckOutcome::Ok(_)));
    }

    #[test]
    fn check_model_present_fail_with_ollama_fix_when_missing_on_ollama() {
        let ids = vec!["other-model".to_string()];
        let r = check_model_present(
            &ids,
            "qwen2.5-coder:7b",
            "chat",
            &ServerKind::Ollama { version: None },
        );
        match r {
            CheckOutcome::Fail { fix, .. } => {
                assert!(
                    fix.contains("ollama pull"),
                    "Ollama fix should suggest `ollama pull`, got: {fix}"
                );
            }
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn check_model_present_fail_with_compat_fix_when_missing_on_generic() {
        let ids = vec!["other-model".to_string()];
        let r = check_model_present(&ids, "qwen2.5-coder", "chat", &ServerKind::OpenAiCompat);
        match r {
            CheckOutcome::Fail { fix, .. } => {
                assert!(
                    fix.contains("loaded at launch"),
                    "Compat fix should reference launch-time loading, got: {fix}"
                );
            }
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn render_marks_failures_and_returns_exit_code_2() {
        let r = Report {
            endpoint: "http://x".into(),
            server: ServerKind::Ollama {
                version: Some("1.2.3".into()),
            },
            chat_model: "qwen".into(),
            embed_model: "nom".into(),
            chat_model_check: CheckOutcome::Fail {
                msg: "missing".into(),
                fix: "ollama pull qwen".into(),
            },
            embed_model_check: CheckOutcome::Ok("present".into()),
            embed_call_check: CheckOutcome::Ok("16-dim".into()),
            context_check: Some(CheckOutcome::Ok("num_ctx = 8192".into())),
        };
        let (out, code) = render(&r);
        assert_eq!(code, 2);
        assert!(out.contains("[FAIL] chat model"));
        assert!(out.contains("ollama pull qwen"));
        assert!(out.contains("[OK]   embed model"));
        assert!(out.contains("Ollama v1.2.3"));
        assert!(out.contains("NOT ready"));
    }

    #[test]
    fn render_returns_exit_code_1_when_only_warns() {
        let r = Report {
            endpoint: "http://x".into(),
            server: ServerKind::Ollama { version: None },
            chat_model: "qwen".into(),
            embed_model: "nom".into(),
            chat_model_check: CheckOutcome::Ok("present".into()),
            embed_model_check: CheckOutcome::Ok("present".into()),
            embed_call_check: CheckOutcome::Ok("16-dim".into()),
            context_check: Some(CheckOutcome::Warn {
                msg: "num_ctx = 2048".into(),
                fix: "build a Modelfile".into(),
            }),
        };
        let (out, code) = render(&r);
        assert_eq!(code, 1);
        assert!(out.contains("[WARN] ollama num_ctx"));
        assert!(out.contains("Usable, but with caveats"));
    }

    #[test]
    fn render_returns_exit_code_0_when_all_ok() {
        let r = Report {
            endpoint: "http://x".into(),
            server: ServerKind::OpenAiCompat,
            chat_model: "x".into(),
            embed_model: "y".into(),
            chat_model_check: CheckOutcome::Ok("a".into()),
            embed_model_check: CheckOutcome::Ok("b".into()),
            embed_call_check: CheckOutcome::Ok("c".into()),
            context_check: None,
        };
        let (out, code) = render(&r);
        assert_eq!(code, 0);
        assert!(out.contains("Ready to use"));
        assert!(!out.contains("[FAIL]"));
        assert!(!out.contains("[WARN]"));
    }
}
