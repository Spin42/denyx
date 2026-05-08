//! `denyx-local-mcp doctor` — diagnostic preflight.
//!
//! Two modes:
//!
//! - **Scan mode** (default — `denyx-local-mcp doctor` with no
//!   flags). Probes the standard local-LLM ports
//!   (Ollama 11434, llama.cpp 8080, LM Studio 1234, vLLM 8000, Text
//!   Gen WebUI 5000), lists every server that responds plus its
//!   served models, and suggests a copy-pasteable `serve` command
//!   with sensible chat + embed model picks.
//! - **Targeted mode** (`--endpoint X`). Verifies the operator's
//!   chosen endpoint, chat model, and embed model are reachable +
//!   correct. On Ollama also reads `num_ctx` to flag the common
//!   "default 2048 too small for our prompt" pitfall.
//!
//! Both modes print copy-pasteable next-steps for every failure
//! and never auto-fix anything. The doctor is read-only by
//! design — its job is "tell the operator what's wrong and how to
//! fix it," not "fix it for them."

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

// ─────────────────────── scan mode ───────────────────────

/// Default endpoints scanned when `denyx-local-mcp doctor` is run
/// without `--endpoint`. Ordered roughly by popularity so the first
/// hit is the most likely "right" one. Probed sequentially with a
/// short timeout — total scan time is bounded by the sum of
/// timeouts for the absent ones.
const DEFAULT_SCAN_ENDPOINTS: &[(&str, &str)] = &[
    ("http://localhost:11434/v1", "Ollama"),
    ("http://localhost:8080/v1", "llama.cpp / LocalAI / MLX-LM"),
    ("http://localhost:1234/v1", "LM Studio / mistral.rs"),
    ("http://localhost:8000/v1", "vLLM"),
    (
        "http://localhost:5000/v1",
        "Text Generation WebUI / TabbyAPI",
    ),
];

/// One server discovered by the scan.
#[derive(Debug, Clone)]
pub struct DetectedServer {
    pub endpoint: String,
    pub kind: ServerKind,
    pub models: Vec<String>,
}

/// Result of a scan: every endpoint we probed, in order, paired
/// with its detection result. Endpoints that didn't respond carry
/// `kind = Unreachable` and an empty `models` list.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub probes: Vec<(String, String, ServerKind, Vec<String>)>, // (endpoint, label, kind, models)
}

impl ScanResult {
    pub fn detected(&self) -> impl Iterator<Item = DetectedServer> + '_ {
        self.probes.iter().filter_map(|(ep, _label, kind, models)| {
            if matches!(kind, ServerKind::Unreachable) {
                None
            } else {
                Some(DetectedServer {
                    endpoint: ep.clone(),
                    kind: kind.clone(),
                    models: models.clone(),
                })
            }
        })
    }
}

/// Probe every endpoint in [`scan_targets`] and return the result.
pub fn scan() -> ScanResult {
    let targets = scan_targets();
    let probes = targets
        .into_iter()
        .map(|(ep, label)| {
            let kind = fingerprint(&ep);
            let models = if matches!(kind, ServerKind::Unreachable) {
                Vec::new()
            } else {
                list_models(&ep, None).unwrap_or_default()
            };
            (ep, label, kind, models)
        })
        .collect();
    ScanResult { probes }
}

/// The list of endpoints scan mode probes. By default this is
/// [`DEFAULT_SCAN_ENDPOINTS`]; the env var
/// `DENYX_LOCAL_MCP_DOCTOR_SCAN` overrides it as a comma-separated
/// list (used by integration tests to point at a mock server).
pub fn scan_targets() -> Vec<(String, String)> {
    if let Ok(v) = std::env::var("DENYX_LOCAL_MCP_DOCTOR_SCAN") {
        return v
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| (s.to_string(), "test override".to_string()))
            .collect();
    }
    DEFAULT_SCAN_ENDPOINTS
        .iter()
        .map(|(ep, label)| (ep.to_string(), label.to_string()))
        .collect()
}

// ─────────────────────── model heuristics ───────────────────────

/// Heuristic: does this model id look like an embedding model?
///
/// Catches the common patterns: anything containing `embed`,
/// `nomic-` (Nomic AI's embed family), `bge-` (BGE family),
/// `e5-` / `gte-` (Microsoft / Alibaba families). Errs toward
/// labelling as embed: a false positive demotes the model to embed
/// suggestions where it'd otherwise be in chat suggestions; the
/// operator can override with `--model` either way.
pub fn looks_like_embed_model(id: &str) -> bool {
    let lc = id.to_ascii_lowercase();
    lc.contains("embed")
        || lc.contains("nomic-")
        || lc.starts_with("bge-")
        || lc.contains("/bge-")
        || lc.starts_with("e5-")
        || lc.contains("/e5-")
        || lc.starts_with("gte-")
        || lc.contains("/gte-")
}

/// Pick the most-likely-good chat model from a server's served list.
/// Heuristic: prefer code-tuned > qwen-family > llama-family > any
/// non-embed model. Returns the id directly so callers can drop it
/// into a `--model` flag.
pub fn suggest_chat_model(models: &[String]) -> Option<String> {
    let candidates: Vec<&String> = models
        .iter()
        .filter(|id| !looks_like_embed_model(id))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let scored = |id: &str| -> i32 {
        let lc = id.to_ascii_lowercase();
        let mut score = 0;
        if lc.contains("coder") || lc.contains("code") {
            score += 100;
        }
        if lc.contains("qwen") {
            score += 30;
        }
        if lc.contains("llama") {
            score += 20;
        }
        // Prefer "instruct" / "chat" tuned variants.
        if lc.contains("instruct") || lc.contains("chat") {
            score += 10;
        }
        // Sweet spot 7B-class for local hardware.
        if lc.contains("7b") {
            score += 5;
        }
        score
    };
    candidates.into_iter().max_by_key(|id| scored(id)).cloned()
}

/// Pick the most-likely-good embed model from a served list.
pub fn suggest_embed_model(models: &[String]) -> Option<String> {
    models.iter().find(|id| looks_like_embed_model(id)).cloned()
}

// ─────────────────────── scan-mode rendering ───────────────────────

/// Render a [`ScanResult`] as human-readable output. Returns the
/// string and the exit code (0 if at least one server with both a
/// suggested chat and embed model was found; 1 otherwise — there's
/// always something to do).
pub fn render_scan(scan: &ScanResult) -> (String, i32) {
    let mut out = String::new();
    out.push_str("denyx-local-mcp doctor — scanning common local-LLM endpoints\n\n");

    for (ep, label, kind, models) in &scan.probes {
        match kind {
            ServerKind::Unreachable => {
                out.push_str(&format!("  {ep:<40} (no response — {label})\n"));
            }
            _ => {
                out.push_str(&format!("  {ep:<40} {server} ✓\n", server = kind.label()));
                let chat_models: Vec<&String> = models
                    .iter()
                    .filter(|m| !looks_like_embed_model(m))
                    .collect();
                let embed_models: Vec<&String> = models
                    .iter()
                    .filter(|m| looks_like_embed_model(m))
                    .collect();
                if !chat_models.is_empty() {
                    out.push_str(&format!("    Chat models ({}):\n", chat_models.len()));
                    for m in chat_models.iter().take(8) {
                        out.push_str(&format!("      - {m}\n"));
                    }
                    if chat_models.len() > 8 {
                        out.push_str(&format!(
                            "      … and {n} more\n",
                            n = chat_models.len() - 8
                        ));
                    }
                }
                if !embed_models.is_empty() {
                    out.push_str(&format!("    Embed models ({}):\n", embed_models.len()));
                    for m in embed_models.iter().take(4) {
                        out.push_str(&format!("      - {m}\n"));
                    }
                }
                if models.is_empty() {
                    out.push_str("    (no models served — pull/load one before using)\n");
                }
            }
        }
    }
    out.push('\n');

    // Pick the first detected server with at least one chat + one
    // embed model, generate a suggested `serve` command.
    let detected: Vec<DetectedServer> = scan.detected().collect();
    if detected.is_empty() {
        out.push_str(
            "No local LLM server detected on the standard ports.\n\n\
             Common starts:\n  \
             Ollama:     `ollama serve` (then `ollama pull qwen2.5-coder:7b`)\n  \
             llama.cpp:  `llama-server -m <model.gguf> -c 8192 --port 8080`\n  \
             LM Studio:  open the app and start the local server in the UI\n  \
             vLLM:       `vllm serve <model> --port 8000`\n\n\
             Or pass an explicit endpoint:\n  \
             denyx-local-mcp doctor --endpoint http://your-host:port/v1\n",
        );
        return (out, 1);
    }

    let pick = detected
        .iter()
        .find(|s| {
            suggest_chat_model(&s.models).is_some() && suggest_embed_model(&s.models).is_some()
        })
        .or_else(|| detected.first());
    let pick = match pick {
        Some(s) => s,
        None => return (out, 1),
    };
    let chat = suggest_chat_model(&pick.models);
    let embed = suggest_embed_model(&pick.models);

    out.push_str("Suggested setup\n");
    out.push_str(&format!("  Endpoint:   {}\n", pick.endpoint));
    match &chat {
        Some(c) => out.push_str(&format!("  Chat model: {c}\n")),
        None => out.push_str("  Chat model: (none found — pull a coder/instruct model)\n"),
    }
    match &embed {
        Some(e) => out.push_str(&format!("  Embed model: {e}\n")),
        None => out.push_str(
            "  Embed model: (none found — pull an embedding model, e.g. `ollama pull nomic-embed-text`)\n",
        ),
    }

    if let (Some(c), Some(e)) = (&chat, &embed) {
        out.push_str("\nReady-to-paste invocation:\n");
        out.push_str(&format!(
            "  denyx-local-mcp serve \\\n    \
             --policy ./denyx.toml \\\n    \
             --mcp-bin denyx-mcp \\\n    \
             --endpoint {endpoint} \\\n    \
             --model {c} \\\n    \
             --embed-model {e}\n",
            endpoint = pick.endpoint
        ));
        if matches!(pick.kind, ServerKind::Ollama { .. }) {
            out.push_str(
                "\nNote (Ollama): default models often ship with num_ctx=2048, \
                 too small for our system prompt. Run \
                 `denyx-local-mcp doctor --endpoint <above> --model <above>` \
                 to verify; if it warns, build a Modelfile variant with \
                 PARAMETER num_ctx 8192.\n",
            );
        }
        return (out, 0);
    }
    (out, 1)
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
    fn looks_like_embed_model_classifies_common_names() {
        assert!(looks_like_embed_model("nomic-embed-text"));
        assert!(looks_like_embed_model("nomic-embed-text:latest"));
        assert!(looks_like_embed_model("nomic-ai/nomic-embed-text-v1.5"));
        assert!(looks_like_embed_model("BAAI/bge-base-en-v1.5"));
        assert!(looks_like_embed_model("intfloat/e5-large-v2"));
        assert!(looks_like_embed_model("Alibaba-NLP/gte-large"));
        assert!(looks_like_embed_model("snowflake-arctic-embed:33m"));

        assert!(!looks_like_embed_model("qwen2.5-coder:7b"));
        assert!(!looks_like_embed_model("llama3.2:3b"));
        assert!(!looks_like_embed_model("mistral-7b-instruct"));
    }

    #[test]
    fn suggest_chat_model_prefers_coder_then_qwen_then_llama() {
        let models = vec![
            "llama3.2:3b".to_string(),
            "mistral-7b-instruct".to_string(),
            "qwen2.5:7b".to_string(),
            "qwen2.5-coder:7b".to_string(),
            "nomic-embed-text".to_string(),
        ];
        assert_eq!(
            suggest_chat_model(&models),
            Some("qwen2.5-coder:7b".to_string())
        );
    }

    #[test]
    fn suggest_chat_model_skips_embed_models() {
        let models = vec![
            "nomic-embed-text".to_string(),
            "BAAI/bge-base-en-v1.5".to_string(),
        ];
        assert_eq!(suggest_chat_model(&models), None);
    }

    #[test]
    fn suggest_chat_model_falls_back_to_any_non_embed_when_none_match() {
        let models = vec!["foo-bar:1b".to_string(), "nomic-embed-text".to_string()];
        assert_eq!(suggest_chat_model(&models), Some("foo-bar:1b".to_string()));
    }

    #[test]
    fn suggest_embed_model_returns_first_embed_in_list() {
        let models = vec![
            "qwen2.5-coder:7b".to_string(),
            "nomic-embed-text".to_string(),
            "BAAI/bge-base-en-v1.5".to_string(),
        ];
        assert_eq!(
            suggest_embed_model(&models),
            Some("nomic-embed-text".to_string())
        );
    }

    #[test]
    fn suggest_embed_model_returns_none_when_no_embed_in_list() {
        let models = vec!["qwen2.5-coder:7b".to_string()];
        assert_eq!(suggest_embed_model(&models), None);
    }

    #[test]
    fn render_scan_when_no_servers_detected_returns_exit_code_1() {
        let scan = ScanResult {
            probes: vec![
                (
                    "http://localhost:11434/v1".to_string(),
                    "Ollama".to_string(),
                    ServerKind::Unreachable,
                    Vec::new(),
                ),
                (
                    "http://localhost:8080/v1".to_string(),
                    "llama.cpp".to_string(),
                    ServerKind::Unreachable,
                    Vec::new(),
                ),
            ],
        };
        let (out, code) = render_scan(&scan);
        assert_eq!(code, 1);
        assert!(out.contains("(no response"));
        assert!(out.contains("No local LLM server detected"));
        assert!(out.contains("ollama serve"));
        assert!(out.contains("llama-server"));
    }

    #[test]
    fn render_scan_with_complete_setup_returns_ready_to_paste_command() {
        let scan = ScanResult {
            probes: vec![(
                "http://localhost:11434/v1".to_string(),
                "Ollama".to_string(),
                ServerKind::Ollama {
                    version: Some("0.5.7".to_string()),
                },
                vec![
                    "qwen2.5-coder:7b".to_string(),
                    "nomic-embed-text".to_string(),
                ],
            )],
        };
        let (out, code) = render_scan(&scan);
        assert_eq!(code, 0);
        assert!(out.contains("Ollama v0.5.7"));
        assert!(out.contains("Chat models (1)"));
        assert!(out.contains("- qwen2.5-coder:7b"));
        assert!(out.contains("Embed models (1)"));
        assert!(out.contains("- nomic-embed-text"));
        assert!(out.contains("Ready-to-paste invocation"));
        assert!(out.contains("--endpoint http://localhost:11434/v1"));
        assert!(out.contains("--model qwen2.5-coder:7b"));
        assert!(out.contains("--embed-model nomic-embed-text"));
        assert!(
            out.contains("num_ctx"),
            "should hint about Ollama num_ctx for Ollama servers"
        );
    }

    #[test]
    fn render_scan_with_server_but_no_models_returns_exit_code_1() {
        let scan = ScanResult {
            probes: vec![(
                "http://localhost:11434/v1".to_string(),
                "Ollama".to_string(),
                ServerKind::Ollama { version: None },
                Vec::new(),
            )],
        };
        let (out, code) = render_scan(&scan);
        assert_eq!(code, 1);
        assert!(out.contains("(no models served"));
    }

    #[test]
    fn render_scan_with_chat_but_no_embed_model_warns() {
        let scan = ScanResult {
            probes: vec![(
                "http://localhost:11434/v1".to_string(),
                "Ollama".to_string(),
                ServerKind::Ollama { version: None },
                vec!["qwen2.5-coder:7b".to_string()],
            )],
        };
        let (out, code) = render_scan(&scan);
        assert_eq!(code, 1);
        assert!(out.contains("Embed model: (none found"));
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
