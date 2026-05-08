//! OpenAI-compatible HTTP provider impls.
//!
//! Most local model servers expose an OpenAI-compatible API:
//!
//! | Server                          | Default endpoint base |
//! |---------------------------------|-----------------------|
//! | `llama.cpp` (server binary)     | `http://localhost:8080/v1` |
//! | LM Studio                       | `http://localhost:1234/v1` |
//! | vLLM                            | `http://localhost:8000/v1` |
//! | LocalAI                         | `http://localhost:8080/v1` |
//! | Text Generation WebUI (OAI ext) | `http://localhost:5000/v1` |
//! | Ollama (compat layer)           | `http://localhost:11434/v1` |
//!
//! Pass the appropriate `--endpoint` to `denyx-local-mcp`. Auth via
//! `--api-key` if the server requires it (LocalAI's auth plugin,
//! some hosted compatibility shims). The chat shape is
//! `POST /chat/completions`; embeddings are `POST /embeddings`.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::provider::{ChatMessage, ChatProvider};
use crate::rag::EmbedProvider;

/// HTTP client for OpenAI-compatible `/chat/completions`. The
/// `endpoint` is the base URL up to and including `/v1` — we append
/// `/chat/completions` and `/embeddings` ourselves.
pub struct OpenAiCompatChat {
    endpoint: String,
    api_key: Option<String>,
    timeout_secs: u64,
}

impl OpenAiCompatChat {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            api_key: None,
            timeout_secs: 240,
        }
    }
    pub fn with_api_key(mut self, key: Option<String>) -> Self {
        self.api_key = key;
        self
    }
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

#[derive(Serialize)]
struct ChatReq<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    temperature: f32,
    stream: bool,
}

#[derive(Deserialize)]
struct ChatRespChoiceMsg {
    content: String,
}
#[derive(Deserialize)]
struct ChatRespChoice {
    message: ChatRespChoiceMsg,
}
#[derive(Deserialize)]
struct ChatResp {
    choices: Vec<ChatRespChoice>,
}

impl ChatProvider for OpenAiCompatChat {
    fn call_chat(&self, model: &str, messages: &[ChatMessage]) -> Result<String> {
        let req = ChatReq {
            model,
            messages,
            temperature: 0.0,
            stream: false,
        };
        let body = serde_json::to_string(&req).context("serialize chat request")?;
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build();
        let url = format!("{}/chat/completions", self.endpoint.trim_end_matches('/'));
        let mut req = agent.post(&url).set("Content-Type", "application/json");
        if let Some(key) = self.api_key.as_deref() {
            req = req.set("Authorization", &format!("Bearer {key}"));
        }
        let resp = req
            .send_string(&body)
            .map_err(|e| anyhow!("openai-compat /chat/completions: {e}"))?;
        let body = resp
            .into_string()
            .context("read openai-compat chat response body")?;
        let parsed: ChatResp =
            serde_json::from_str(&body).context("decode openai-compat response")?;
        let first = parsed
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("openai-compat response had empty choices array"))?;
        Ok(first.message.content)
    }
}

/// HTTP client for OpenAI-compatible `/embeddings`.
pub struct OpenAiCompatEmbed {
    endpoint: String,
    model: String,
    api_key: Option<String>,
    timeout_secs: u64,
}

impl OpenAiCompatEmbed {
    pub fn new(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            model: model.into(),
            api_key: None,
            timeout_secs: 60,
        }
    }
    pub fn with_api_key(mut self, key: Option<String>) -> Self {
        self.api_key = key;
        self
    }
}

#[derive(Serialize)]
struct EmbedReq<'a> {
    model: &'a str,
    input: &'a str,
}

#[derive(Deserialize)]
struct EmbedRespItem {
    embedding: Vec<f32>,
}
#[derive(Deserialize)]
struct EmbedResp {
    data: Vec<EmbedRespItem>,
}

impl EmbedProvider for OpenAiCompatEmbed {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let req = EmbedReq {
            model: &self.model,
            input: text,
        };
        let body = serde_json::to_string(&req).context("serialize embed request")?;
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build();
        let url = format!("{}/embeddings", self.endpoint.trim_end_matches('/'));
        let mut r = agent.post(&url).set("Content-Type", "application/json");
        if let Some(key) = self.api_key.as_deref() {
            r = r.set("Authorization", &format!("Bearer {key}"));
        }
        let resp = r
            .send_string(&body)
            .map_err(|e| anyhow!("openai-compat /embeddings: {e}"))?;
        let body = resp
            .into_string()
            .context("read openai-compat embeddings response body")?;
        let parsed: EmbedResp =
            serde_json::from_str(&body).context("decode openai-compat response")?;
        let first = parsed
            .data
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("openai-compat embeddings response had empty data array"))?;
        Ok(first.embedding)
    }
}
