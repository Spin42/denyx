//! Ollama (`ollama.com`) HTTP-backed provider impls.
//!
//! Ollama exposes its own native chat (`/api/chat`) and embeddings
//! (`/api/embeddings`) endpoints. They differ from the OpenAI-compat
//! shape used by most other local servers (llama.cpp, LM Studio,
//! vLLM, LocalAI), so they get their own client.
//!
//! For a non-Ollama backend, see [`crate::openai_compat`].

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::provider::{ChatMessage, ChatProvider};
use crate::rag::EmbedProvider;

/// HTTP-backed Ollama `/api/chat` client.
pub struct OllamaChat {
    host: String,
    timeout_secs: u64,
}

impl OllamaChat {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            timeout_secs: 240,
        }
    }
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

#[derive(Serialize)]
struct ChatOptions {
    temperature: f32,
    num_ctx: u32,
}

#[derive(Serialize)]
struct ChatReq<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    stream: bool,
    options: ChatOptions,
}

#[derive(Deserialize)]
struct ChatRespMsg {
    content: String,
}
#[derive(Deserialize)]
struct ChatResp {
    message: ChatRespMsg,
}

impl ChatProvider for OllamaChat {
    fn call_chat(&self, model: &str, messages: &[ChatMessage]) -> Result<String> {
        let req = ChatReq {
            model,
            messages,
            stream: false,
            options: ChatOptions {
                temperature: 0.0,
                num_ctx: 8192,
            },
        };
        let body = serde_json::to_string(&req).context("serialize chat request")?;
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build();
        let resp = agent
            .post(&format!("{}/api/chat", self.host))
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| anyhow!("ollama /api/chat: {e}"))?;
        let body = resp
            .into_string()
            .context("read ollama chat response body")?;
        let parsed: ChatResp =
            serde_json::from_str(&body).context("decode ollama chat response")?;
        Ok(parsed.message.content)
    }
}

/// HTTP-backed Ollama `/api/embeddings` client.
pub struct OllamaEmbed {
    host: String,
    model: String,
    timeout_secs: u64,
}

impl OllamaEmbed {
    pub fn new(host: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            model: model.into(),
            timeout_secs: 60,
        }
    }
}

#[derive(Serialize)]
struct EmbedReq<'a> {
    model: &'a str,
    prompt: &'a str,
}

#[derive(Deserialize)]
struct EmbedResp {
    embedding: Vec<f32>,
}

impl EmbedProvider for OllamaEmbed {
    fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let req = EmbedReq {
            model: &self.model,
            prompt: text,
        };
        let body = serde_json::to_string(&req).context("serialize embed request")?;
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build();
        let resp = agent
            .post(&format!("{}/api/embeddings", self.host))
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| anyhow!("ollama /api/embeddings: {e}"))?;
        let body = resp
            .into_string()
            .context("read ollama embeddings response body")?;
        let parsed: EmbedResp =
            serde_json::from_str(&body).context("decode ollama embeddings response")?;
        Ok(parsed.embedding)
    }
}
