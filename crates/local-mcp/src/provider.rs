//! Provider-agnostic abstractions for the local-executor pipeline.
//!
//! Two traits — [`ChatProvider`] and [`crate::rag::EmbedProvider`] —
//! plus the common [`ChatMessage`] type and the `strip_fences`
//! helper. Concrete implementations live in [`crate::ollama`]
//! (Ollama's native API) and [`crate::openai_compat`] (the
//! OpenAI-compatible API exposed by llama.cpp's server, LM Studio,
//! vLLM, LocalAI, Text Generation WebUI's OpenAI extension, etc.).
//!
//! The traits are designed to be cheap to add a new provider for:
//! a new backend is roughly "implement two functions, register a
//! `--provider` value." Custom providers can also be linked in by
//! depending on this crate as a library and writing a struct that
//! implements the traits — `denyx-local-mcp` is library-first for
//! exactly that case.

use anyhow::Result;
use serde::Serialize;

/// One message in a chat-style request. Roles are passed through
/// verbatim — concrete impls map them to whatever the underlying API
/// expects (most use `system` / `user` / `assistant` directly).
#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
        }
    }
}

/// "Given a sequence of messages, return the assistant's reply."
/// Implementors are responsible for HTTP, retries, decoding, etc.
pub trait ChatProvider: Send + Sync {
    /// Run a chat completion. `model` is provider-specific (Ollama
    /// model name, OpenAI model id, etc. — the CLI passes through
    /// whatever the operator typed).
    fn call_chat(&self, model: &str, messages: &[ChatMessage]) -> Result<String>;
}

/// Blanket impl: `Box<dyn ChatProvider>` is itself a `ChatProvider`,
/// so the runtime-selected provider in `main.rs` can be passed
/// through generic `T: ChatProvider + ?Sized` parameters.
impl<T: ?Sized + ChatProvider> ChatProvider for Box<T> {
    fn call_chat(&self, model: &str, messages: &[ChatMessage]) -> Result<String> {
        (**self).call_chat(model, messages)
    }
}

/// Strip Markdown code fences from the start/end of a string. Handles
/// the common pattern of an LLM wrapping its output in ```python …```
/// or unlabeled ``` … ``` even when asked for raw code. Provider-
/// independent — every chat backend shows the same "model adds fences
/// despite instructions" behaviour.
pub fn strip_fences(text: &str) -> String {
    let trimmed = text.trim();
    if !trimmed.starts_with("```") {
        return trimmed.to_string();
    }
    let nl = match trimmed.find('\n') {
        Some(i) => i,
        None => return trimmed.to_string(),
    };
    let inner = &trimmed[nl + 1..];
    let inner = inner.trim_end();
    if let Some(stripped) = inner.strip_suffix("```") {
        stripped.trim().to_string()
    } else {
        inner.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_fences_passes_through_text_without_fences() {
        assert_eq!(strip_fences("x = 1\nprint(x)"), "x = 1\nprint(x)");
    }

    #[test]
    fn strip_fences_strips_leading_language_tag() {
        let s = "```python\nx = 1\nprint(x)\n```";
        assert_eq!(strip_fences(s), "x = 1\nprint(x)");
    }

    #[test]
    fn strip_fences_strips_unlabeled_fences() {
        let s = "```\nprint('hi')\n```";
        assert_eq!(strip_fences(s), "print('hi')");
    }

    #[test]
    fn strip_fences_handles_trailing_whitespace_after_fence() {
        let s = "```python\nprint('hi')\n```\n\n";
        assert_eq!(strip_fences(s), "print('hi')");
    }

    #[test]
    fn strip_fences_handles_only_opening_fence() {
        // Pathological: opening fence but no closing.
        let s = "```python\nprint('hi')";
        assert_eq!(strip_fences(s), "print('hi')");
    }

    #[test]
    fn strip_fences_returns_input_when_only_one_line_with_fence() {
        // Edge case: fence and no newline at all.
        assert_eq!(strip_fences("```nope"), "```nope");
    }

    #[test]
    fn strip_fences_trims_outer_whitespace() {
        assert_eq!(strip_fences("\n\n   print(1)\n\n"), "print(1)");
    }

    #[test]
    fn chat_message_constructors_set_role() {
        assert_eq!(ChatMessage::system("a").role, "system");
        assert_eq!(ChatMessage::user("b").role, "user");
        assert_eq!(ChatMessage::assistant("c").role, "assistant");
    }
}
