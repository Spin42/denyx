//! Confirm-per-call hook: synchronous callback the host invokes before
//! running a capability listed in `policy.requires_approval`.
//!
//! The CLI provides a TTY implementation (stderr prompt + stdin yes/no).
//! Embedded integrators (Claude Code, opencode) implement this trait
//! against their own UI surface. The MCP server (Slice 3) implements it
//! by sending an MCP request out and waiting for the answer.

#[derive(Debug, Clone)]
pub struct ConfirmRequest {
    pub task_id: String,
    pub capability: String,
    pub summary: String,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConfirmDecision {
    Allow,
    Deny,
}

pub trait ConfirmHook: Send + Sync {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmDecision;
}

/// Render script-controlled text (a summary's path, URL or argv) for a
/// human prompt. Control characters are escaped so terminal sequences
/// cannot erase the real prompt and draw a fake one.
pub fn display_safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().collect()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Default safe behavior when no hook is wired: deny everything that
/// requires confirmation. Forces the integrator to make a deliberate
/// choice.
pub struct DenyAllConfirm;
impl ConfirmHook for DenyAllConfirm {
    fn confirm(&self, _request: &ConfirmRequest) -> ConfirmDecision {
        ConfirmDecision::Deny
    }
}

/// Auto-allow (useful for tests and demos that don't want a TTY).
pub struct AllowAllConfirm;
impl ConfirmHook for AllowAllConfirm {
    fn confirm(&self, _request: &ConfirmRequest) -> ConfirmDecision {
        ConfirmDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AEG-PEN-R5-007: a summary carries script-controlled text, so its
    /// control characters must not reach the operator's terminal.
    #[test]
    fn display_safe_escapes_control_characters() {
        let spoof = "a\u{1b}[2K\r\n\u{1b}[1Afake\u{7f}\u{9b}b";
        let shown = display_safe(spoof);
        assert!(
            !shown.chars().any(char::is_control),
            "control characters survived: {shown:?}"
        );
        assert!(shown.starts_with('a') && shown.ends_with('b'));
    }

    #[test]
    fn display_safe_keeps_printable_text() {
        let url = "net.http_get: https://api.example.com/v1?q=é";
        assert_eq!(display_safe(url), url);
    }
}
