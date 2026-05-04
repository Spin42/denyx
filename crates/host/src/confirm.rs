//! Confirm-per-call hook: synchronous callback the host invokes before
//! running a capability listed in `policy.confirm_per_call`.
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
