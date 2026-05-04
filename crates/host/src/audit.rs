//! Append-only audit log. Slice 1: stdlib JSON Lines writer (file or
//! stderr) plus a NullAuditSink for tests. Slice 2 work: tamper-evident
//! signing, Merkle chaining, OpenTelemetry adapter.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: String,
    pub task_id: String,
    pub step: u32,
    pub capability: String,
    pub status: AuditStatus,
    /// Free-form structured detail. Capability-specific shape.
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Allowed,
    Denied,
    Errored,
}

impl AuditEvent {
    pub fn fs(
        task_id: &str,
        step: u32,
        cap: &str,
        path: &Path,
        ok: bool,
        err: Option<String>,
    ) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: cap.into(),
            status: if ok {
                AuditStatus::Allowed
            } else {
                AuditStatus::Errored
            },
            detail: serde_json::json!({
                "path": path.display().to_string(),
                "error": err,
            }),
        }
    }

    pub fn http(
        task_id: &str,
        step: u32,
        cap: &str,
        url: &str,
        ok: bool,
        err: Option<String>,
    ) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: cap.into(),
            status: if ok {
                AuditStatus::Allowed
            } else {
                AuditStatus::Errored
            },
            detail: serde_json::json!({
                "url": url,
                "error": err,
            }),
        }
    }

    pub fn subprocess(
        task_id: &str,
        step: u32,
        argv: &[String],
        exit: Option<i32>,
        ok: bool,
        err: Option<String>,
    ) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: "subprocess.exec".into(),
            status: if ok {
                AuditStatus::Allowed
            } else {
                AuditStatus::Errored
            },
            detail: serde_json::json!({
                "argv": argv,
                "exit": exit,
                "error": err,
            }),
        }
    }

    pub fn env(
        task_id: &str,
        step: u32,
        var_name: &str,
        ok: bool,
        err: Option<String>,
    ) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: "env.read".into(),
            status: if ok {
                AuditStatus::Allowed
            } else {
                AuditStatus::Errored
            },
            detail: serde_json::json!({
                "name": var_name,
                "error": err,
            }),
        }
    }

    pub fn denied(task_id: &str, step: u32, cap: &str, target: &str, reason: &str) -> Self {
        Self {
            ts: now_iso(),
            task_id: task_id.into(),
            step,
            capability: cap.into(),
            status: AuditStatus::Denied,
            detail: serde_json::json!({
                "target": target,
                "reason": reason,
            }),
        }
    }
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Sink trait. Implementations are expected to be cheap (or async-batched
/// internally) since they're called inline with capability evaluation.
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: AuditEvent);
}

pub struct NullAuditSink;
impl AuditSink for NullAuditSink {
    fn emit(&self, _event: AuditEvent) {}
}

pub struct JsonlAuditSink {
    path: Option<PathBuf>,
    inner: Mutex<Box<dyn Write + Send>>,
}

impl JsonlAuditSink {
    /// Append to a file (creating if needed), opening in append mode.
    pub fn file(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(Box::new(f)),
        })
    }

    /// Stream to stderr.
    pub fn stderr() -> Self {
        Self {
            path: None,
            inner: Mutex::new(Box::new(std::io::stderr())),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl AuditSink for JsonlAuditSink {
    fn emit(&self, event: AuditEvent) {
        let mut w = self.inner.lock().expect("audit lock");
        // We swallow errors here on purpose: an audit-write failure must
        // not be allowed to influence the visible run outcome.
        if let Ok(line) = serde_json::to_string(&event) {
            let _ = writeln!(w, "{}", line);
            let _ = w.flush();
        }
    }
}
