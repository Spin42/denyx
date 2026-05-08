//! Subprocess client for `denyx-mcp`.
//!
//! Spawns `denyx-mcp` as a child process and speaks newline-delimited
//! JSON-RPC 2.0 over its stdio, then exposes a single high-level
//! method [`DenyxMcpClient::denyx_run`] used by the pipeline. The
//! Denyx server is the policy gate: every Starlark program the local
//! executor synthesises is run through it.
//!
//! Mirrors `local_mcp.py`'s `DenyxMcpClient`, with the same
//! `--confirm-mode auto-allow` choice (the orchestrator's
//! `delegate_to_local` calls would otherwise be blanket-denied by the
//! new `auto` default since this client doesn't advertise MCP
//! elicitation).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// One-line JSON-RPC client for a child `denyx-mcp`.
///
/// Construction spawns the subprocess and performs the MCP
/// `initialize` handshake; failure to initialise (e.g. bad policy
/// path, binary missing) propagates as an error from `new`. After
/// construction the client is held until [`Self::close`] is called.
pub struct DenyxMcpClient {
    inner: Mutex<Inner>,
}

struct Inner {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl DenyxMcpClient {
    /// Spawn a child `denyx-mcp` and run the MCP initialize handshake.
    ///
    /// `audit_log` is optional — if `None`, the child server runs
    /// without an audit log path (events go to its default location
    /// per its own CLI defaults).
    pub fn spawn(mcp_bin: &Path, policy: &Path, audit_log: Option<&Path>) -> Result<Self> {
        let mut cmd = Command::new(mcp_bin);
        cmd.arg("--policy")
            .arg(policy)
            .arg("--confirm-mode")
            .arg("auto-allow");
        if let Some(p) = audit_log {
            cmd.arg("--audit-log").arg(p);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawn denyx-mcp at {mcp_bin:?}"))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("denyx-mcp child had no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("denyx-mcp child had no stdout"))?;
        let stdout = BufReader::new(stdout);

        let mut inner = Inner {
            child,
            stdin,
            stdout,
            next_id: 0,
        };

        let init = inner.call(
            "initialize",
            Some(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "local-executor", "version": "0"},
            })),
        )?;
        if init.get("result").is_none() {
            return Err(anyhow!("denyx-mcp initialize failed: {init}"));
        }

        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Call `tools/call denyx_run` with the given Starlark script and
    /// task id. Returns the full JSON-RPC response (caller pulls the
    /// `result` / `error` fields).
    pub fn denyx_run(&self, script: &str, task_id: &str) -> Result<Value> {
        let mut inner = self.inner.lock().expect("denyx_client mutex");
        inner.call(
            "tools/call",
            Some(json!({
                "name": "denyx_run",
                "arguments": { "script": script, "task_id": task_id },
            })),
        )
    }

    /// Close the subprocess. Non-fatal if the child has already
    /// exited or wait() times out (in that case it's killed).
    pub fn close(self) {
        let mut inner = match self.inner.into_inner() {
            Ok(i) => i,
            Err(p) => p.into_inner(),
        };
        // Drop stdin first so the server sees EOF and exits cleanly.
        let _ = inner.stdin.flush();
        drop(inner.stdin);
        // Best-effort wait, then kill.
        let _ = wait_with_timeout(&mut inner.child, std::time::Duration::from_secs(3));
    }
}

fn wait_with_timeout(child: &mut Child, dur: std::time::Duration) -> Option<()> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Some(()),
            Ok(None) if start.elapsed() >= dur => {
                let _ = child.kill();
                return None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
}

impl Inner {
    fn call(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        self.next_id += 1;
        let mut req = json!({
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
        });
        if let Some(p) = params {
            req["params"] = p;
        }
        let line = serde_json::to_string(&req)? + "\n";
        self.stdin
            .write_all(line.as_bytes())
            .context("write to denyx-mcp stdin")?;
        self.stdin.flush().context("flush denyx-mcp stdin")?;

        let mut resp_line = String::new();
        let n = self
            .stdout
            .read_line(&mut resp_line)
            .context("read denyx-mcp stdout")?;
        if n == 0 {
            return Err(anyhow!("denyx-mcp server closed unexpectedly"));
        }
        let resp: Value = serde_json::from_str(resp_line.trim())
            .with_context(|| format!("parse denyx-mcp response: {resp_line:?}"))?;
        Ok(resp)
    }
}

/// Default location for the denyx-mcp binary if the operator doesn't
/// pass `--mcp-bin`. Mirrors the Python's `DEFAULT_DENYX_MCP` —
/// `target/release/denyx-mcp` relative to the workspace root, which
/// works when built from source. For `cargo install`-d workflows the
/// operator should pass the absolute path on PATH.
pub fn default_mcp_bin_guess(repo_root: &Path) -> PathBuf {
    repo_root.join("target").join("release").join("denyx-mcp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mcp_bin_guess_is_relative_to_workspace() {
        let p = default_mcp_bin_guess(Path::new("/some/repo"));
        assert!(p.ends_with("target/release/denyx-mcp"));
        assert!(p.starts_with("/some/repo"));
    }
}
