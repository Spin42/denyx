//! `denyx hook-daemon` — a long-lived process behind a Unix domain
//! socket that keeps a `denyx hook`-equivalent policy resident and
//! pre-parsed, so `denyx hook --daemon-socket <path>` invocations skip
//! the cold policy parse that's their dominant per-call latency cost.
//!
//! Motivation: `denyx hook`'s own contract is carefully fail-closed
//! (see `hook.rs`'s module doc — `catch_unwind`-wrapped, exit 0 only
//! on a confirmed allow, exit 2 for everything else). But the
//! *calling harness* (Claude Code's `PreToolUse` hooks) fails OPEN on
//! a timeout or malformed output — behavior Denyx does not control.
//! The end-to-end guarantee of a hook-based integration is bounded by
//! that timeout, so making `denyx hook` itself fast and predictable
//! directly shrinks the window where "denyx is just slow today"
//! silently becomes "the harness timed out and allowed the call
//! anyway." A warm daemon (policy already parsed, audit sink already
//! open) removes the cold-start cost entirely.
//!
//! ## Design (deliberately simple for a first version)
//!
//! - **Transport**: a Unix domain stream socket, one connection per
//!   request (no multiplexing, no keep-alive). The client writes the
//!   exact JSON it would otherwise send on `denyx hook`'s stdin, then
//!   half-closes its write side (`shutdown(Write)`); the server reads
//!   to EOF, processes, writes a tagged response, and closes.
//! - **Response format**: one tag byte (`0x00` = Allow, `0x01` =
//!   Deny) followed by the UTF-8 payload — the exact JSON `denyx hook`
//!   would print to stdout for Allow, or the deny reason string for
//!   Deny.
//! - **Fixed daemon-side config.** `--policy`, `--audit-log`, and
//!   `--task-id` are set ONCE at `denyx hook-daemon start` and never
//!   overridden per-request — the wire protocol carries only
//!   `tool_name`/`tool_input`, nothing else. This is a deliberate
//!   simplification: it avoids needing to plumb per-call overrides
//!   through the socket, but it means every `denyx hook
//!   --daemon-socket ...` invocation that successfully reaches the
//!   daemon gets decided by the DAEMON's fixed policy, not whatever
//!   `--policy`/`--task-id` that particular invocation happened to
//!   pass. Operators must keep the daemon's startup flags consistent
//!   with what direct-mode invocations would use — e.g. by launching
//!   both from the same wrapper script / environment so they can't
//!   drift apart. `denyx hook`'s fallback path (used whenever the
//!   daemon is unreachable) always uses ITS OWN args, so a stopped or
//!   never-started daemon is always safe, just slower — never a
//!   silent policy substitution.
//! - **No self-daemonization.** `denyx hook-daemon start` runs in the
//!   foreground, matching plenty of Unix server conventions — background
//!   it yourself (`&`, `nohup`, a systemd unit, a supervisor). Rust's
//!   standard library has no portable double-fork primitive, and a
//!   hand-rolled one is a plausible source of subtle bugs for a
//!   security-relevant control-plane process; foreground-by-default
//!   with the operator owning process supervision is the safer
//!   default for a first implementation.
//! - **Stale-socket recovery, no signal handling.** `start` checks
//!   whether an existing socket file actually answers before binding;
//!   if not (the owning process crashed without cleaning up), it
//!   removes the stale file and proceeds. `stop` sends `SIGTERM` via
//!   the system `kill` binary (avoiding a new dependency on a signals
//!   crate) to the PID recorded in a sibling `.pid` file; the process
//!   exiting on the default `SIGTERM` disposition is sufficient — no
//!   custom signal handler removes the socket/PID files on exit in
//!   this first version, so `start` doing the stale-check is what
//!   keeps repeated start/stop cycles working cleanly rather than a
//!   clean-shutdown path.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde_json::Value;

use crate::hook;

#[derive(Parser, Debug)]
pub struct HookDaemonCli {
    #[command(subcommand)]
    pub command: HookDaemonCommand,
}

#[derive(Subcommand, Debug)]
pub enum HookDaemonCommand {
    /// Start the daemon in the foreground. Loads the policy once,
    /// binds the Unix socket, and serves requests until killed.
    Start(HookDaemonStartArgs),
    /// Stop a running daemon (sends SIGTERM to the PID in its `.pid`
    /// file, derived from the same `--policy`/`--socket` you'd pass
    /// to `start`).
    Stop(HookDaemonSocketArgs),
    /// Report whether a daemon appears to be running and reachable at
    /// the socket path derived from `--policy`/`--socket`.
    Status(HookDaemonSocketArgs),
}

#[derive(Parser, Debug)]
pub struct HookDaemonStartArgs {
    /// Path to the policy TOML file. Loaded once at startup and held
    /// resident for the daemon's lifetime — a change to the policy
    /// file is NOT picked up until the daemon is stopped and
    /// restarted (unlike `denyx hook` without a daemon, which
    /// reparses fresh on every invocation). Same fallback as `denyx
    /// hook`: omitted means secure-defaults.
    #[arg(short, long)]
    pub policy: Option<PathBuf>,

    /// Append audit events to this file (JSON Lines). Same posture as
    /// `denyx hook --audit-log`: refuses to write inside the policy's
    /// own reachable surface, falling back to stderr. Opened once at
    /// startup and shared across every request the daemon serves.
    #[arg(long)]
    pub audit_log: Option<PathBuf>,

    /// Task id stamped into every audit event this daemon instance
    /// emits, for every request it serves — fixed for the daemon's
    /// lifetime since the wire protocol carries no per-request
    /// override (see module doc).
    #[arg(long, default_value = "hook-daemon")]
    pub task_id: String,

    /// Unix socket path to listen on. Defaults to a path derived
    /// deterministically from the canonicalized `--policy` path (or
    /// the current directory if `--policy` is omitted) under the
    /// system temp directory, so independent projects don't collide
    /// and repeated invocations with the same policy reuse the same
    /// path without operator bookkeeping.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct HookDaemonSocketArgs {
    /// Same meaning as `denyx hook-daemon start`'s `--policy` — used
    /// only to derive the default socket path if `--socket` isn't
    /// given; must match what `start` was launched with.
    #[arg(short, long)]
    pub policy: Option<PathBuf>,

    /// Explicit socket path, overriding the derived default. Must
    /// match what `start` was launched with.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

pub fn run(cli: HookDaemonCli) -> i32 {
    let result = match cli.command {
        HookDaemonCommand::Start(args) => cmd_start(args),
        HookDaemonCommand::Stop(args) => cmd_stop(args),
        HookDaemonCommand::Status(args) => cmd_status(args),
    };
    match result {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("denyx hook daemon: {msg}");
            1
        }
    }
}

/// Deterministic default socket path: a hash of the canonicalized
/// policy path (or cwd, if no policy given) under the system temp
/// dir. Two invocations with the same effective policy location
/// agree on the same socket without any shared state beyond the
/// filesystem.
fn default_socket_path(policy: Option<&Path>) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let key = match policy {
        Some(p) => std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    std::env::temp_dir().join(format!("denyx-hook-{:x}.sock", hasher.finish()))
}

fn pid_path_for(socket_path: &Path) -> PathBuf {
    socket_path.with_extension("pid")
}

fn cmd_start(args: HookDaemonStartArgs) -> Result<(), String> {
    let policy = hook::load_policy(args.policy.as_deref())?;
    let audit = hook::build_audit_sink_for(args.audit_log.as_deref(), &policy);
    let socket_path = args
        .socket
        .clone()
        .unwrap_or_else(|| default_socket_path(args.policy.as_deref()));

    if socket_path.exists() {
        if UnixStream::connect(&socket_path).is_ok() {
            return Err(format!(
                "a denyx hook daemon already appears to be listening on {socket_path:?}; \
                 stop it first with `denyx hook-daemon stop`"
            ));
        }
        // Stale socket file left by a daemon that didn't clean up
        // (crash, kill -9). Nothing answered, so it's safe to remove.
        std::fs::remove_file(&socket_path)
            .map_err(|e| format!("failed to remove stale socket {socket_path:?}: {e}"))?;
    }

    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| format!("failed to bind {socket_path:?}: {e}"))?;

    let pid_path = pid_path_for(&socket_path);
    std::fs::write(&pid_path, std::process::id().to_string())
        .map_err(|e| format!("failed to write pid file {pid_path:?}: {e}"))?;

    eprintln!(
        "denyx hook daemon listening on {} (pid {}, policy {:?})",
        socket_path.display(),
        std::process::id(),
        args.policy
    );

    for conn in listener.incoming() {
        let Ok(mut stream) = conn else { continue };
        serve_one(&mut stream, &policy, &audit, &args.task_id);
    }
    Ok(())
}

/// Handle exactly one request on an already-accepted connection.
/// Never propagates an error up to the accept loop — a malformed
/// request or a client that disconnects mid-write denies that one
/// connection and the daemon keeps serving.
fn serve_one(
    stream: &mut UnixStream,
    policy: &denyx_policy::Policy,
    audit: &std::sync::Arc<dyn denyx_host::AuditSink>,
    task_id: &str,
) {
    let mut raw = String::new();
    if stream.read_to_string(&mut raw).is_err() {
        let _ = write_response(stream, &Err("failed to read request".to_string()));
        return;
    }
    let response = match serde_json::from_str::<Value>(&raw) {
        Ok(request) => hook::handle_request(policy, audit, task_id, &request),
        Err(e) => Err(format!("malformed JSON request: {e}")),
    };
    let _ = write_response(stream, &response);
}

fn write_response(
    stream: &mut UnixStream,
    response: &Result<String, String>,
) -> std::io::Result<()> {
    match response {
        Ok(payload) => {
            stream.write_all(&[0u8])?;
            stream.write_all(payload.as_bytes())
        }
        Err(reason) => {
            stream.write_all(&[1u8])?;
            stream.write_all(reason.as_bytes())
        }
    }
}

fn cmd_stop(args: HookDaemonSocketArgs) -> Result<(), String> {
    let socket_path = args
        .socket
        .clone()
        .unwrap_or_else(|| default_socket_path(args.policy.as_deref()));
    let pid_path = pid_path_for(&socket_path);
    let pid = std::fs::read_to_string(&pid_path)
        .map_err(|e| format!("no pid file at {pid_path:?} (is the daemon running?): {e}"))?;
    let pid = pid.trim();

    let status = std::process::Command::new("kill")
        .args(["-TERM", pid])
        .status()
        .map_err(|e| format!("failed to run kill: {e}"))?;
    if !status.success() {
        return Err(format!(
            "kill -TERM {pid} failed (process already gone? stale pid file?)"
        ));
    }
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&socket_path);
    eprintln!("denyx hook daemon (pid {pid}) stopped");
    Ok(())
}

fn cmd_status(args: HookDaemonSocketArgs) -> Result<(), String> {
    let socket_path = args
        .socket
        .clone()
        .unwrap_or_else(|| default_socket_path(args.policy.as_deref()));
    match UnixStream::connect(&socket_path) {
        Ok(_) => {
            println!("denyx hook daemon: reachable at {}", socket_path.display());
            Ok(())
        }
        Err(_) if socket_path.exists() => {
            println!(
                "denyx hook daemon: socket file exists at {} but nothing answers (stale — \
                 `denyx hook-daemon start` will clean it up)",
                socket_path.display()
            );
            Ok(())
        }
        Err(_) => {
            println!(
                "denyx hook daemon: not running (no socket at {})",
                socket_path.display()
            );
            Ok(())
        }
    }
}

/// Client side: send `raw_request` (the exact bytes `denyx hook`
/// itself read from stdin) to a running daemon and return its
/// decision. Returns `Err` for anything that means "daemon
/// unreachable, caller should fall back to direct evaluation" — a
/// connection failure, an I/O error, or a malformed/short response.
/// Never returns `Err` for a legitimate ALLOW/DENY decision from the
/// daemon; that's the inner `Result<String, String>` (Ok = allow
/// payload to print, Err = deny reason).
pub(crate) fn client_request(
    socket_path: &Path,
    raw_request: &str,
) -> Result<Result<String, String>, String> {
    let mut stream =
        UnixStream::connect(socket_path).map_err(|e| format!("connect failed: {e}"))?;
    stream
        .write_all(raw_request.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("shutdown failed: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("read failed: {e}"))?;
    let Some((&tag, payload)) = response.split_first() else {
        return Err("empty response from daemon".to_string());
    };
    let payload = String::from_utf8_lossy(payload).to_string();
    match tag {
        0 => Ok(Ok(payload)),
        1 => Ok(Err(payload)),
        other => Err(format!("unknown response tag {other} from daemon")),
    }
}
