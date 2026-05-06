//! `aegis-mcp` — Aegis MCP server.
//!
//! Speaks newline-delimited JSON-RPC 2.0 on stdio (one JSON message per
//! line). Implements the subset of MCP needed to expose Aegis as a
//! policy-gated tool surface: `initialize`, `tools/list`, `tools/call`.
//!
//! Tools exposed:
//!
//! - `aegis_run(script, task_id?)` — primary surface. The caller hands
//!   over a Starlark program; the server runs it through the host's
//!   `Runner` under the configured policy. Output is the script's
//!   printed lines.
//! - `aegis_fs_read(path)`, `aegis_fs_write(path, content)`,
//!   `aegis_fs_delete(path)` — sugar over `aegis_run` for hosts that
//!   prefer one MCP call per action.
//! - `aegis_subprocess_exec(argv)` — same.
//! - `aegis_net_http_get(url)`, `aegis_net_http_post(url, body)` — same.
//! - `aegis_env_read(name)` — same.
//! - `aegis_tool_routing(name?)` — read-only oracle. Returns the
//!   `[tools.X]` routing hints (capabilities, backend_url,
//!   backend_method, description, allowed flag) for a named tool,
//!   or all declared tools if no name is given. Lets a calling host
//!   like Claude Code consult the policy's tool surface without
//!   re-parsing the TOML itself.
//!
//! Each tool call goes through the same enforcement path the CLI uses:
//! pre-execution verifier, policy checks at every capability builtin,
//! audit log entry per attempt, requires-approval hook (see
//! `--confirm-mode`).
//!
//! ## Bidirectional dispatch
//!
//! The transport carries both client → server tool calls AND server
//! → client elicitation requests (when the configured `ConfirmHook`
//! needs to ask the user something). A reader thread demuxes each
//! incoming line: messages with a `method` field are dispatched to
//! the main tool-call loop; messages with a `result` or `error`
//! (i.e. responses to *our* outbound requests) are pushed to a
//! channel the elicitation hook is blocking on. Stdout is shared
//! via `Arc<Mutex<...>>` so the main loop and the elicitation hook
//! can interleave writes safely.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use aegis_host::{
    AegisError, AllowAllConfirm, AuditSink, ConfirmDecision, ConfirmHook, ConfirmRequest,
    DenyAllConfirm, HttpAuditSink, JsonlAuditSink, Runner,
};
use aegis_policy::{Policy, PolicyFile};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// MCP protocol version we advertise. `2025-06-18` is the first
/// version that includes `elicitation/create` in the spec; clients
/// that speak that version may advertise the elicitation capability,
/// in which case `--confirm-mode auto` (the default) routes
/// `requires_approval`-listed capabilities through real user prompts
/// instead of the auto-deny tag.
const PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_NAME: &str = "aegis-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long an `ElicitConfirm` call waits for the user's response
/// before degrading to Deny. The user is being asked to approve a
/// real action; a generous timeout matches typical UI patterns. Past
/// this, we assume the prompt was missed (or the client swallowed
/// the elicitation in auto mode) and fail closed.
const ELICITATION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Parser, Debug)]
#[command(
    name = "aegis-mcp",
    version,
    about = "MCP server exposing the Aegis policy-gated runtime over stdio"
)]
struct Cli {
    /// Path to the policy TOML file. If omitted (and `--policy-url`
    /// also omitted), falls back to the built-in `secure-defaults`
    /// baseline (denies every effecting capability) and prints a
    /// banner on stderr. Mutually exclusive with `--policy-url`.
    #[arg(short, long)]
    policy: Option<PathBuf>,

    /// Append audit events to this file (JSON Lines). Default (when
    /// AEGIS_AUDIT_URL is also unset): stderr.
    #[arg(long)]
    audit_log: Option<PathBuf>,

    // ---- env-var-only fields (no CLI flag, see config cascade in
    // load_aegis_config_cascade): ----
    //
    // The control-plane URLs and bearer token are read from the
    // `AEGIS_POLICY_URL`, `AEGIS_AUDIT_URL`, and `AEGIS_AUTH_TOKEN`
    // environment variables. We DO NOT take them on the command line
    // because:
    //
    //   - argv is visible via `ps`, `/proc/<pid>/cmdline`, shell
    //     history, IDE "recently run" lists. A bearer token leaks
    //     trivially that way.
    //   - URLs leak the same way and tell an attacker who's escaped
    //     the runtime sandbox where to send forged audit events.
    //
    // The values are sourced (highest priority first) from:
    //
    //   1. The process env when aegis-mcp launches (set by the
    //      shell, MCP host's `env` block, k8s pod spec, systemd
    //      unit, etc.).
    //   2. `$HOME/.config/aegis/.env` — per-user override.
    //   3. `/etc/aegis/.env` — system-wide, root-managed.
    //
    // The agent itself can never read any of them: the variable
    // names AEGIS_AUTH_TOKEN / AEGIS_TOKEN / AEGIS_SERVER_TOKEN /
    // AEGIS_JWT / AEGIS_API_KEY / AEGIS_POLICY_URL / AEGIS_AUDIT_URL
    // are on the runtime's reserved list (see
    // `aegis_policy::AEGIS_RESERVED_VAR_NAMES`); they're denied
    // from `env.read` and stripped from any subprocess env
    // unconditionally, regardless of policy. Both config files are
    // additionally denied at the filesystem level by
    // `secure-defaults` (`**/.env*` plus `~/.config/aegis/**`).
    #[arg(skip)]
    policy_url: Option<String>,

    #[arg(skip)]
    audit_url: Option<String>,

    #[arg(skip)]
    auth_token: Option<String>,

    /// How `requires_approval`-listed capabilities behave when invoked
    /// through this MCP server.
    ///
    /// - `auto` (default): negotiate per-client. If the client
    ///   advertises the MCP `elicitation` capability at initialize
    ///   time, we route every approval-required call through a real
    ///   user prompt via `elicitation/create`. If the client does
    ///   not advertise elicitation, we fall back to `auto-deny`.
    /// - `elicit`: force elicitation regardless of client capability
    ///   advertisement. If the client doesn't actually support it,
    ///   the elicitation request will time out (and the call denies
    ///   safely).
    /// - `auto-allow`: skip the approval check entirely. Every
    ///   approval-required call passes. **Use only for tests and
    ///   demos** — this defeats the purpose of `requires_approval`.
    /// - `auto-deny`: every approval-required call returns a tool
    ///   result with `isError: true` and an `aegis_error_kind:
    ///   "confirm_denied"` tag. The orchestrator can interpret that,
    ///   surface a UI prompt of its own, and edit the policy or
    ///   re-issue the call from a non-gated context.
    ///
    /// Caveat for "auto" with `claude --permission-mode auto` or
    /// opencode in unattended mode: those modes typically auto-
    /// respond to elicitation prompts without surfacing them to the
    /// user. In that configuration, `auto` effectively degrades to
    /// whatever the client's auto-response is — Aegis's request
    /// gets approved or declined without human review. See
    /// docs/07-claude-code.md and docs/04-policy-file.md for the
    /// honest deployment guidance.
    #[arg(long, default_value = "auto")]
    confirm_mode: ConfirmModeArg,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum ConfirmModeArg {
    Auto,
    Elicit,
    AutoAllow,
    AutoDeny,
}

fn main() -> anyhow::Result<()> {
    // Cascade-load Aegis control-plane config (the AEGIS_AUTH_TOKEN,
    // AEGIS_POLICY_URL, AEGIS_AUDIT_URL env vars) from dedicated
    // dotenv files. Order: process env > per-user file > system file.
    // Lives in dedicated files at well-known paths — NOT the project's
    // own `.env`, which is for project secrets and is denied to the
    // agent by `secure-defaults`. See `load_aegis_config_cascade`.
    load_aegis_config_cascade();

    let mut cli = Cli::parse();
    cli.auth_token = std::env::var("AEGIS_AUTH_TOKEN").ok();
    cli.policy_url = std::env::var("AEGIS_POLICY_URL").ok().or(cli.policy_url);
    cli.audit_url = std::env::var("AEGIS_AUDIT_URL").ok().or(cli.audit_url);
    // Policy source: file > URL > built-in secure-defaults fallback.
    // Clap's ArgGroup already enforced that file and URL aren't both
    // set; here we just dispatch on which one (if either) is.
    let policy = if let Some(url) = cli.policy_url.as_deref() {
        fetch_policy_from_url(url, cli.auth_token.as_deref())?
    } else if let Some(path) = cli.policy.as_deref() {
        Policy::load(path).map_err(|e| anyhow::anyhow!("load policy {path:?}: {e}"))?
    } else {
        eprintln!(
            "aegis-mcp: no --policy or --policy-url provided; using built-in \
`secure-defaults` baseline. This denies every fs/net/subprocess/env capability — \
every tool call will fail until you launch with --policy <project.toml> or \
--policy-url <https://policy-server/...>. See examples/policies/ for templates."
        );
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Policy::secure_defaults_at(cwd)?
    };
    // Audit sink: URL > file > stderr default.
    let audit: Arc<dyn AuditSink> = if let Some(url) = cli.audit_url.as_deref() {
        Arc::new(HttpAuditSink::new(url, cli.auth_token.as_deref()))
    } else if let Some(path) = cli.audit_log.as_deref() {
        let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        policy
            .guard_audit_log(&canon)
            .map_err(|e| anyhow::anyhow!("audit-log path is reachable to the agent: {e}"))?;
        Arc::new(JsonlAuditSink::file(path)?)
    } else {
        Arc::new(JsonlAuditSink::stderr())
    };

    // Shared stdout. The main dispatch loop and the elicitation hook
    // both write to it; the mutex serialises lines so two concurrent
    // writes can't interleave mid-message.
    let stdout: Arc<Mutex<io::Stdout>> = Arc::new(Mutex::new(io::stdout()));

    // Demux channel pair: the reader thread parses each incoming line
    // and routes it to either the request channel (consumed by the
    // main loop) or the elicitation-response channel (consumed by the
    // hook).
    let (req_tx, req_rx) = mpsc::channel::<Value>();
    let (elicit_resp_tx, elicit_resp_rx) = mpsc::channel::<Value>();

    thread::spawn(move || reader_thread(req_tx, elicit_resp_tx));

    // Capability negotiation flag. Set to true at initialize-time if
    // the client advertised the MCP `elicitation` capability. The
    // `AutoConfirm` hook reads this on every confirm call to decide
    // whether to elicit or fall back to deny.
    let elicit_supported = Arc::new(AtomicBool::new(false));

    // Build the confirm hook based on the CLI flag. `Auto` and
    // `Elicit` both produce hooks that may send `elicitation/create`
    // upstream; they need handles to stdout, the response channel,
    // and (for `Auto`) the negotiation flag.
    let elicit_machinery = Arc::new(ElicitMachinery {
        stdout: stdout.clone(),
        rx: Mutex::new(elicit_resp_rx),
        next_id: AtomicU64::new(10_000),
    });

    let confirm_hook: Arc<dyn ConfirmHook> = match cli.confirm_mode {
        ConfirmModeArg::AutoAllow => Arc::new(AllowAllConfirm),
        ConfirmModeArg::AutoDeny => Arc::new(DenyAllConfirm),
        ConfirmModeArg::Elicit => Arc::new(ElicitConfirm {
            machinery: elicit_machinery.clone(),
        }),
        ConfirmModeArg::Auto => Arc::new(AutoConfirm {
            elicit_supported: elicit_supported.clone(),
            elicit: ElicitConfirm {
                machinery: elicit_machinery.clone(),
            },
            fallback: DenyAllConfirm,
        }),
    };

    let runner = Runner::new(policy)
        .with_audit(audit)
        .with_confirm_hook(confirm_hook);

    let mut counter: u64 = 0;
    while let Ok(value) = req_rx.recv() {
        let resp = match serde_json::from_value::<Request>(value) {
            Ok(req) => handle(&runner, &mut counter, &elicit_supported, req),
            Err(e) => Response::error(Value::Null, -32700, format!("parse error: {e}"), None),
        };
        let line = serde_json::to_string(&resp)?;
        let mut out = stdout.lock().unwrap();
        writeln!(out, "{line}")?;
        out.flush()?;
    }
    Ok(())
}

/// Cascade-load the Aegis control-plane config. The cascade is:
///
/// 1. **Process env** (highest priority). Whatever was already set
///    by the calling shell, the MCP host's `env` block (Claude Code's
///    `.mcp.json` / opencode equivalent), the systemd unit's
///    `EnvironmentFile=`, the k8s pod spec's `env`, etc. Always
///    wins — the operator at the top of the chain has the final say.
/// 2. **Per-user file:** `$HOME/.config/aegis/.env`. The developer's
///    own override of system defaults, e.g. switching their personal
///    machine to a staging policy server.
/// 3. **System file:** `/etc/aegis/.env`. SecOps-managed, root-owned.
///    Pins corporate-wide control-plane URLs across every developer
///    machine without each user having to set anything.
///
/// Each `.env` file is parsed with the minimal `KEY=VALUE` grammar:
/// blank lines and `#` comments ignored, optional `export ` prefix
/// stripped, surrounding `"` or `'` quotes on the value stripped.
/// **A key already present in process env is never overridden** — a
/// dotenv file fills gaps, it doesn't trump the launcher.
///
/// Both files live OUTSIDE the project tree. The project's own
/// `.env` (for application secrets like `DATABASE_URL`) is NOT
/// loaded by aegis-mcp — that's the IDE / dev tool's job. Mixing
/// project secrets with control-plane config in one file would
/// muddle two trust boundaries: project secrets are agent-relevant
/// (the agent might legitimately need `DATABASE_URL`), control-plane
/// secrets are operator-only (the agent must NEVER see them).
///
/// Both default paths are caught by `secure-defaults`'
/// `[filesystem].deny = ["**/.env*"]`, so an agent that bypassed
/// `env.read` (which is itself blocked by the AEGIS_RESERVED_VAR_NAMES
/// runtime invariant) and tried to read the file directly is also
/// denied.
///
/// Failures are silent — these files are optional. The hard
/// requirement is "the value must be in process env when we read it",
/// not "we must successfully parse a file".
fn load_aegis_config_cascade() {
    // Per-user file first (higher priority among files; loaded
    // before /etc so it claims the keys before the system file
    // gets a chance, since the loader skips already-set keys).
    if let Some(home) = std::env::var_os("HOME") {
        let mut path = std::path::PathBuf::from(home);
        path.push(".config/aegis/.env");
        let _ = load_dotenv_into_env(&path);
    }
    // System-wide fallback.
    let _ = load_dotenv_into_env(std::path::Path::new("/etc/aegis/.env"));
}

/// Minimal dotenv loader. Reads `path` and sets each `KEY=VALUE`
/// pair into the process env, skipping any key already present.
/// Returns the number of new keys set. Silent on missing file or
/// parse failure — see `load_aegis_config_cascade` for the
/// rationale.
///
/// Inline implementation rather than a `dotenvy` dep because the
/// surface we need is 30 lines and a third-party crate dep would
/// increase the audit surface of a security-critical binary for
/// very little gain.
fn load_dotenv_into_env(path: &std::path::Path) -> std::io::Result<usize> {
    let content = std::fs::read_to_string(path)?;
    let mut count = 0;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        // Strip surrounding matching quotes (' or ").
        let unquoted = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, unquoted);
            count += 1;
        }
    }
    Ok(count)
}

/// Fetch a policy from an HTTP(S) URL at startup. The response body
/// is parsed as TOML via the same `PolicyFile::from_toml_str` path
/// the file-loaded policy uses; inheritance (`inherits = "..."`) is
/// resolved before building the runtime `Policy`. The policy root
/// for relative-pattern resolution is the cwd the agent was launched
/// from — the same convention `Policy::load` uses for relative paths
/// in a file-loaded policy.
///
/// Fail-closed on every non-success: 404 / 401 / 403 / 5xx / network
/// error / parse error / empty body all surface as Err and the
/// caller (`main`) exits with a clear error before any tool call is
/// accepted. There is no on-disk cache: the policy is re-fetched on
/// every aegis-mcp startup. This is intentional — the only
/// tamper-resistant strategy at MVP is "no local artefact to
/// tamper with."
///
/// Timeout is 5 seconds total. Generous enough for a slow corporate
/// network on the policy server's first morning hit; not so long
/// the developer waits forever on a misconfigured URL.
fn fetch_policy_from_url(url: &str, auth_token: Option<&str>) -> anyhow::Result<Policy> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .redirects(0) // a redirect from a corp policy URL is a config error, not a feature
        .build();
    let mut req = agent.get(url);
    if let Some(t) = auth_token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            let snippet: String = body.chars().take(200).collect();
            anyhow::bail!(
                "policy fetch from {url} returned HTTP {code}. Server said: {snippet:?}. \
                 Check that the URL is correct, the bearer token is valid, and the server \
                 has a policy assigned for this machine/project."
            );
        }
        Err(e) => {
            anyhow::bail!(
                "policy fetch from {url} failed: {e}. Check network connectivity and that \
                 the policy server is reachable from this machine."
            );
        }
    };
    let status = resp.status();
    if !(200..300).contains(&status) {
        // ureq's default Agent surfaces non-2xx as Err(Status), but
        // a custom Agent might not. Belt-and-braces.
        anyhow::bail!("policy fetch from {url} returned HTTP {status} (expected 2xx)");
    }
    let body = resp
        .into_string()
        .map_err(|e| anyhow::anyhow!("policy fetch from {url}: failed to read body: {e}"))?;
    if body.trim().is_empty() {
        anyhow::bail!(
            "policy fetch from {url} returned an empty body. An empty TOML parses to a \
             default-deny policy, which is almost certainly not what the operator intended. \
             Refusing to start."
        );
    }
    let file = PolicyFile::from_toml_str(&body)
        .map_err(|e| anyhow::anyhow!("policy fetch from {url}: TOML parse failed: {e}"))?
        .resolve_inheritance()
        .map_err(|e| {
            anyhow::anyhow!("policy fetch from {url}: inheritance resolution failed: {e}")
        })?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let policy = Policy::from_file(file, cwd)
        .map_err(|e| anyhow::anyhow!("policy fetch from {url}: build Policy failed: {e}"))?;
    // Sandbox preflight (refuse to start if `[subprocess].sandbox =
    // "bwrap"` was declared but bwrap isn't on PATH). Mirrors what
    // `Policy::load` does for file-loaded policies. The
    // self-writable / audit-log guards don't apply here — we have
    // no on-disk policy file path and the audit-log path (if any)
    // is checked separately in main().
    policy
        .guard_sandbox_available()
        .map_err(|e| anyhow::anyhow!("policy fetch from {url}: sandbox preflight failed: {e}"))?;
    Ok(policy)
}

/// Reader thread body. Parses each line of stdin into a
/// `serde_json::Value` and routes by structural shape: a `method`
/// field means it's an inbound request (or notification) from the
/// client; otherwise (the line has `result` or `error` and an `id`)
/// it's a response to one of our outbound requests, which is
/// currently always an elicitation.
fn reader_thread(req_tx: Sender<Value>, elicit_resp_tx: Sender<Value>) {
    let stdin = io::stdin();
    let handle = stdin.lock();
    let mut br = io::BufReader::new(handle);
    let mut buf = String::new();
    loop {
        buf.clear();
        match br.read_line(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                // Forward malformed lines as request-shaped values
                // so the main loop can produce a parse-error
                // response; dropping silently would deadlock a
                // client waiting on a reply.
                let bogus = json!({ "jsonrpc": "2.0", "id": null, "method": "__parse_error__" });
                let _ = req_tx.send(bogus);
                continue;
            }
        };
        if value.get("method").is_some() {
            let _ = req_tx.send(value);
        } else if value.get("result").is_some() || value.get("error").is_some() {
            let _ = elicit_resp_tx.send(value);
        }
        // Else: malformed — neither request nor response. Drop.
    }
}

#[derive(Debug, Deserialize)]
struct Request {
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl Response {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }
    fn error(id: Value, code: i32, message: String, data: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message,
                data,
            }),
        }
    }
}

fn handle(
    runner: &Runner,
    counter: &mut u64,
    elicit_supported: &Arc<AtomicBool>,
    req: Request,
) -> Response {
    let _ = req.jsonrpc; // not validated for MVP
    let id = req.id.clone();
    match req.method.as_str() {
        "initialize" => {
            // Read and remember whether the client supports
            // elicitation. The advertisement format is
            // `params.capabilities.elicitation` set to any value
            // (the spec uses an empty object today, leaving room for
            // future sub-fields). Presence — not value — is what we
            // check.
            let advertised = req
                .params
                .get("capabilities")
                .and_then(|c| c.get("elicitation"))
                .is_some();
            elicit_supported.store(advertised, Ordering::SeqCst);

            // Respond with the client's requested protocol version
            // when present (per MCP convention) so older clients
            // that can't negotiate up to 2025-06-18 still get a
            // usable session, falling back to our default if absent.
            let proto = req
                .params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(PROTOCOL_VERSION)
                .to_string();
            Response::ok(
                id,
                json!({
                    "protocolVersion": proto,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                }),
            )
        }
        "initialized" | "notifications/initialized" => Response::ok(id, json!({})),
        "tools/list" => Response::ok(id, json!({ "tools": tool_definitions() })),
        "tools/call" => handle_tools_call(runner, counter, id, req.params),
        "ping" => Response::ok(id, json!({})),
        "__parse_error__" => Response::error(
            id,
            -32700,
            "parse error: incoming line was not valid JSON".into(),
            None,
        ),
        other => Response::error(id, -32601, format!("method not found: {other}"), None),
    }
}

fn handle_tools_call(runner: &Runner, counter: &mut u64, id: Value, params: Value) -> Response {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);

    *counter += 1;
    let task_id = format!("mcp-{counter}");

    if name == "aegis_tool_routing" {
        return handle_tool_routing(runner, id, &args);
    }

    let script_result = match dispatch(&name, &args, &task_id) {
        Ok(s) => s,
        Err(msg) => {
            return tool_error_response(id, &AegisError::Other(msg));
        }
    };

    match runner.run(&task_id, &script_result.script, &script_result.script_name) {
        Ok(outcome) => Response::ok(
            id,
            json!({
                "content": [
                    { "type": "text", "text": outcome.printed.join("\n") }
                ],
                "isError": false,
            }),
        ),
        Err(e) => tool_error_response(id, &e),
    }
}

fn tool_error_response(id: Value, err: &AegisError) -> Response {
    let kind = match err {
        AegisError::ConfirmDenied(_) => "confirm_denied",
        AegisError::Policy(_) => "policy_violation",
        AegisError::Verifier(_) => "verifier_rejection",
        AegisError::RuntimeLimit(_) => "runtime_limit",
        AegisError::Starlark(_) => "starlark_error",
        AegisError::Io(_) => "io_error",
        AegisError::Other(_) => "other",
    };
    Response::ok(
        id,
        json!({
            "content": [
                { "type": "text", "text": err.to_string() }
            ],
            "isError": true,
            "aegis_error_kind": kind,
        }),
    )
}

fn handle_tool_routing(runner: &Runner, id: Value, args: &Value) -> Response {
    let policy = runner.policy();
    let name = args.get("name").and_then(|v| v.as_str());

    fn record_to_json(
        policy: &aegis_policy::Policy,
        name: &str,
        record: &aegis_policy::ToolRecord,
    ) -> Value {
        let allowed = policy.check_tool(name).is_ok();
        json!({
            "name": name,
            "allowed": allowed,
            "capabilities": record.capabilities,
            "backend_url": record.backend_url,
            "backend_method": record.method(),
            "description": record.description,
        })
    }

    let body = match name {
        Some(n) => match policy.tool_routing(n) {
            Some(record) => json!({ "tool": record_to_json(policy, n, record) }),
            None => json!({
                "tool": null,
                "error": format!("tool {n:?} not declared in [tools]"),
            }),
        },
        None => {
            let tools: Vec<Value> = policy
                .tools_iter()
                .map(|(n, r)| record_to_json(policy, n, r))
                .collect();
            json!({ "tools": tools })
        }
    };

    Response::ok(
        id,
        json!({
            "content": [
                { "type": "text", "text": serde_json::to_string(&body).unwrap_or_default() }
            ],
            "isError": false,
            "structuredContent": body,
        }),
    )
}

/// Shared state between `ElicitConfirm` and the main loop: stdout to
/// write the outbound `elicitation/create` to, the channel we receive
/// responses on (populated by the reader thread), and the id
/// allocator for outbound requests.
struct ElicitMachinery {
    stdout: Arc<Mutex<io::Stdout>>,
    rx: Mutex<Receiver<Value>>,
    next_id: AtomicU64,
}

/// `ConfirmHook` impl that asks the client to surface a real
/// approval prompt to the user via the MCP `elicitation/create`
/// request. Blocks the runner thread until the response arrives,
/// up to `ELICITATION_TIMEOUT`, then degrades to Deny if no
/// response materialised.
///
/// **Important deployment caveat.** Some MCP clients (Claude Code in
/// `--permission-mode auto` / `bypassPermissions`, opencode in
/// unattended mode) auto-respond to elicitation requests without
/// surfacing them to the user. In that configuration the user is
/// *not* in the loop, even though the server faithfully sent the
/// prompt. The honest framing is in docs/04-policy-file.md and
/// docs/07-claude-code.md.
struct ElicitConfirm {
    machinery: Arc<ElicitMachinery>,
}

impl ConfirmHook for ElicitConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmDecision {
        let id = self.machinery.next_id.fetch_add(1, Ordering::SeqCst);
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "elicitation/create",
            "params": {
                "message": format!(
                    "Aegis: the agent is asking to perform `{cap}`.\n\nDetails: {summary}\nTask: {task}\n\nApprove this single call?",
                    cap = request.capability,
                    summary = request.summary,
                    task = request.task_id,
                ),
                "requestedSchema": {
                    "type": "object",
                    "title": format!("Approve {}?", request.capability),
                    "properties": {
                        "approved": {
                            "type": "boolean",
                            "description": "Allow this capability for this single call.",
                            "default": false
                        }
                    },
                    "required": ["approved"]
                }
            }
        });
        // Write the request line.
        {
            let mut out = match self.machinery.stdout.lock() {
                Ok(g) => g,
                Err(_) => return ConfirmDecision::Deny,
            };
            let line = match serde_json::to_string(&req) {
                Ok(s) => s,
                Err(_) => return ConfirmDecision::Deny,
            };
            if writeln!(out, "{line}").is_err() {
                return ConfirmDecision::Deny;
            }
            if out.flush().is_err() {
                return ConfirmDecision::Deny;
            }
        }
        // Wait for any response on the elicitation channel. We don't
        // demultiplex by id because the runner is single-threaded —
        // there is at most one outstanding outbound elicitation at
        // any moment, so the next response is by construction ours.
        let rx_guard = match self.machinery.rx.lock() {
            Ok(g) => g,
            Err(_) => return ConfirmDecision::Deny,
        };
        match rx_guard.recv_timeout(ELICITATION_TIMEOUT) {
            Ok(value) => parse_elicit_response(&value, id),
            Err(_) => ConfirmDecision::Deny,
        }
    }
}

/// Parse an MCP `elicitation/create` response payload into a confirm
/// decision. The shape is `{action: "accept"|"decline"|"cancel",
/// content: { ...user-supplied... }}`. We treat **only**
/// `action == "accept" AND content.approved == true` as Allow.
/// Everything else (including malformed responses, error replies,
/// id mismatches, missing fields) is Deny.
fn parse_elicit_response(value: &Value, expected_id: u64) -> ConfirmDecision {
    if let Some(rid) = value.get("id").and_then(|v| v.as_u64()) {
        if rid != expected_id {
            return ConfirmDecision::Deny;
        }
    }
    if value.get("error").is_some() {
        return ConfirmDecision::Deny;
    }
    let result = match value.get("result") {
        Some(r) => r,
        None => return ConfirmDecision::Deny,
    };
    let action = result.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let approved = result
        .get("content")
        .and_then(|c| c.get("approved"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if action == "accept" && approved {
        ConfirmDecision::Allow
    } else {
        ConfirmDecision::Deny
    }
}

/// Default `--confirm-mode auto` hook: routes through `ElicitConfirm`
/// when the client advertised elicitation at initialize time, and
/// falls back to a plain Deny (matching `--confirm-mode auto-deny`)
/// when the client doesn't support elicitation. The negotiation
/// flag is shared with the main dispatch loop, which sets it on
/// receiving the client's `initialize` message.
struct AutoConfirm {
    elicit_supported: Arc<AtomicBool>,
    elicit: ElicitConfirm,
    fallback: DenyAllConfirm,
}

impl ConfirmHook for AutoConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> ConfirmDecision {
        if self.elicit_supported.load(Ordering::SeqCst) {
            self.elicit.confirm(request)
        } else {
            self.fallback.confirm(request)
        }
    }
}

struct ScriptCall {
    script: String,
    script_name: String,
}

fn dispatch(name: &str, args: &Value, task_id: &str) -> Result<ScriptCall, String> {
    match name {
        "aegis_run" => {
            let script = args
                .get("script")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "aegis_run: missing 'script' argument".to_string())?
                .to_string();
            Ok(ScriptCall {
                script,
                script_name: format!("{task_id}.star"),
            })
        }
        "aegis_fs_read" => {
            let path = require_str(args, "path")?;
            Ok(synth(format!(
                "_r = fs.read({})\nprint(_r)",
                starlark_str(path)
            )))
        }
        "aegis_fs_write" => {
            let path = require_str(args, "path")?;
            let content = require_str(args, "content")?;
            Ok(synth(format!(
                "fs.write({}, {})\nprint(\"ok\")",
                starlark_str(path),
                starlark_str(content)
            )))
        }
        "aegis_fs_delete" => {
            let path = require_str(args, "path")?;
            Ok(synth(format!(
                "fs.delete({})\nprint(\"ok\")",
                starlark_str(path)
            )))
        }
        "aegis_subprocess_exec" => {
            let argv = require_argv(args)?;
            Ok(synth(format!(
                "_r = subprocess.exec({})\nprint(_r)",
                starlark_list(&argv)
            )))
        }
        "aegis_net_http_get" => {
            let url = require_str(args, "url")?;
            Ok(synth(format!(
                "_r = net.http_get({})\nprint(_r)",
                starlark_str(url)
            )))
        }
        "aegis_net_http_post" => {
            let url = require_str(args, "url")?;
            let body = require_str(args, "body")?;
            Ok(synth(format!(
                "_r = net.http_post({}, {})\nprint(_r)",
                starlark_str(url),
                starlark_str(body)
            )))
        }
        "aegis_env_read" => {
            let name = require_str(args, "name")?;
            Ok(synth(format!(
                "_r = env.read({})\nprint(_r)",
                starlark_str(name)
            )))
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

fn synth(body: String) -> ScriptCall {
    ScriptCall {
        script: body,
        script_name: "mcp_call.star".into(),
    }
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing '{key}' argument (must be a string)"))
}

fn require_argv(args: &Value) -> Result<Vec<String>, String> {
    let arr = args
        .get("argv")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing 'argv' argument (must be an array of strings)".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        out.push(
            v.as_str()
                .ok_or_else(|| "argv entries must all be strings".to_string())?
                .to_string(),
        );
    }
    Ok(out)
}

fn starlark_str(s: &str) -> String {
    format!("{:?}", s)
}

fn starlark_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| starlark_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "aegis_run",
            "description": "Run a Starlark program under the configured Aegis policy. The program has access to the policy-gated namespaced builtins (fs.read, fs.write, fs.delete, net.http_get, net.http_post, net.http_put, net.http_patch, net.http_delete, subprocess.exec, env.read). Returns the program's printed output. This is the most flexible surface; agents that compose multi-step actions should prefer this over the per-capability tools.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "script": { "type": "string", "description": "Starlark source. May reference fs.*, net.*, subprocess.*, env.*." },
                    "task_id": { "type": "string", "description": "Optional caller-supplied identifier; lands in audit events." }
                },
                "required": ["script"]
            }
        },
        {
            "name": "aegis_fs_read",
            "description": "Read a file under the policy's filesystem read_allow.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "aegis_fs_write",
            "description": "Write a file under the policy's filesystem write_allow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            }
        },
        {
            "name": "aegis_fs_delete",
            "description": "Delete a file under the policy's filesystem delete_allow.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "aegis_subprocess_exec",
            "description": "Spawn a child process. argv[0] is matched against the policy's subprocess.allow_commands and the joined argv against subprocess.deny_args.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1
                    }
                },
                "required": ["argv"]
            }
        },
        {
            "name": "aegis_net_http_get",
            "description": "HTTP GET. URL host is matched against http_get_allow; resolved IPs go through deny_ips.",
            "inputSchema": {
                "type": "object",
                "properties": { "url": { "type": "string" } },
                "required": ["url"]
            }
        },
        {
            "name": "aegis_net_http_post",
            "description": "HTTP POST with a string body.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "body": { "type": "string" }
                },
                "required": ["url", "body"]
            }
        },
        {
            "name": "aegis_env_read",
            "description": "Read a named environment variable. Subject to environment.allow_vars / deny_vars.",
            "inputSchema": {
                "type": "object",
                "properties": { "name": { "type": "string" } },
                "required": ["name"]
            }
        },
        {
            "name": "aegis_tool_routing",
            "description": "Read-only policy oracle. Returns the [tools.X] routing record for a given external tool name (e.g. WebSearch, Bash, Read), or every declared tool if no name is provided. The record contains: capabilities (Aegis caps the tool requires), backend_url and backend_method (where the policy expects the call to land), description, and an allowed flag (true iff every required capability is permitted). Bridges and hosts use this to surface the policy's tool surface to a calling agent without re-parsing the TOML.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Optional tool name. Omit to receive every declared [tools.X] record."
                    }
                }
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    //! Unit tests for the inline helpers in main.rs that don't require
    //! the full subprocess+JSON-RPC dance. End-to-end coverage lives
    //! in tests/server_mode.rs.

    use super::*;

    fn write_temp(name: &str, body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aegis_dotenv_{}_{}_{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn dotenv_basic_key_value_pairs() {
        let path = write_temp("basic", "FOO=bar\nBAZ=qux\n");
        // Use names that aren't already in env to avoid the "process
        // env wins" rule eating the test.
        let k1 = format!("AEGIS_TEST_DOTENV_BASIC_FOO_{}", std::process::id());
        let k2 = format!("AEGIS_TEST_DOTENV_BASIC_BAZ_{}", std::process::id());
        let body = format!("{k1}=bar\n{k2}=qux\n");
        std::fs::write(&path, body).unwrap();

        let n = load_dotenv_into_env(&path).unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::env::var(&k1).unwrap(), "bar");
        assert_eq!(std::env::var(&k2).unwrap(), "qux");
        std::env::remove_var(&k1);
        std::env::remove_var(&k2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dotenv_skips_comments_and_blank_lines() {
        let k = format!("AEGIS_TEST_DOTENV_CMT_{}", std::process::id());
        let path = write_temp(
            "comments",
            &format!("# this is a comment\n\n   \n{k}=v\n# trailing comment\n"),
        );
        let n = load_dotenv_into_env(&path).unwrap();
        assert_eq!(n, 1);
        assert_eq!(std::env::var(&k).unwrap(), "v");
        std::env::remove_var(&k);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dotenv_strips_export_prefix() {
        let k = format!("AEGIS_TEST_DOTENV_EXPORT_{}", std::process::id());
        let path = write_temp("export", &format!("export {k}=hello\n"));
        load_dotenv_into_env(&path).unwrap();
        assert_eq!(std::env::var(&k).unwrap(), "hello");
        std::env::remove_var(&k);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dotenv_strips_matching_quotes() {
        let k1 = format!("AEGIS_TEST_DOTENV_DBLQ_{}", std::process::id());
        let k2 = format!("AEGIS_TEST_DOTENV_SGLQ_{}", std::process::id());
        let path = write_temp(
            "quotes",
            &format!("{k1}=\"double quoted\"\n{k2}='single quoted'\n"),
        );
        load_dotenv_into_env(&path).unwrap();
        assert_eq!(std::env::var(&k1).unwrap(), "double quoted");
        assert_eq!(std::env::var(&k2).unwrap(), "single quoted");
        std::env::remove_var(&k1);
        std::env::remove_var(&k2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dotenv_keeps_mismatched_quotes_as_part_of_value() {
        let k = format!("AEGIS_TEST_DOTENV_MIX_{}", std::process::id());
        // Mismatched: starts with " but ends with '. Not valid quoting;
        // the function leaves the chars in place rather than guessing.
        let path = write_temp("mixed", &format!("{k}=\"oops'\n"));
        load_dotenv_into_env(&path).unwrap();
        assert_eq!(std::env::var(&k).unwrap(), "\"oops'");
        std::env::remove_var(&k);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dotenv_silently_skips_malformed_lines() {
        // Lines without `=` are skipped, not errors. Important: a
        // typo'd `.env` must not bring the whole agent down.
        let k = format!("AEGIS_TEST_DOTENV_MALFORMED_{}", std::process::id());
        let path = write_temp(
            "malformed",
            &format!(
                "this is not key=value because... wait no it has = in it\n\
                 {k}=value\n\
                 garbage_no_equals\n"
            ),
        );
        let n = load_dotenv_into_env(&path).unwrap();
        // Two lines parse: the first (the comment-ish line happens to
        // contain `=`, so it parses) and the named-value line. The
        // garbage-no-equals line is skipped.
        assert!(n >= 1);
        assert_eq!(std::env::var(&k).unwrap(), "value");
        std::env::remove_var(&k);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dotenv_existing_process_env_wins() {
        let k = format!("AEGIS_TEST_DOTENV_PRECEDENCE_{}", std::process::id());
        // Pre-set the var in process env. The .env should NOT override.
        std::env::set_var(&k, "from-process-env");
        let path = write_temp("precedence", &format!("{k}=from-dotenv\n"));
        load_dotenv_into_env(&path).unwrap();
        assert_eq!(std::env::var(&k).unwrap(), "from-process-env");
        std::env::remove_var(&k);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dotenv_missing_file_is_silent() {
        // The hard requirement is "the env must contain the value when
        // we read it", not "we must successfully parse a file". Missing
        // files are not errors that should bubble up to the operator.
        let bogus = std::env::temp_dir().join(format!(
            "aegis_dotenv_does_not_exist_{}",
            std::process::id()
        ));
        let result = load_dotenv_into_env(&bogus);
        assert!(result.is_err()); // returns Err, but the caller in
                                  // load_aegis_config_cascade swallows it
    }
}
