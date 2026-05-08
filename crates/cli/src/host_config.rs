//! Generate/merge Claude Code and opencode host configs from a Denyx
//! policy. The output is the project-local lockdown layer: the MCP
//! server entry, the deny list on built-in effecting tools, and (opt-
//! in) the OS-level sandbox stanza Claude Code v2 added for native
//! filesystem + network isolation of Bash subprocesses.
//!
//! Why this lives here, not in the setup prompt: the prompt used to
//! ship JSON-shape instructions to the LLM and trust it to produce
//! valid configs. That broke across model revisions and was a vector
//! for hallucinated keys (`disableBypassPermissions` vs
//! `disableBypassPermissionsMode`, `mcp_servers` vs `mcpServers`,
//! etc). Moving the generator into Rust gets one tested implementation
//! and shrinks the prompt to a single CLI invocation.
//!
//! Pure-function design: every generator takes `(&Policy, &Opts)` and
//! returns a `serde_json::Value`. The merge functions take an existing
//! `Value` plus a generated `Value` and return the merged `Value`.
//! All I/O is in the calling layer (`main.rs`). This keeps the
//! generator easy to test and platform-agnostic.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use denyx_policy::Policy;

/// Which host's configs to emit.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Host {
    Claude,
    Opencode,
    Both,
}

/// How `denyx-mcp` is launched. Affects the `command`/`args` shape
/// the host config carries.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Platform {
    /// Linux. `denyx-mcp` runs directly as a host binary.
    Native,
    /// macOS via Lima VM. `limactl shell <vm> denyx-mcp ...`.
    Lima,
    /// Windows via WSL2. `wsl.exe -d <distro> -e denyx-mcp ...`.
    Wsl,
}

/// Existing-file merge strategy. Default is `Merge` because clobbering
/// surprises users who already had unrelated settings; `Replace` is
/// only useful when running on a clean tree or when an earlier merge
/// produced something the operator wants to discard.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Existing {
    Merge,
    Replace,
}

/// Sandbox emission policy.
///
/// `Auto` is the default: emit the sandbox stanza with
/// `failIfUnavailable: false`, so a host without bubblewrap installed
/// shows a warning and falls back rather than refusing to start.
/// `Required` flips `failIfUnavailable: true` for environments that
/// must enforce sandboxing as a security gate. `Off` omits the stanza
/// entirely; the policy gate via Denyx is still in effect.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Sandbox {
    Auto,
    Required,
    Off,
}

/// Inputs to every generator. The CLI layer parses flags into this
/// struct and threads it through.
///
/// Policy/audit can each be wired as either a local file or a remote
/// HTTP endpoint. When `policy_url` is `Some`, the generated MCP entry
/// uses `--policy-url <URL>` instead of `--policy <path>`; same for
/// `audit_url` vs `--audit-log <path>`. A local `policy_path` is still
/// required at host-config time because the OS-sandbox stanza
/// (`allowedDomains`/`allowWrite`) is derived from the policy's
/// `http_*_allow` and `write_allow` lists — the URL the runtime
/// fetches at startup may differ, but the sandbox layer needs *some*
/// snapshot to seed itself with.
#[derive(Debug, Clone)]
pub struct Opts {
    pub host: Host,
    pub platform: Platform,
    pub denyx_mcp_binary: String,
    pub policy_path: PathBuf,
    pub policy_url: Option<String>,
    pub audit_log_path: PathBuf,
    pub audit_url: Option<String>,
    pub lima_vm: String,
    pub wsl_distro: Option<String>,
    pub sandbox: Sandbox,
    /// True on Windows; adds `PowerShell` to the Claude Code deny list.
    pub windows: bool,
}

/// Built-in effecting tools we deny on Claude Code. The list is
/// "every tool that touches filesystem, network, or subprocess
/// directly without going through an MCP server." `Read` is in the
/// list because `Read(./.env)`-class deny rules apply only to the
/// built-in Read tool, not to Bash subprocesses; even if the model
/// only had `Read` enabled, it could still bypass the policy on any
/// path the deny rule didn't anticipate. Forcing all reads through
/// `denyx_fs_read` keeps the policy as the single source of truth.
const CLAUDE_DENY_TOOLS: &[&str] = &[
    "Bash",
    "Edit",
    "Write",
    "Read",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "Monitor",
    "NotebookEdit",
];

/// Built-in opencode tool keys (lowercase, matches opencode's config
/// convention). Each is set to `false` so the host doesn't expose
/// the tool at all.
const OPENCODE_DENY_TOOLS: &[&str] = &[
    "bash",
    "read",
    "write",
    "edit",
    "glob",
    "grep",
    "webfetch",
    "websearch",
];

/// Build the (`command`, `args`) pair for the MCP server entry given
/// the platform and the resolved binary location. The denyx-mcp args
/// (`--policy`/`--policy-url`, `--audit-log`/`--audit-url`,
/// `--confirm-mode auto`) are appended after any platform wrapper args.
pub fn build_command_and_args(opts: &Opts) -> (String, Vec<String>) {
    let mut denyx_args: Vec<String> = Vec::new();
    if let Some(url) = &opts.policy_url {
        denyx_args.push("--policy-url".to_string());
        denyx_args.push(url.clone());
    } else {
        denyx_args.push("--policy".to_string());
        denyx_args.push(opts.policy_path.display().to_string());
    }
    if let Some(url) = &opts.audit_url {
        denyx_args.push("--audit-url".to_string());
        denyx_args.push(url.clone());
    } else {
        denyx_args.push("--audit-log".to_string());
        denyx_args.push(opts.audit_log_path.display().to_string());
    }
    denyx_args.push("--confirm-mode".to_string());
    denyx_args.push("auto".to_string());
    match opts.platform {
        Platform::Native => (opts.denyx_mcp_binary.clone(), denyx_args),
        Platform::Lima => {
            let mut args = vec![
                "shell".to_string(),
                opts.lima_vm.clone(),
                opts.denyx_mcp_binary.clone(),
            ];
            args.extend(denyx_args);
            ("limactl".to_string(), args)
        }
        Platform::Wsl => {
            let distro = opts
                .wsl_distro
                .as_deref()
                .expect("wsl_distro is required when platform is Wsl");
            let mut args = vec![
                "-d".to_string(),
                distro.to_string(),
                "-e".to_string(),
                opts.denyx_mcp_binary.clone(),
            ];
            args.extend(denyx_args);
            ("wsl.exe".to_string(), args)
        }
    }
}

/// Generate the Claude Code MCP server entry as the body of a fresh
/// `.mcp.json`. Always wraps the denyx server under `mcpServers.denyx`.
pub fn claude_mcp(opts: &Opts) -> Value {
    let (cmd, args) = build_command_and_args(opts);
    json!({
        "mcpServers": {
            "denyx": {
                "command": cmd,
                "args": args,
            }
        }
    })
}

/// Generate the Claude Code settings file (deny list + bypass-mode
/// disable + optional sandbox stanza).
pub fn claude_settings(policy: &Policy, opts: &Opts) -> Value {
    let mut deny_list: Vec<String> = CLAUDE_DENY_TOOLS.iter().map(|s| s.to_string()).collect();
    if opts.windows {
        deny_list.push("PowerShell".to_string());
    }

    let mut settings = json!({
        "permissions": { "deny": deny_list },
        "disableBypassPermissionsMode": "disable",
        "disableAutoMode": "disable",
    });

    if matches!(opts.sandbox, Sandbox::Auto | Sandbox::Required) {
        settings["sandbox"] = sandbox_stanza(policy, opts.sandbox);
    }

    settings
}

/// Build the sandbox sub-object. `allowedDomains` is the union of
/// every `http_*_allow` host plus `local_only_hosts` (the script can
/// still reach those — local-only is about the *response* data, not
/// the outbound call). `allowWrite` is the subset of policy
/// `write_allow` paths that escape the project tree (absolute or
/// home-relative). `deniedDomains` matches the secure-defaults
/// preset's `deny_ips` for cloud-metadata + RFC1918 hostnames.
fn sandbox_stanza(policy: &Policy, mode: Sandbox) -> Value {
    let file = policy.file_snapshot();

    let mut allowed: BTreeSet<String> = BTreeSet::new();
    for s in file
        .network
        .http_get_allow
        .iter()
        .chain(&file.network.http_post_allow)
        .chain(&file.network.http_put_allow)
        .chain(&file.network.http_patch_allow)
        .chain(&file.network.http_delete_allow)
        .chain(&file.network.local_only_hosts)
    {
        allowed.insert(s.clone());
    }
    let allowed_domains: Vec<String> = allowed.into_iter().collect();

    // Cloud-metadata hostnames belong in deniedDomains; the
    // CIDR-level deny in the secure-defaults preset already
    // covers the IPs, but Claude Code's sandbox doesn't accept
    // CIDRs in `deniedDomains` — only literal hostnames.
    let denied_domains = vec![
        "169.254.169.254".to_string(),
        "metadata.google.internal".to_string(),
        "metadata.azure.com".to_string(),
    ];

    // Filter write_allow to absolute / home-relative entries only.
    // Project-relative paths like `src/**` are already covered by
    // Claude Code's default "cwd writable" behavior — no need to
    // duplicate. Strip a trailing `/**` glob since the sandbox
    // takes raw path prefixes, not glob patterns.
    let mut allow_write: BTreeSet<String> = BTreeSet::new();
    for raw in &file.filesystem.write_allow {
        if raw.starts_with('/') || raw.starts_with("~/") {
            let cleaned = raw
                .trim_end_matches("/**")
                .trim_end_matches("/*")
                .to_string();
            if !cleaned.is_empty() {
                allow_write.insert(cleaned);
            }
        }
    }
    let allow_write: Vec<String> = allow_write.into_iter().collect();

    json!({
        "enabled": true,
        "failIfUnavailable": matches!(mode, Sandbox::Required),
        "filesystem": { "allowWrite": allow_write },
        "network": {
            "allowedDomains": allowed_domains,
            "deniedDomains": denied_domains,
        }
    })
}

/// Generate the opencode config (tools deny + permission deny + MCP
/// entry). opencode collapses `command` + `args` into a single array,
/// so we build that here.
pub fn opencode_config(_policy: &Policy, opts: &Opts) -> Value {
    let (cmd, args) = build_command_and_args(opts);
    let mut command_array: Vec<String> = vec![cmd];
    command_array.extend(args);

    let mut tools_obj = Map::new();
    for tool in OPENCODE_DENY_TOOLS {
        tools_obj.insert((*tool).to_string(), json!(false));
    }

    json!({
        "$schema": "https://opencode.ai/config.json",
        "tools": tools_obj,
        "permission": {
            "*": "deny",
            "denyx*": "allow",
        },
        "mcp": {
            "denyx": {
                "type": "local",
                "command": command_array,
                "enabled": true,
            }
        }
    })
}

// ─────────────────────────── merge logic ───────────────────────────
//
// Every merge function takes (existing, generated) and returns the
// merged result. Existing keys outside our concern are preserved.
// Arrays we own (deny lists) are unioned + deduped. Scalars we own
// (e.g. disableBypassPermissionsMode) are set if absent; if present
// with a value that contradicts our intent (operator opted out),
// `merge` leaves them and emits a warning to stderr.
//
// `Replace` mode bypasses the merge entirely — see
// `final_value_for_write` in main.rs.

/// Merge a `.mcp.json`. The denyx entry is inserted/replaced;
/// other servers under `mcpServers` and other top-level keys
/// remain untouched.
pub fn merge_claude_mcp(existing: Value, generated: Value) -> Value {
    let mut out = if existing.is_object() {
        existing
    } else {
        json!({})
    };
    let denyx_entry = generated
        .pointer("/mcpServers/denyx")
        .cloned()
        .unwrap_or(json!({}));

    let obj = out.as_object_mut().expect("just normalized to object");
    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut();
    if let Some(servers) = servers {
        servers.insert("denyx".to_string(), denyx_entry);
    }
    out
}

/// Merge a Claude Code `settings.json`. Unions `permissions.deny` with
/// generated entries (dedupes); sets `disableBypassPermissionsMode` /
/// `disableAutoMode` if absent (warns to stderr if present with an
/// opt-out value); deep-merges the sandbox stanza if generated.
pub fn merge_claude_settings(existing: Value, generated: Value) -> Value {
    let mut out = if existing.is_object() {
        existing
    } else {
        json!({})
    };
    let obj = out.as_object_mut().expect("normalized");

    // Union deny list. Other keys under `permissions` (allow, ask,
    // additionalDirectories) stay as-is.
    if let Some(gen_deny) = generated
        .pointer("/permissions/deny")
        .and_then(|v| v.as_array())
    {
        let perms = obj
            .entry("permissions")
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(perms) = perms {
            let deny = perms.entry("deny").or_insert_with(|| json!([]));
            if let Some(arr) = deny.as_array_mut() {
                let mut set: BTreeSet<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                for v in gen_deny {
                    if let Some(s) = v.as_str() {
                        set.insert(s.to_string());
                    }
                }
                *deny = json!(set.into_iter().collect::<Vec<_>>());
            }
        }
    }

    // Bypass-mode disables. Set if absent. If present with a different
    // value, warn but don't override — the operator may have a reason.
    for key in ["disableBypassPermissionsMode", "disableAutoMode"] {
        let gen_val = generated
            .get(key)
            .cloned()
            .unwrap_or_else(|| json!("disable"));
        match obj.get(key) {
            None => {
                obj.insert(key.to_string(), gen_val);
            }
            Some(existing_val) if existing_val == &json!("disable") => {
                // Already set to the value we want.
            }
            Some(existing_val) => {
                eprintln!(
                    "denyx host-config: warning — {key} is set to {existing_val} \
                     in the existing settings.json; not overriding. Pass \
                     `--existing replace` to force the Denyx-recommended value."
                );
            }
        }
    }

    // Sandbox stanza: deep-merge if generated; otherwise leave alone.
    if let Some(gen_sb) = generated.get("sandbox") {
        let merged = match obj.remove("sandbox") {
            None => gen_sb.clone(),
            Some(existing_sb) => deep_merge_arrays(existing_sb, gen_sb.clone()),
        };
        obj.insert("sandbox".to_string(), merged);
    }

    out
}

/// Merge an opencode `opencode.json`. `tools.X = false` from the
/// generated side wins over `tools.X = true` in the existing file
/// (with a stderr warning); `false` or absent stays `false`.
/// `permission.*` map merges with existing-wins semantics for keys
/// the existing file already has. `mcp.denyx` is replaced.
pub fn merge_opencode(existing: Value, generated: Value) -> Value {
    let mut out = if existing.is_object() {
        existing
    } else {
        json!({})
    };
    let obj = out.as_object_mut().expect("normalized");

    if !obj.contains_key("$schema") {
        if let Some(s) = generated.get("$schema") {
            obj.insert("$schema".to_string(), s.clone());
        }
    }

    if let Some(gen_tools) = generated.get("tools").and_then(|v| v.as_object()) {
        let tools = obj
            .entry("tools")
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(tools) = tools {
            for (k, gen_v) in gen_tools {
                match tools.get(k) {
                    Some(v) if v == &json!(true) => {
                        eprintln!(
                            "denyx host-config: warning — opencode.json had \
                             tools.{k} = true; overriding to false."
                        );
                        tools.insert(k.clone(), gen_v.clone());
                    }
                    None => {
                        tools.insert(k.clone(), gen_v.clone());
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(gen_perm) = generated.get("permission").and_then(|v| v.as_object()) {
        let perm = obj
            .entry("permission")
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(perm) = perm {
            for (k, v) in gen_perm {
                perm.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }

    if let Some(gen_denyx) = generated.pointer("/mcp/denyx") {
        let mcp = obj
            .entry("mcp")
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(mcp) = mcp {
            mcp.insert("denyx".to_string(), gen_denyx.clone());
        }
    }

    out
}

/// Deep-merge two JSON values. Object keys are merged recursively;
/// arrays of strings are unioned (dedupe + sort); other scalars
/// keep the existing value (the user's). Used for the sandbox
/// stanza where the operator may have customized `allowWrite` /
/// `allowedDomains`.
fn deep_merge_arrays(existing: Value, generated: Value) -> Value {
    match (existing, generated) {
        (Value::Object(mut e), Value::Object(g)) => {
            for (k, gv) in g {
                let merged = match e.remove(&k) {
                    None => gv,
                    Some(ev) => deep_merge_arrays(ev, gv),
                };
                e.insert(k, merged);
            }
            Value::Object(e)
        }
        (Value::Array(e), Value::Array(g)) => {
            let mut set: BTreeSet<String> = BTreeSet::new();
            let mut non_strings: Vec<Value> = Vec::new();
            for v in e.into_iter().chain(g) {
                if let Some(s) = v.as_str() {
                    set.insert(s.to_string());
                } else {
                    non_strings.push(v);
                }
            }
            let mut out: Vec<Value> = set.into_iter().map(Value::String).collect();
            out.extend(non_strings);
            Value::Array(out)
        }
        (e, _g) => e,
    }
}

// ────────────────── audit-dir scaffolding ───────────────────────────

/// Create `<dir>/.denyx/` if missing, and ensure `.denyx/` is in
/// `<dir>/.gitignore`. Idempotent. Returns `(audit_dir_created,
/// gitignore_updated)`.
pub fn prepare_audit_dir(dir: &Path) -> std::io::Result<(bool, bool)> {
    let audit_dir = dir.join(".denyx");
    let audit_dir_created = if audit_dir.exists() {
        false
    } else {
        std::fs::create_dir_all(&audit_dir)?;
        true
    };

    let gitignore = dir.join(".gitignore");
    let gitignore_updated = if gitignore.exists() {
        let body = std::fs::read_to_string(&gitignore)?;
        if body.lines().any(|l| l.trim() == ".denyx/") {
            false
        } else {
            let mut new_body = body.clone();
            if !new_body.ends_with('\n') {
                new_body.push('\n');
            }
            new_body.push_str(".denyx/\n");
            std::fs::write(&gitignore, new_body)?;
            true
        }
    } else {
        std::fs::write(&gitignore, ".denyx/\n")?;
        true
    };

    Ok((audit_dir_created, gitignore_updated))
}

// ────────────────────────── unit tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use denyx_policy::{Policy, PolicyFile};
    use std::path::PathBuf;

    fn opts_native() -> Opts {
        Opts {
            host: Host::Both,
            platform: Platform::Native,
            denyx_mcp_binary: "denyx-mcp".to_string(),
            policy_path: PathBuf::from("./denyx.toml"),
            policy_url: None,
            audit_log_path: PathBuf::from("./.denyx/audit.jsonl"),
            audit_url: None,
            lima_vm: "denyx".to_string(),
            wsl_distro: None,
            sandbox: Sandbox::Auto,
            windows: false,
        }
    }

    fn opts_lima() -> Opts {
        Opts {
            platform: Platform::Lima,
            policy_path: PathBuf::from("/Users/me/proj/denyx.toml"),
            audit_log_path: PathBuf::from("/Users/me/proj/.denyx/audit.jsonl"),
            lima_vm: "denyx".to_string(),
            ..opts_native()
        }
    }

    fn opts_wsl() -> Opts {
        Opts {
            platform: Platform::Wsl,
            wsl_distro: Some("Ubuntu-22.04".to_string()),
            policy_path: PathBuf::from("/mnt/c/Users/me/proj/denyx.toml"),
            audit_log_path: PathBuf::from("/mnt/c/Users/me/proj/.denyx/audit.jsonl"),
            windows: true,
            ..opts_native()
        }
    }

    fn empty_policy() -> Policy {
        let raw = "inherits = \"secure-defaults\"\n";
        let file = PolicyFile::from_toml_str(raw)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        Policy::from_file(file, std::env::temp_dir()).unwrap()
    }

    fn policy_with_hosts() -> Policy {
        let raw = r#"
inherits = "secure-defaults"

[network]
http_get_allow  = ["api.github.com", "registry.npmjs.org"]
http_post_allow = ["api.openai.com"]
local_only_hosts = ["api.anthropic.com"]

[filesystem]
write_allow = ["src/**", "/tmp/**", "~/.cache/myproj/**"]
"#;
        let file = PolicyFile::from_toml_str(raw)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        Policy::from_file(file, std::env::temp_dir()).unwrap()
    }

    #[test]
    fn native_command_is_bare_binary() {
        let (cmd, args) = build_command_and_args(&opts_native());
        assert_eq!(cmd, "denyx-mcp");
        assert_eq!(
            args,
            vec![
                "--policy",
                "./denyx.toml",
                "--audit-log",
                "./.denyx/audit.jsonl",
                "--confirm-mode",
                "auto",
            ]
        );
    }

    #[test]
    fn lima_command_wraps_in_limactl_shell() {
        let (cmd, args) = build_command_and_args(&opts_lima());
        assert_eq!(cmd, "limactl");
        assert_eq!(args[0], "shell");
        assert_eq!(args[1], "denyx");
        assert_eq!(args[2], "denyx-mcp");
        assert!(args.contains(&"--policy".to_string()));
    }

    #[test]
    fn wsl_command_wraps_in_wsl_exe() {
        let (cmd, args) = build_command_and_args(&opts_wsl());
        assert_eq!(cmd, "wsl.exe");
        assert_eq!(args[0], "-d");
        assert_eq!(args[1], "Ubuntu-22.04");
        assert_eq!(args[2], "-e");
        assert_eq!(args[3], "denyx-mcp");
    }

    #[test]
    fn policy_url_replaces_policy_path_in_args() {
        let mut o = opts_native();
        o.policy_url = Some("https://denyx.example.com/policy".to_string());
        let (cmd, args) = build_command_and_args(&o);
        assert_eq!(cmd, "denyx-mcp");
        assert!(
            args.iter().any(|a| a == "--policy-url"),
            "expected --policy-url in args: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "--policy"),
            "should NOT carry --policy when --policy-url is set: {args:?}"
        );
        assert!(args.contains(&"https://denyx.example.com/policy".to_string()));
    }

    #[test]
    fn audit_url_replaces_audit_log_in_args() {
        let mut o = opts_native();
        o.audit_url = Some("https://denyx.example.com/audit".to_string());
        let (_cmd, args) = build_command_and_args(&o);
        assert!(
            args.iter().any(|a| a == "--audit-url"),
            "expected --audit-url in args: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "--audit-log"),
            "should NOT carry --audit-log when --audit-url is set: {args:?}"
        );
        assert!(args.contains(&"https://denyx.example.com/audit".to_string()));
    }

    #[test]
    fn policy_and_audit_urls_can_be_set_independently() {
        let mut o = opts_native();
        o.policy_url = Some("https://srv/policy".to_string());
        // audit_url left as None — local audit + remote policy
        let (_cmd, args) = build_command_and_args(&o);
        assert!(args.iter().any(|a| a == "--policy-url"));
        assert!(args.iter().any(|a| a == "--audit-log"));
        assert!(!args.iter().any(|a| a == "--policy"));
        assert!(!args.iter().any(|a| a == "--audit-url"));
    }

    #[test]
    fn url_mode_works_through_lima_wrapper() {
        let mut o = opts_lima();
        o.policy_url = Some("https://srv/policy".to_string());
        o.audit_url = Some("https://srv/audit".to_string());
        let (cmd, args) = build_command_and_args(&o);
        assert_eq!(cmd, "limactl");
        // limactl shell <vm> denyx-mcp ... — denyx-mcp is at index 2,
        // then the URL flags.
        assert_eq!(args[0], "shell");
        assert_eq!(args[1], "denyx");
        assert_eq!(args[2], "denyx-mcp");
        assert!(args.iter().any(|a| a == "--policy-url"));
        assert!(args.iter().any(|a| a == "--audit-url"));
    }

    #[test]
    fn claude_settings_has_default_deny_list() {
        let s = claude_settings(&empty_policy(), &opts_native());
        let deny = s
            .pointer("/permissions/deny")
            .and_then(|v| v.as_array())
            .expect("deny array");
        let names: Vec<&str> = deny.iter().filter_map(|v| v.as_str()).collect();
        for tool in CLAUDE_DENY_TOOLS {
            assert!(names.contains(tool), "missing {tool}");
        }
        assert!(
            !names.contains(&"PowerShell"),
            "non-windows should not include PowerShell"
        );
    }

    #[test]
    fn claude_settings_includes_powershell_on_windows() {
        let mut o = opts_native();
        o.windows = true;
        let s = claude_settings(&empty_policy(), &o);
        let deny = s.pointer("/permissions/deny").unwrap();
        assert!(deny
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &json!("PowerShell")));
    }

    #[test]
    fn claude_settings_disables_bypass_and_auto_modes() {
        let s = claude_settings(&empty_policy(), &opts_native());
        assert_eq!(s["disableBypassPermissionsMode"], json!("disable"));
        assert_eq!(s["disableAutoMode"], json!("disable"));
    }

    #[test]
    fn sandbox_off_omits_stanza() {
        let mut o = opts_native();
        o.sandbox = Sandbox::Off;
        let s = claude_settings(&empty_policy(), &o);
        assert!(s.get("sandbox").is_none());
    }

    #[test]
    fn sandbox_required_sets_fail_if_unavailable_true() {
        let mut o = opts_native();
        o.sandbox = Sandbox::Required;
        let s = claude_settings(&empty_policy(), &o);
        assert_eq!(s["sandbox"]["failIfUnavailable"], json!(true));
    }

    #[test]
    fn sandbox_auto_sets_fail_if_unavailable_false() {
        let s = claude_settings(&empty_policy(), &opts_native());
        assert_eq!(s["sandbox"]["failIfUnavailable"], json!(false));
    }

    #[test]
    fn sandbox_allowed_domains_unions_all_http_verbs_and_local_only() {
        let s = claude_settings(&policy_with_hosts(), &opts_native());
        let allowed = s["sandbox"]["network"]["allowedDomains"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"api.github.com"));
        assert!(names.contains(&"registry.npmjs.org"));
        assert!(names.contains(&"api.openai.com"));
        assert!(names.contains(&"api.anthropic.com"));
    }

    #[test]
    fn sandbox_allow_write_includes_absolute_and_home_paths_only() {
        let s = claude_settings(&policy_with_hosts(), &opts_native());
        let allow_write = s["sandbox"]["filesystem"]["allowWrite"].as_array().unwrap();
        let paths: Vec<&str> = allow_write.iter().filter_map(|v| v.as_str()).collect();
        assert!(paths.contains(&"/tmp"));
        assert!(paths.contains(&"~/.cache/myproj"));
        assert!(
            !paths.iter().any(|p| p.starts_with("src")),
            "project-relative `src/**` should not be in allowWrite (covered by cwd default)"
        );
    }

    #[test]
    fn sandbox_denied_domains_includes_metadata_hosts() {
        let s = claude_settings(&empty_policy(), &opts_native());
        let denied = s["sandbox"]["network"]["deniedDomains"].as_array().unwrap();
        let names: Vec<&str> = denied.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"169.254.169.254"));
    }

    #[test]
    fn opencode_collapses_command_and_args_into_array() {
        let c = opencode_config(&empty_policy(), &opts_native());
        let cmd = c
            .pointer("/mcp/denyx/command")
            .and_then(|v| v.as_array())
            .expect("command array");
        assert_eq!(cmd[0], json!("denyx-mcp"));
        assert_eq!(cmd[1], json!("--policy"));
    }

    #[test]
    fn opencode_disables_all_builtin_tools() {
        let c = opencode_config(&empty_policy(), &opts_native());
        let tools = c.get("tools").and_then(|v| v.as_object()).unwrap();
        for tool in OPENCODE_DENY_TOOLS {
            assert_eq!(tools[*tool], json!(false), "{tool} should be false");
        }
    }

    #[test]
    fn opencode_includes_permission_wildcard_block() {
        let c = opencode_config(&empty_policy(), &opts_native());
        assert_eq!(c["permission"]["*"], json!("deny"));
        assert_eq!(c["permission"]["denyx*"], json!("allow"));
    }

    #[test]
    fn merge_claude_mcp_preserves_other_servers() {
        let existing = json!({
            "mcpServers": {
                "github": { "command": "github-mcp", "args": [] }
            },
            "unrelatedKey": "preserved"
        });
        let generated = claude_mcp(&opts_native());
        let merged = merge_claude_mcp(existing, generated);
        assert_eq!(merged["unrelatedKey"], json!("preserved"));
        assert!(merged["mcpServers"]["github"].is_object());
        assert!(merged["mcpServers"]["denyx"].is_object());
    }

    #[test]
    fn merge_claude_mcp_replaces_prior_denyx_entry() {
        let existing = json!({
            "mcpServers": {
                "denyx": { "command": "old-denyx-mcp", "args": [] }
            }
        });
        let generated = claude_mcp(&opts_native());
        let merged = merge_claude_mcp(existing, generated);
        assert_eq!(merged["mcpServers"]["denyx"]["command"], json!("denyx-mcp"));
    }

    #[test]
    fn merge_claude_settings_unions_deny_list_no_dupes() {
        let existing = json!({
            "permissions": {
                "deny": ["Bash", "CustomTool"],
                "allow": ["Edit(./src/**)"]
            }
        });
        let generated = claude_settings(&empty_policy(), &opts_native());
        let merged = merge_claude_settings(existing, generated);
        let deny = merged["permissions"]["deny"].as_array().unwrap();
        let names: Vec<&str> = deny.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"Bash"));
        assert!(names.contains(&"CustomTool"));
        assert!(names.contains(&"Edit"));
        let count_bash = names.iter().filter(|n| **n == "Bash").count();
        assert_eq!(count_bash, 1, "Bash should not appear twice");
        // Allow list under permissions is preserved.
        assert_eq!(
            merged["permissions"]["allow"],
            json!(["Edit(./src/**)"]),
            "unrelated permission keys preserved"
        );
    }

    #[test]
    fn merge_claude_settings_preserves_unrelated_top_level_keys() {
        let existing = json!({
            "model": "claude-opus-4-7",
            "outputStyle": "concise"
        });
        let generated = claude_settings(&empty_policy(), &opts_native());
        let merged = merge_claude_settings(existing, generated);
        assert_eq!(merged["model"], json!("claude-opus-4-7"));
        assert_eq!(merged["outputStyle"], json!("concise"));
    }

    #[test]
    fn merge_claude_settings_does_not_override_explicit_bypass_opt_out() {
        let existing = json!({ "disableBypassPermissionsMode": false });
        let generated = claude_settings(&empty_policy(), &opts_native());
        let merged = merge_claude_settings(existing, generated);
        assert_eq!(
            merged["disableBypassPermissionsMode"],
            json!(false),
            "operator opt-out is not silently flipped"
        );
    }

    #[test]
    fn merge_claude_settings_deep_merges_sandbox() {
        let existing = json!({
            "sandbox": {
                "filesystem": { "allowWrite": ["/opt/company-tools"] }
            }
        });
        let generated = claude_settings(&policy_with_hosts(), &opts_native());
        let merged = merge_claude_settings(existing, generated);
        let allow_write = merged["sandbox"]["filesystem"]["allowWrite"]
            .as_array()
            .unwrap();
        let paths: Vec<&str> = allow_write.iter().filter_map(|v| v.as_str()).collect();
        assert!(paths.contains(&"/opt/company-tools"));
        assert!(paths.contains(&"/tmp"));
        assert!(paths.contains(&"~/.cache/myproj"));
    }

    #[test]
    fn merge_opencode_overrides_true_to_false_with_warning() {
        let existing = json!({
            "tools": { "bash": true, "myCustom": "keep-me" }
        });
        let generated = opencode_config(&empty_policy(), &opts_native());
        let merged = merge_opencode(existing, generated);
        assert_eq!(merged["tools"]["bash"], json!(false));
        assert_eq!(merged["tools"]["myCustom"], json!("keep-me"));
    }

    #[test]
    fn merge_opencode_replaces_denyx_mcp_entry() {
        let existing = json!({
            "mcp": {
                "denyx": { "type": "local", "command": ["old"], "enabled": true }
            }
        });
        let generated = opencode_config(&empty_policy(), &opts_native());
        let merged = merge_opencode(existing, generated);
        let cmd = merged["mcp"]["denyx"]["command"].as_array().unwrap();
        assert_eq!(cmd[0], json!("denyx-mcp"));
    }
}
