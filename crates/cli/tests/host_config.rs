//! Integration tests for `denyx host-config`.
//!
//! Spawns the compiled `denyx` binary in a tempdir so the writes the
//! command performs (`./.mcp.json`, `./.claude/settings.json`,
//! `./opencode.json`, `./.denyx/`, `.gitignore`) are real, then asserts
//! on the on-disk results. Covers:
//!   - greenfield write (no pre-existing files)
//!   - merge with a pre-existing settings.json that has unrelated keys
//!   - --existing replace clobbers
//!   - --dry-run prints to stdout, writes nothing
//!   - --platform wsl without --wsl-distro fails fast

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_denyx");

fn write_minimal_policy(dir: &std::path::Path) -> PathBuf {
    let body = r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["api.github.com"]

[filesystem]
write_allow = ["src/**", "/opt/myproj/**", "~/.cache/myproj/**"]
"#;
    let path = dir.join("denyx.toml");
    std::fs::write(&path, body).expect("write policy");
    path
}

fn run(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
    Command::new(BIN)
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn denyx")
}

fn read_json(path: &std::path::Path) -> serde_json::Value {
    let body = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&body).expect("json")
}

#[test]
fn greenfield_writes_all_three_files() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "both",
            "--platform",
            "native",
            "--sandbox",
            "auto",
        ],
        &tmp,
    );
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let mcp = read_json(&tmp.join(".mcp.json"));
    assert_eq!(mcp["mcpServers"]["denyx"]["command"], "denyx-mcp");
    assert!(mcp["mcpServers"]["denyx"]["args"].is_array());

    let settings = read_json(&tmp.join(".claude").join("settings.json"));
    assert!(settings["permissions"]["deny"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "Bash"));
    assert_eq!(settings["disableBypassPermissionsMode"], "disable");
    assert!(settings["sandbox"]["enabled"] == true);

    let oc = read_json(&tmp.join("opencode.json"));
    assert_eq!(oc["tools"]["bash"], false);
    assert!(oc["mcp"]["denyx"]["command"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "denyx-mcp"));

    assert!(&tmp.join(".denyx").is_dir());
    let gi = std::fs::read_to_string(tmp.join(".gitignore")).unwrap();
    assert!(gi.contains(".denyx/"));
}

#[test]
fn merge_preserves_unrelated_keys_in_settings_json() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    // Pre-create a settings.json with the operator's own keys.
    let claude_dir = tmp.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let pre = serde_json::json!({
        "model": "claude-opus-4-7",
        "outputStyle": "concise",
        "permissions": { "allow": ["Edit(./src/**)"] }
    });
    std::fs::write(
        claude_dir.join("settings.json"),
        serde_json::to_string_pretty(&pre).unwrap(),
    )
    .unwrap();

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "claude",
            "--sandbox",
            "off",
        ],
        &tmp,
    );
    assert!(out.status.success());

    let merged = read_json(&claude_dir.join("settings.json"));
    assert_eq!(merged["model"], "claude-opus-4-7");
    assert_eq!(merged["outputStyle"], "concise");
    assert_eq!(
        merged["permissions"]["allow"],
        serde_json::json!(["Edit(./src/**)"])
    );
    assert!(merged["permissions"]["deny"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "Bash"));
}

#[test]
fn existing_replace_clobbers_unrelated_keys() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let claude_dir = tmp.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        r#"{"model":"keep-me-or-not"}"#,
    )
    .unwrap();

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "claude",
            "--existing",
            "replace",
            "--sandbox",
            "off",
        ],
        &tmp,
    );
    assert!(out.status.success());

    let after = read_json(&claude_dir.join("settings.json"));
    assert!(
        after.get("model").is_none(),
        "replace should drop unrelated keys"
    );
    assert!(after["permissions"]["deny"].is_array());
}

#[test]
fn dry_run_writes_nothing_to_disk() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "claude",
            "--dry-run",
        ],
        &tmp,
    );
    assert!(out.status.success());
    assert!(!&tmp.join(".mcp.json").exists());
    assert!(!&tmp.join(".claude").exists());
    assert!(
        !&tmp.join(".denyx").exists(),
        "dry-run should not create the audit dir"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(".mcp.json"));
    assert!(stdout.contains("settings.json"));
}

#[test]
fn wsl_platform_requires_wsl_distro() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--platform",
            "wsl",
        ],
        &tmp,
    );
    assert!(!out.status.success(), "missing --wsl-distro should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("wsl-distro"), "stderr was: {stderr}");
}

#[test]
fn lima_platform_emits_limactl_command() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "claude",
            "--platform",
            "lima",
            "--lima-vm",
            "denyx",
            "--sandbox",
            "off",
        ],
        &tmp,
    );
    assert!(out.status.success());

    let mcp = read_json(&tmp.join(".mcp.json"));
    assert_eq!(mcp["mcpServers"]["denyx"]["command"], "limactl");
    let args = mcp["mcpServers"]["denyx"]["args"].as_array().unwrap();
    assert_eq!(args[0], "shell");
    assert_eq!(args[1], "denyx");
    assert_eq!(args[2], "denyx-mcp");
}

#[test]
fn sandbox_required_sets_fail_if_unavailable_true() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "claude",
            "--sandbox",
            "required",
        ],
        &tmp,
    );
    assert!(out.status.success());
    let s = read_json(&tmp.join(".claude").join("settings.json"));
    assert_eq!(s["sandbox"]["failIfUnavailable"], true);
}

#[test]
fn policy_url_bakes_url_into_mcp_args() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "both",
            "--policy-url",
            "https://denyx.example.com/policy",
            "--audit-url",
            "https://denyx.example.com/audit",
            "--sandbox",
            "off",
        ],
        &tmp,
    );
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // Claude .mcp.json should carry --policy-url + --audit-url, not --policy / --audit-log.
    let mcp = read_json(&tmp.join(".mcp.json"));
    let args: Vec<&str> = mcp["mcpServers"]["denyx"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        args.contains(&"--policy-url"),
        "expected --policy-url, got {args:?}"
    );
    assert!(
        args.contains(&"--audit-url"),
        "expected --audit-url, got {args:?}"
    );
    assert!(
        !args.contains(&"--policy"),
        "should NOT include --policy in URL mode"
    );
    assert!(
        !args.contains(&"--audit-log"),
        "should NOT include --audit-log in URL mode"
    );
    assert!(args.contains(&"https://denyx.example.com/policy"));
    assert!(args.contains(&"https://denyx.example.com/audit"));

    // opencode.json command array carries the same.
    let oc = read_json(&tmp.join("opencode.json"));
    let oc_cmd: Vec<&str> = oc["mcp"]["denyx"]["command"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(oc_cmd.contains(&"--policy-url"));
    assert!(oc_cmd.contains(&"--audit-url"));

    // The team-mode warning should land on stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("team mode"),
        "expected team-mode warning, stderr was: {stderr}"
    );
}

#[test]
fn audit_url_alone_keeps_local_policy() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "claude",
            "--audit-url",
            "https://denyx.example.com/audit",
            "--sandbox",
            "off",
        ],
        &tmp,
    );
    assert!(out.status.success());

    let mcp = read_json(&tmp.join(".mcp.json"));
    let args: Vec<&str> = mcp["mcpServers"]["denyx"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(args.contains(&"--policy"), "policy stays local");
    assert!(args.contains(&"--audit-url"), "audit goes remote");
    assert!(!args.contains(&"--audit-log"));
    assert!(!args.contains(&"--policy-url"));
}

#[test]
fn no_mcp_writes_lockdown_only() {
    let tmp = tempdir();
    let policy = write_minimal_policy(&tmp);

    let out = run(
        &[
            "host-config",
            "--policy",
            policy.to_str().unwrap(),
            "--host",
            "both",
            "--no-mcp",
            "--sandbox",
            "off",
        ],
        &tmp,
    );
    assert!(out.status.success());

    // .mcp.json must NOT be created
    assert!(
        !tmp.join(".mcp.json").exists(),
        "--no-mcp should not write .mcp.json"
    );
    // .claude/settings.json IS created (lockdown layer)
    let s = read_json(&tmp.join(".claude").join("settings.json"));
    assert!(s["permissions"]["deny"].is_array());
    // opencode.json is created but without mcp.denyx
    let oc = read_json(&tmp.join("opencode.json"));
    assert!(oc.get("mcp").is_none(), "--no-mcp should drop mcp block");
    assert_eq!(oc["tools"]["bash"], false);
    assert_eq!(oc["permission"]["*"], "deny");
}

fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "denyx_host_config_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}
