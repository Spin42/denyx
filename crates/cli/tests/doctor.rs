//! Integration tests for `denyx doctor` — invoking the real binary
//! against tempdir-backed project layouts.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_denyx");

fn unique_tempdir(label: &str) -> PathBuf {
    let workspace_target = PathBuf::from(BIN)
        .parent()
        .expect("denyx parent")
        .to_path_buf();
    let base = workspace_target.join("doctor-tmp").join(format!(
        "{label}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn run_doctor(project_path: &std::path::Path) -> std::process::Output {
    Command::new(BIN)
        .args(["doctor", "--project-path", project_path.to_str().unwrap()])
        .output()
        .expect("spawn denyx doctor")
}

#[test]
fn doctor_no_files_is_info_level_and_exits_zero() {
    let tmp = unique_tempdir("denyx_no_files");
    let out = run_doctor(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(stdout.contains("[INFO] denyx.toml: absent"));
    assert!(stdout.contains("Safe by design"));
    assert!(stdout.contains("Ready"));
}

#[test]
fn doctor_detects_tool_url_not_in_network_allow_as_critical() {
    let tmp = unique_tempdir("denyx_tool_url_critical");
    // Policy declares a tool with backend_url whose host isn't in
    // any http_*_allow list.
    std::fs::write(
        tmp.join("denyx.toml"),
        r#"
inherits = "secure-defaults"

[network]
http_get_allow = ["api.github.com"]

[tools.SearchAPI]
backend_url = "https://search.example.com/api"
backend_method = "GET"
capabilities = ["net.http_get"]
"#,
    )
    .unwrap();
    let out = run_doctor(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "tool URL outside allow list should exit 2. stdout:\n{stdout}"
    );
    assert!(stdout.contains("[FAIL] tool URL vs network"));
    assert!(stdout.contains("search.example.com"));
    assert!(stdout.contains("NOT ready"));
}

#[test]
fn doctor_warns_when_requires_approval_is_bypassed_by_auto_allow() {
    let tmp = unique_tempdir("denyx_approval_bypass");
    std::fs::write(
        tmp.join("denyx.toml"),
        r#"
inherits = "secure-defaults"
requires_approval = ["fs.delete"]
"#,
    )
    .unwrap();
    std::fs::write(
        tmp.join(".mcp.json"),
        r#"{"mcpServers":{"denyx":{"command":"denyx-mcp","args":["--policy","./denyx.toml","--confirm-mode","auto-allow"]}}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(tmp.join(".claude")).unwrap();
    std::fs::write(
        tmp.join(".claude").join("settings.json"),
        r#"{"permissions":{"deny":["Bash","Edit","Write","Read","Glob","Grep","WebFetch","WebSearch"]}}"#,
    )
    .unwrap();
    let out = run_doctor(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
    assert!(stdout.contains("[WARN] requires_approval"));
    assert!(stdout.contains("auto-allow"));
    assert!(stdout.contains("Usable, with caveats"));
}

#[test]
fn doctor_detects_conflicting_policy_paths_across_host_configs() {
    let tmp = unique_tempdir("denyx_conflicting_paths");
    std::fs::write(tmp.join("denyx.toml"), r#"inherits = "secure-defaults""#).unwrap();
    std::fs::write(
        tmp.join(".mcp.json"),
        r#"{"mcpServers":{"denyx":{"command":"denyx-mcp","args":["--policy","./denyx.toml"]}}}"#,
    )
    .unwrap();
    std::fs::write(
        tmp.join("opencode.json"),
        r#"{"mcp":{"denyx":{"command":["denyx-mcp","--policy","./other.toml"]}}}"#,
    )
    .unwrap();
    let out = run_doctor(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
    assert!(stdout.contains("[WARN] conflicting policy paths"));
    assert!(stdout.contains("./denyx.toml"));
    assert!(stdout.contains("./other.toml"));
}

#[test]
fn doctor_clean_setup_exits_zero_with_ready_message() {
    let tmp = unique_tempdir("denyx_clean");
    // Minimal valid setup: policy, host-config wiring denyx-mcp,
    // active lockdown, .gitignore excluding .denyx/.
    std::fs::write(tmp.join("denyx.toml"), r#"inherits = "secure-defaults""#).unwrap();
    std::fs::write(
        tmp.join(".mcp.json"),
        r#"{"mcpServers":{"denyx":{"command":"denyx-mcp","args":["--policy","./denyx.toml","--confirm-mode","auto"]}}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(tmp.join(".claude")).unwrap();
    std::fs::write(
        tmp.join(".claude").join("settings.json"),
        r#"{"permissions":{"deny":["Bash","Edit","Write","Read","Glob","Grep","WebFetch","WebSearch"]}}"#,
    )
    .unwrap();
    std::fs::write(tmp.join(".gitignore"), ".denyx/\n").unwrap();
    let out = run_doctor(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "clean setup should exit 0. stdout:\n{stdout}"
    );
    assert!(stdout.contains("Ready: project setup looks consistent"));
    assert!(!stdout.contains("[FAIL]"));
    assert!(!stdout.contains("[WARN]"));
}
