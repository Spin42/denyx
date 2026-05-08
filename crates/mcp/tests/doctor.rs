//! Integration tests for `denyx-mcp doctor` — invoking the real
//! binary against tempdir-backed project layouts.
//!
//! Project diagnostics depend on filesystem state (presence /
//! absence of `denyx.toml`, `.mcp.json`, `.claude/settings.json`,
//! etc.), so we set up tempdirs for each scenario and assert on
//! stdout + exit code.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_denyx-mcp");

fn unique_tempdir(label: &str) -> PathBuf {
    let workspace_target = PathBuf::from(BIN)
        .parent()
        .expect("denyx-mcp parent")
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
        .expect("spawn denyx-mcp doctor")
}

#[test]
fn doctor_no_files_reports_missing_policy_as_info_and_exits_zero() {
    let tmp = unique_tempdir("no_files");
    let out = run_doctor(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "no files alone shouldn't fail. stdout:\n{stdout}"
    );
    assert!(stdout.contains("[INFO] denyx.toml: absent"));
    assert!(stdout.contains("secure-defaults baseline"));
    assert!(stdout.contains("Safe by design"));
    assert!(stdout.contains("Ready"));
}

#[test]
fn doctor_with_denyx_mcp_wired_and_active_lockdown_passes() {
    let tmp = unique_tempdir("standalone_ok");
    std::fs::write(
        tmp.join(".mcp.json"),
        r#"{"mcpServers":{"denyx":{"command":"denyx-mcp","args":["--policy","./denyx.toml"]}}}"#,
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
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(stdout.contains("[OK]   Claude Code"));
    assert!(stdout.contains("denyx-mcp wired"));
    assert!(stdout.contains("active"));
    assert!(stdout.contains("Ready"));
}

#[test]
fn doctor_warns_when_lockdown_is_absent() {
    let tmp = unique_tempdir("no_lockdown");
    std::fs::write(
        tmp.join(".mcp.json"),
        r#"{"mcpServers":{"denyx":{"command":"denyx-mcp","args":[]}}}"#,
    )
    .unwrap();
    // No .claude/settings.json → lockdown Absent.
    let out = run_doctor(&tmp);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout:\n{stdout}");
    assert!(stdout.contains("[WARN]"));
    assert!(stdout.contains("no deny list configured"));
    assert!(stdout.contains("model can bypass denyx-mcp"));
}

#[test]
fn doctor_treats_local_executor_shape_as_info_not_warning() {
    let tmp = unique_tempdir("local_executor");
    // Project wires denyx-local-mcp (the bridge). denyx-mcp runs
    // as its child. Doctor should report this as a valid setup,
    // not warn about it.
    std::fs::write(
        tmp.join(".mcp.json"),
        r#"{"mcpServers":{"local-executor":{"command":"denyx-local-mcp","args":["serve","--policy","./denyx.toml","--mcp-bin","denyx-mcp"]}}}"#,
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
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(stdout.contains("[INFO]"));
    assert!(stdout.contains("denyx-local-mcp wired"));
    assert!(stdout.contains("Local-executor shape"));
}

#[test]
fn doctor_defaults_project_path_to_cwd() {
    // Run with no --project-path. The cwd at spawn-time becomes the
    // project root.
    let tmp = unique_tempdir("cwd_default");
    let out = Command::new(BIN)
        .arg("doctor")
        .current_dir(&tmp)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should print the canonicalized cwd as the project root.
    assert!(
        stdout.contains("project:"),
        "should print project header. stdout:\n{stdout}"
    );
    // Empty tempdir → INFO about missing denyx.toml + Ready.
    assert!(stdout.contains("[INFO] denyx.toml: absent"));
    assert_eq!(out.status.code(), Some(0));
}
