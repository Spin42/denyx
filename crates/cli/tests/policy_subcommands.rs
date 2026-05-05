//! Integration tests for `aegis policy validate` and `aegis policy show`.
//!
//! Both spawn the compiled `aegis` binary with a temp policy file and
//! assert on exit code + stdout/stderr.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_aegis");

fn write_policy(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aegis_policy_subcmd_{}_{}_{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("aegis.toml");
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn validate_succeeds_on_a_well_formed_policy() {
    let body = r#"
inherits = "secure-defaults"

[filesystem]
read_allow = ["src/**"]
"#;
    let path = write_policy("validate_ok", body);
    let out = Command::new(BIN)
        .args(["policy", "validate"])
        .arg(&path)
        .output()
        .expect("spawn aegis");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK:"), "{stdout}");
    assert!(stdout.contains("1 capability"), "expected derivation count: {stdout}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn validate_fails_on_self_writable_policy() {
    // Policy lives at <dir>/aegis.toml with write_allow = ["**"];
    // since relative patterns anchor at the policy's parent dir,
    // ** matches the policy file itself — guard refuses.
    let body = r#"
[filesystem]
write_allow = ["**"]
"#;
    let path = write_policy("validate_self_writable", body);
    let out = Command::new(BIN)
        .args(["policy", "validate"])
        .arg(&path)
        .output()
        .expect("spawn aegis");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to load"),
        "expected SelfWritable error in stderr: {stderr}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn validate_fails_on_malformed_toml() {
    let path = write_policy("validate_bad", "[broken[][}}}");
    let out = Command::new(BIN)
        .args(["policy", "validate"])
        .arg(&path)
        .output()
        .expect("spawn aegis");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("validation failed"), "{stderr}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn show_lists_effective_capabilities_and_populated_sections() {
    let body = r#"
inherits = "secure-defaults"

[filesystem]
read_allow  = ["src/**"]
write_allow = ["build/**"]

[subprocess]
allow_commands = ["git", "make"]

[subprocess.deny_args]
git = ["push --force"]

[tools.WebSearch]
capabilities = ["net.http_get"]
backend_url  = "https://api.duckduckgo.com/?format=json&q="

confirm_per_call = ["fs.delete"]

[runtime]
max_seconds = 30
"#;
    let path = write_policy("show", body);
    let out = Command::new(BIN)
        .args(["policy", "show"])
        .arg(&path)
        .output()
        .expect("spawn aegis");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Effective capabilities derived from populated sections.
    assert!(stdout.contains("[capabilities]"));
    assert!(stdout.contains("- fs.read"));
    assert!(stdout.contains("- fs.write"));
    assert!(stdout.contains("- subprocess.exec"));
    // fs.delete is in `confirm_per_call` for the test but is NOT a
    // derived capability (no delete_allow). Walk the lines to assert
    // it doesn't appear in the [capabilities] block specifically.
    let cap_block: String = stdout
        .split("\n\n")
        .find(|chunk| chunk.starts_with("[capabilities]"))
        .unwrap_or_default()
        .to_string();
    assert!(
        !cap_block.contains("fs.delete"),
        "[capabilities] block should not list fs.delete: {cap_block}"
    );

    // Sections rendered.
    assert!(stdout.contains("[filesystem].read_allow"));
    assert!(stdout.contains("- src/**"));
    assert!(stdout.contains("[subprocess].allow_commands"));
    assert!(stdout.contains("- git"));
    assert!(stdout.contains("[subprocess.deny_args]"));
    assert!(stdout.contains("[tools]"));
    assert!(stdout.contains("WebSearch"));
    assert!(stdout.contains("api.duckduckgo.com"));
    assert!(stdout.contains("[confirm_per_call]"));
    assert!(stdout.contains("[runtime]"));
    assert!(stdout.contains("max_seconds: 30"));

    // Inherited deny rules from secure-defaults are surfaced too.
    assert!(stdout.contains("/etc/passwd"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn show_on_nonexistent_file_fails_cleanly() {
    let out = Command::new(BIN)
        .args(["policy", "show", "/nonexistent/aegis.toml"])
        .output()
        .expect("spawn aegis");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("load policy"), "{stderr}");
}

#[test]
fn show_handles_minimal_policy_without_panic() {
    // A policy with only `inherits` — every section is the
    // preset's default. Should still render without crashing.
    let body = r#"
inherits = "secure-defaults"
"#;
    let path = write_policy("show_minimal", body);
    let out = Command::new(BIN)
        .args(["policy", "show"])
        .arg(&path)
        .output()
        .expect("spawn aegis");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // No effective capabilities (preset has only deny lists).
    assert!(stdout.contains("(none"), "expected empty-cap notice: {stdout}");
    let _ = std::fs::remove_file(&path);
}
