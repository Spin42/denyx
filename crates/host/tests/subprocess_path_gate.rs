//! Tests for the subprocess argv path-policy gate. The headline
//! property: an allowed binary cannot reach a file via argv that the
//! script itself couldn't reach via `fs.read` / `fs.write`. Closes
//! the `subprocess.exec(["cat", "/etc/passwd"])` bypass.

use std::path::PathBuf;

use aegis_host::{AegisError, Runner};
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str, root: PathBuf) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, root).unwrap();
    Runner::new(policy)
}

#[test]
fn cat_etc_passwd_is_blocked_by_argv_gate() {
    // The classic bypass: cat is allowed, /etc/passwd is in fs deny.
    // Without the argv gate, `subprocess.exec(["cat","/etc/passwd"])`
    // would succeed because the OS opens the file, not Aegis.
    let toml = r#"
[filesystem]
read_allow = ["src/**"]
deny       = ["/etc/passwd"]

[environment]
allow_vars = ["PATH"]

[subprocess]
allow_commands = ["cat"]
"#;
    let runner = runner_for(toml, std::env::temp_dir());
    let src = r#"out = subprocess.exec(["cat", "/etc/passwd"])
print(out)
"#;
    let err = runner.run("t", src, "test.star").unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, AegisError::Policy(_)),
        "expected Policy violation, got: {err:?}"
    );
    assert!(
        msg.contains("/etc/passwd"),
        "error should name the offending path: {msg}"
    );
    assert!(
        msg.contains("[filesystem].deny") || msg.contains("deny"),
        "error should explain it matched a deny rule: {msg}"
    );
}

#[test]
fn cat_path_outside_any_allow_is_blocked() {
    // /var/log/syslog is NOT in deny but ALSO not in any allow list.
    // The script couldn't `fs.read` it; subprocess shouldn't reach
    // it either.
    let toml = r#"
[filesystem]
read_allow = ["src/**"]

[environment]
allow_vars = ["PATH"]

[subprocess]
allow_commands = ["cat"]
"#;
    let runner = runner_for(toml, std::env::temp_dir());
    let src = r#"subprocess.exec(["cat", "/var/log/syslog"])"#;
    let err = runner.run("t", src, "test.star").unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, AegisError::Policy(_)), "got: {err:?}");
    assert!(
        msg.contains("not in any [filesystem] allow list") || msg.contains("allow_list"),
        "error should explain the missing allow: {msg}"
    );
}

#[test]
fn tee_to_unwritable_path_is_blocked() {
    // Write side: tee /etc/somewhere should fail because /etc/** isn't
    // in write_allow.
    let toml = r#"
[filesystem]
write_allow = ["/tmp/aegis_path_gate_test/**"]

[environment]
allow_vars = ["PATH"]

[subprocess]
allow_commands = ["tee"]
"#;
    let runner = runner_for(toml, std::env::temp_dir());
    let src = r#"subprocess.exec(["tee", "/etc/aegis_should_fail"])"#;
    let err = runner.run("t", src, "test.star").unwrap_err();
    assert!(matches!(err, AegisError::Policy(_)));
}

#[test]
fn cp_with_one_unwritable_target_blocked() {
    // cp src/x /etc/y — the destination /etc/y isn't allowed.
    let toml = r#"
[filesystem]
read_allow  = ["src/**"]
write_allow = ["/tmp/aegis_path_gate_test/**"]

[environment]
allow_vars = ["PATH"]

[subprocess]
allow_commands = ["cp"]
"#;
    let runner = runner_for(toml, std::env::temp_dir());
    let src = r#"subprocess.exec(["cp", "src/main.py", "/etc/aegis_should_fail"])"#;
    let err = runner.run("t", src, "test.star").unwrap_err();
    assert!(matches!(err, AegisError::Policy(_)));
}

#[test]
fn cat_file_inside_allow_succeeds() {
    // Sanity: cat'ing a file in read_allow should still work.
    let dir = std::env::temp_dir().join(format!("aegis_path_gate_ok_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("hello.txt");
    std::fs::write(&target, "hello world").unwrap();

    let abs = dir.to_string_lossy().replace('\\', "/");
    let toml = format!(
        r#"
[filesystem]
read_allow = ["{abs}/**"]

[environment]
allow_vars = ["PATH"]

[subprocess]
allow_commands = ["cat"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    let src = format!(
        r#"out = subprocess.exec(["cat", "{}/hello.txt"])
print(out)
"#,
        abs
    );
    let outcome = runner.run("t", &src, "test.star").unwrap();
    assert!(
        outcome.printed.iter().any(|l| l.contains("hello world")),
        "expected the file content in output: {:?}",
        outcome.printed
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn flags_and_subcommands_are_not_treated_as_paths() {
    // git log / make build / echo hello — bare strings that aren't
    // paths, and flags. None of these should trip the path gate even
    // though the policy has narrow read_allow.
    let toml = r#"
[filesystem]
read_allow = ["src/**"]

[environment]
allow_vars = ["PATH"]

[subprocess]
allow_commands = ["echo"]
"#;
    let runner = runner_for(toml, std::env::temp_dir());
    // echo --foo bar baz — none of these should look like paths.
    let src = r#"subprocess.exec(["echo", "--foo", "bar", "baz", "-x"])"#;
    // We only need this to NOT fail at the gate. The actual exec
    // succeeds (echo just prints). If the gate falsely flagged any
    // arg, we'd get a Policy error.
    runner
        .run("t", src, "test.star")
        .expect("flags + bare-name args should pass the path gate");
}

#[test]
fn pure_policy_check_subprocess_argv_paths() {
    // Direct unit-style test of the new method, without spawning.
    let toml = r#"
[filesystem]
read_allow = ["src/**"]
deny       = ["/etc/passwd"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let argv = |a: &[&str]| -> Vec<String> { a.iter().map(|s| s.to_string()).collect() };

    // Absolute path matching deny: rejected.
    assert!(p
        .check_subprocess_argv_paths(&argv(&["cat", "/etc/passwd"]))
        .is_err());

    // Absolute path not in any allow: rejected.
    assert!(p
        .check_subprocess_argv_paths(&argv(&["cat", "/var/log/syslog"]))
        .is_err());

    // Relative path matching read_allow: ok.
    assert!(p
        .check_subprocess_argv_paths(&argv(&["cat", "src/main.py"]))
        .is_ok());

    // Flags: ok, not treated as paths.
    assert!(p
        .check_subprocess_argv_paths(&argv(&["echo", "--foo", "-x"]))
        .is_ok());

    // Bare names that don't exist at /work: ok.
    assert!(p
        .check_subprocess_argv_paths(&argv(&["git", "log"]))
        .is_ok());

    // Empty argv: ok.
    assert!(p.check_subprocess_argv_paths(&[]).is_ok());

    // argv0 itself never gets the path-gate (it's just the binary name).
    assert!(p
        .check_subprocess_argv_paths(&argv(&["/etc/passwd"]))
        .is_ok());
}
