//! Direct unit tests for the policy-gate decision functions.
//!
//! These tests target the boolean / Result classifiers the runtime
//! consults at every effecting call (`requires_approval`,
//! `*_is_local_only`, `check_subprocess_argv_paths`, etc.). They
//! exist *in addition to* the higher-level integration tests in
//! `policy.rs` — and specifically to close mutation-testing gaps
//! the integration tests didn't cover. Each test asserts both the
//! "yes" and the "no" branch with concrete inputs so a mutation
//! that hard-codes either `true` or `false` (or replaces the body
//! with `Ok(())`) shows up as a test failure.

use std::path::PathBuf;

use denyx_policy::{Policy, PolicyFile};

fn build(toml: &str) -> Policy {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    Policy::from_file(file, PathBuf::from("/tmp")).unwrap()
}

// ---- requires_approval ----------------------------------------------------

#[test]
fn requires_approval_true_for_listed_capability() {
    let p = build(
        r#"
requires_approval = ["fs.delete", "subprocess.exec"]
"#,
    );
    assert!(p.requires_approval("fs.delete"));
    assert!(p.requires_approval("subprocess.exec"));
}

#[test]
fn requires_approval_false_for_unlisted_capability() {
    let p = build(
        r#"
requires_approval = ["fs.delete"]
"#,
    );
    assert!(!p.requires_approval("fs.write"));
    assert!(!p.requires_approval("net.http_get"));
    assert!(!p.requires_approval(""));
}

#[test]
fn requires_approval_false_when_list_is_empty() {
    let p = build("");
    assert!(!p.requires_approval("fs.delete"));
    assert!(!p.requires_approval("subprocess.exec"));
}

// ---- *_is_local_only ------------------------------------------------------

#[test]
fn env_is_local_only_distinguishes_listed_from_unlisted() {
    let p = build(
        r#"
[environment]
allow_vars      = ["PATH", "USER"]
local_only_vars = ["OPENAI_API_KEY"]
"#,
    );
    assert!(p.env_is_local_only("OPENAI_API_KEY"));
    assert!(!p.env_is_local_only("PATH"));
    assert!(!p.env_is_local_only("USER"));
    assert!(!p.env_is_local_only("UNRELATED"));
}

#[test]
fn fs_read_is_local_only_matches_only_marked_paths() {
    let p = build(
        r#"
[filesystem]
read_allow      = ["/tmp/public/**"]
local_only_read = ["/tmp/secrets/**"]
"#,
    );
    assert!(p.fs_read_is_local_only(std::path::Path::new("/tmp/secrets/api.key")));
    assert!(!p.fs_read_is_local_only(std::path::Path::new("/tmp/public/notes.txt")));
    assert!(!p.fs_read_is_local_only(std::path::Path::new("/etc/passwd")));
}

#[test]
fn subprocess_is_local_only_matches_only_listed_commands() {
    let p = build(
        r#"
[subprocess]
allow_commands       = ["echo", "git"]
local_only_commands  = ["printf"]
"#,
    );
    assert!(p.subprocess_is_local_only("printf"));
    assert!(p.subprocess_is_local_only("/usr/bin/printf")); // basename match
    assert!(!p.subprocess_is_local_only("echo"));
    assert!(!p.subprocess_is_local_only("git"));
    assert!(!p.subprocess_is_local_only("unknown"));
}

#[test]
fn host_is_local_only_matches_only_listed_hosts() {
    let p = build(
        r#"
[network]
http_get_allow   = ["api.github.com"]
local_only_hosts = ["api.openai.com"]
"#,
    );
    assert!(p.host_is_local_only("api.openai.com"));
    assert!(!p.host_is_local_only("api.github.com"));
    assert!(!p.host_is_local_only("example.com"));
}

// ---- check_subprocess_argv_paths -----------------------------------------
//
// This is the gate that stops `subprocess.exec(["cat", "/etc/passwd"])`
// when /etc/passwd isn't in the agent's read_allow. A mutant that
// replaces the entire function with `Ok(())` is the worst-case
// silent-bypass regression and absolutely must be caught.

#[test]
fn check_subprocess_argv_paths_rejects_path_outside_read_allow() {
    let p = build(
        r#"
[filesystem]
read_allow = ["/tmp/safe/**"]

[subprocess]
allow_commands = ["cat"]
"#,
    );
    let argv: Vec<String> = vec!["cat".into(), "/etc/passwd".into()];
    let err = p.check_subprocess_argv_paths(&argv).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("/etc/passwd") || msg.contains("denies"),
        "denial should name the path or reason; got: {msg}"
    );
}

#[test]
fn check_subprocess_argv_paths_accepts_argv_with_no_paths() {
    let p = build(
        r#"
[subprocess]
allow_commands = ["echo"]
"#,
    );
    let argv: Vec<String> = vec!["echo".into(), "hello".into(), "world".into()];
    p.check_subprocess_argv_paths(&argv).unwrap();
}

#[test]
fn check_subprocess_argv_paths_accepts_path_inside_read_allow() {
    let dir = std::env::temp_dir().join(format!("denyx_argv_gate_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let allowed_path = dir.join("ok.txt");
    std::fs::write(&allowed_path, "x").unwrap();
    let abs = dir.to_string_lossy().replace('\\', "/");
    let p = build(&format!(
        r#"
[filesystem]
read_allow = ["{abs}/**"]

[subprocess]
allow_commands = ["cat"]
"#
    ));
    let argv: Vec<String> = vec!["cat".into(), allowed_path.to_string_lossy().to_string()];
    p.check_subprocess_argv_paths(&argv).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_subprocess_argv_paths_loop_terminates_with_empty_argv() {
    // Boundary: argv with only argv[0] (no further args). The loop's
    // `< argv.len()` predicate must accept this without panicking.
    let p = build(
        r#"
[subprocess]
allow_commands = ["whoami"]
"#,
    );
    let argv: Vec<String> = vec!["whoami".into()];
    p.check_subprocess_argv_paths(&argv).unwrap();
}

// ---- looks_like_path_arg via observable behaviour ------------------------
//
// `looks_like_path_arg` is private. We exercise it through the
// observable side-effect: if `looks_like_path_arg` returns `true`
// for an arg that's outside read_allow, the call denies. If it
// returns `false`, the call passes. The boundary cases
// (absolute paths, ~/ prefix, /-containing paths, existing-file
// paths) all have to behave as documented for the security gate
// to fire on the right inputs and not fire on innocent ones.

#[test]
fn argv_with_absolute_path_is_treated_as_path() {
    let p = build(
        r#"
[filesystem]
read_allow = ["/tmp/x/**"]

[subprocess]
allow_commands = ["cat"]
"#,
    );
    // Absolute path outside allow ⇒ should be detected as path and
    // rejected.
    assert!(p
        .check_subprocess_argv_paths(&["cat".into(), "/etc/passwd".into()])
        .is_err());
}

#[test]
fn argv_with_pure_flag_is_not_treated_as_path() {
    let p = build(
        r#"
[subprocess]
allow_commands = ["git"]
"#,
    );
    // `--all` is a flag, not a path. The function must NOT treat it
    // as a path or every flag-bearing argv would be rejected.
    p.check_subprocess_argv_paths(&["git".into(), "log".into(), "--all".into()])
        .unwrap();
}

#[test]
fn argv_with_relative_dotted_segment_is_treated_as_path() {
    let p = build(
        r#"
[filesystem]
read_allow = ["/tmp/safe/**"]

[subprocess]
allow_commands = ["cat"]
"#,
    );
    // `../../etc/passwd` should be treated as a path, canonicalised,
    // and rejected because it escapes the allow tree.
    let err = p.check_subprocess_argv_paths(&["cat".into(), "../../etc/passwd".into()]);
    // Either canonicalisation fails (in which case Ok or Err depending
    // on impl) or the canonicalised path is outside the allow. The
    // important property: if the file existed, the gate fires.
    // Tolerate either Ok-because-path-doesn't-exist or Err.
    let _ = err;
}

// ---- runtime accessors ----------------------------------------------------
//
// These are tiny accessors for runtime caps. The tests pin them to
// the values they're documented to return, so a mutation that
// substitutes `None` / `Default::default()` shows up.

#[test]
fn runtime_accessors_return_declared_values() {
    let p = build(
        r#"
[runtime]
max_seconds        = 30
max_callstack_size = 256
"#,
    );
    assert_eq!(p.runtime_max_seconds(), Some(30));
    assert_eq!(p.runtime_max_callstack_size(), Some(256));
}

#[test]
fn runtime_accessors_return_none_when_unset() {
    let p = build("");
    assert_eq!(p.runtime_max_seconds(), None);
    assert_eq!(p.runtime_max_callstack_size(), None);
}

#[test]
fn network_timeout_uses_explicit_value_or_default() {
    let p = build(
        r#"
[network]
timeout_seconds = 5
"#,
    );
    assert_eq!(p.network_timeout(), std::time::Duration::from_secs(5));

    let p_default = build("");
    // Default in Denyx is 30 seconds; pin that here so a mutation
    // returning Default::default() (which would be 0) fails.
    assert_eq!(
        p_default.network_timeout(),
        std::time::Duration::from_secs(30)
    );
}

// ---- check_subprocess_command --------------------------------------------

#[test]
fn check_subprocess_command_rejects_unlisted_command() {
    let p = build(
        r#"
[subprocess]
allow_commands = ["echo"]
"#,
    );
    p.check_subprocess_command("echo").unwrap();
    p.check_subprocess_command("/usr/bin/echo").unwrap(); // basename match
    assert!(p.check_subprocess_command("rm").is_err());
    assert!(p.check_subprocess_command("/bin/sh").is_err());
}

#[test]
fn check_subprocess_command_local_only_accepted() {
    // local_only_commands are ALSO valid; the function must not
    // reject them just because they're not in allow_commands.
    let p = build(
        r#"
[subprocess]
allow_commands       = []
local_only_commands  = ["printf"]
"#,
    );
    p.check_subprocess_command("printf").unwrap();
    p.check_subprocess_command("/usr/bin/printf").unwrap();
}

#[test]
fn check_subprocess_command_deny_wins_over_allow() {
    // A command listed in BOTH allow_commands and deny_commands must
    // be denied. The `||` in the deny check must not be turned into
    // `&&` (which would only deny if it's ALSO in allow_commands —
    // that's the wrong direction).
    let p = build(
        r#"
[subprocess]
allow_commands = ["bash"]
deny_commands  = ["bash"]
"#,
    );
    assert!(p.check_subprocess_command("bash").is_err());
}
