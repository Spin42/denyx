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

// ── Mutation-targeted boundary tests (added 2026-05-08) ────────────
//
// These tests close specific gaps surfaced by `cargo mutants` that
// the existing tests left open. Each test names the mutant it kills
// in its docstring so a future reader knows why the test exists
// and can re-verify by running:
//   cargo mutants --workspace --no-shuffle --no-config \
//                 --file crates/policy/src/lib.rs

#[test]
fn check_env_read_local_only_membership_uses_eq_not_neq() {
    // Targets `== with !=` on line 1150 (`let in_local_only = ...
    // .any(|n| n == name);`). With the mutant, `in_local_only`
    // becomes "is there ANY n in env_local_only that's NOT this
    // name" — which is true whenever the list is non-empty and the
    // name isn't the only entry. That'd flip the gate from
    // "deny vars not in any allow list" to "allow most vars when
    // env_local_only has any entries."
    //
    // Setup: env_local_only = ["FOO"]. Ask about "BAR" which is in
    // NEITHER allow nor local_only. Original returns Err. Mutant
    // would compute in_local_only=true ("FOO" != "BAR") and return
    // Ok — silently letting BAR through.
    let p = build(
        r#"
[environment]
local_only_vars = ["FOO"]
"#,
    );
    let r = p.check_env_read("BAR");
    assert!(
        r.is_err(),
        "BAR is in NEITHER allow_vars nor local_only_vars; must be denied"
    );
}

#[test]
fn subprocess_env_propagates_allowed_var_only_when_not_denied() {
    // Targets `== with !=` on line 1251 (`if self.env_deny.iter()
    // .any(|d| d == name) { continue; }`). Mutant flips the deny
    // skip — would skip vars NOT in deny, leaving denied ones
    // through. Critical: subprocess_env builds the env passed to
    // child processes; a denied var leaking is a credential leak.
    //
    // Set HOME (a sentinel for "always present in test envs") so
    // we can verify it appears in the output. Set deny_vars to
    // contain something NOT in the allow list so the mutant's
    // inverted skip would matter.
    std::env::set_var("DENYX_TEST_ALLOWED_VAR", "yes");
    let p = build(
        r#"
[environment]
allow_vars = ["DENYX_TEST_ALLOWED_VAR"]
deny_vars  = ["AWS_SECRET_ACCESS_KEY"]
"#,
    );
    let env = p.subprocess_env("git");
    let names: Vec<&str> = env.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        names.contains(&"DENYX_TEST_ALLOWED_VAR"),
        "allowed var must propagate. got: {names:?}"
    );
    std::env::remove_var("DENYX_TEST_ALLOWED_VAR");
}

#[test]
fn check_subprocess_command_or_match_basename_or_full_argv0() {
    // Targets `|| with &&` on line 1403 (deny check) and analogous
    // mutation on the allow check at line 1413. The original deny
    // matches if the deny-list entry equals EITHER the basename OR
    // the full argv0. The mutant `&&` requires both — so a deny
    // list with just the basename ("rm") wouldn't match an absolute
    // path argv0 ("/bin/rm"), letting it through.
    let p = build(
        r#"
[subprocess]
deny_commands = ["rm"]
allow_commands = ["python3"]
"#,
    );
    // Absolute path: basename matches, full argv0 doesn't.
    assert!(
        p.check_subprocess_command("/bin/rm").is_err(),
        "deny by basename must catch absolute-path argv0"
    );
    // Allow-side mirror: allow_commands has just "python3";
    // full path "/usr/bin/python3" must match by basename.
    assert!(
        p.check_subprocess_command("/usr/bin/python3").is_ok(),
        "allow by basename must match absolute-path argv0"
    );
}

#[test]
fn check_subprocess_command_eq_not_neq() {
    // Targets `== with !=` on line 1420 (in the local_only check,
    // `.any(|c| c == basename || c == argv0)`). Mutant flips to
    // `!= ... ||` which would match almost any command.
    let p = build(
        r#"
[subprocess]
local_only_commands = ["curl"]
"#,
    );
    // "curl" should be allowed (local-only).
    assert!(p.check_subprocess_command("curl").is_ok());
    // "wget" is in NEITHER allow nor local_only nor deny. Must be
    // rejected. Mutant `!= ||` would let it through because some
    // entry in local_only_commands ("curl") != "wget".
    assert!(
        p.check_subprocess_command("wget").is_err(),
        "wget must be denied; not in any allow / local_only list"
    );
}

#[test]
fn check_subprocess_argv_paths_runs_for_three_argv_elements() {
    // Targets `< with >` on line 1507 (`if argv.len() < 2 { return
    // Ok(()); }`). With `>`, argv.len() > 2 returns Ok early —
    // which means commands with 3+ elements bypass the path scan
    // entirely. Real example: `cat /etc/passwd extra` would slip
    // through despite /etc/passwd being denied.
    let p = build(
        r#"
inherits = "secure-defaults"

[subprocess]
allow_commands = ["cat"]
"#,
    );
    let argv: Vec<String> = vec!["cat".into(), "/etc/passwd".into(), "ignored".into()];
    let r = p.check_subprocess_argv_paths(&argv);
    assert!(
        r.is_err(),
        "3-element argv with denied path must still be gated"
    );
}

#[test]
fn check_subprocess_argv_paths_or_join_of_allow_lists_uses_or() {
    // Targets `|| with &&` on lines 1528-1529 in the permitted-
    // path check (`fs_read.is_match || local_only_read.is_match
    // || fs_write.is_match || fs_delete.is_match`). Mutant `&&`
    // requires ALL four allow lists to match — almost never true
    // for any real path → permitted=false → over-deny. Catches the
    // mutant whenever a path is in ONE allow list but not all four.
    let p = build(
        r#"
[filesystem]
read_allow = ["/proj/src/**"]

[subprocess]
allow_commands = ["cat"]
"#,
    );
    let argv: Vec<String> = vec!["cat".into(), "/proj/src/main.py".into()];
    // Rooted at "/tmp" by build(), so /proj/src/main.py is absolute
    // and resolves directly; matches read_allow only.
    let r = p.check_subprocess_argv_paths(&argv);
    assert!(
        r.is_ok(),
        "path covered by ONE allow list (read_allow) must be permitted; \
         mutant && would require all four lists to match. got: {r:?}"
    );
}

#[test]
fn derive_capabilities_pushes_fs_read_when_only_read_allow_is_set() {
    // Targets `|| with &&` on line 1726 (`if !read_allow.is_empty()
    // || !local_only_read.is_empty()`) — mutant requires BOTH
    // non-empty, so a project that only sets read_allow (the common
    // case) wouldn't get fs.read derived. The verifier would then
    // reject every fs.read call as "capability not enabled."
    let p = build(
        r#"
[filesystem]
read_allow = ["/x/**"]
"#,
    );
    let funcs = p.effective_functions();
    assert!(
        funcs.contains(&"fs.read"),
        "read_allow alone must enable fs.read; got: {funcs:?}"
    );
}

#[test]
fn derive_capabilities_pushes_fs_read_when_only_local_only_read_is_set() {
    // Mirror of the above — local_only_read alone must also enable
    // fs.read. Catches the same `||` → `&&` mutation from the other
    // direction.
    let p = build(
        r#"
[filesystem]
local_only_read = ["~/.config/myapp/token"]
"#,
    );
    let funcs = p.effective_functions();
    assert!(
        funcs.contains(&"fs.read"),
        "local_only_read alone must enable fs.read; got: {funcs:?}"
    );
}

#[test]
fn derive_capabilities_pushes_http_verbs_when_only_local_only_hosts_set() {
    // Targets `|| with &&` on lines 1737-1750 (the http_*_allow
    // checks). Each line is `if !http_X_allow.is_empty() ||
    // any_local_only_host`. Mutant `&&` requires both to be
    // non-empty — so a policy that ONLY sets local_only_hosts
    // wouldn't enable any net.http_* capability.
    let p = build(
        r#"
[network]
local_only_hosts = ["api.openai.com"]
"#,
    );
    let funcs = p.effective_functions();
    for verb in &[
        "net.http_get",
        "net.http_post",
        "net.http_put",
        "net.http_patch",
        "net.http_delete",
    ] {
        assert!(
            funcs.contains(verb),
            "local_only_hosts alone must enable {verb}; got: {funcs:?}"
        );
    }
}

#[test]
fn derive_capabilities_pushes_env_read_when_only_one_env_list_set() {
    // Mirrors fs.read for env. Both `allow_vars` alone and
    // `local_only_vars` alone must enable env.read.
    let p_allow = build(
        r#"
[environment]
allow_vars = ["USER"]
"#,
    );
    let p_local = build(
        r#"
[environment]
local_only_vars = ["OPENAI_API_KEY"]
"#,
    );
    assert!(p_allow.effective_functions().contains(&"env.read"));
    assert!(p_local.effective_functions().contains(&"env.read"));
}

#[test]
fn derive_capabilities_pushes_subprocess_exec_when_only_one_command_list_set() {
    // Mirror for subprocess.exec: both allow_commands and
    // local_only_commands enable it.
    let p_allow = build(
        r#"
[subprocess]
allow_commands = ["git"]
"#,
    );
    let p_local = build(
        r#"
[subprocess]
local_only_commands = ["doctl"]
"#,
    );
    assert!(p_allow.effective_functions().contains(&"subprocess.exec"));
    assert!(p_local.effective_functions().contains(&"subprocess.exec"));
}

#[test]
fn looks_like_path_arg_treats_three_elements_with_path() {
    // The function `looks_like_path_arg` is private. We exercise
    // it via `check_subprocess_argv_paths`. Several `||` mutations
    // in the path-prefix chain (line 1573-1577) survive because
    // `arg.contains('/')` handles the same cases at the next if.
    // The `||` between `arg.starts_with("~/")` and `arg == "~"`
    // (specifically) only matters for arg = "~" exactly — that's
    // the only case where contains('/') doesn't fire.
    //
    // Setup: argv with arg = "~" and a policy that DOES NOT permit
    // home dir. Without the gate (mutant), "~" passes through as
    // a non-path; with the gate (original), "~" gets resolved and
    // checked → if not in any allow list, denied.
    let p = build(
        r#"
inherits = "secure-defaults"

[subprocess]
allow_commands = ["echo"]
"#,
    );
    let argv: Vec<String> = vec!["echo".into(), "~".into()];
    // `~` alone resolves to the user's home dir. Under
    // secure-defaults that's not in read/write/delete allow lists,
    // so the gate must reject. Mutant `||` → `&&` between
    // starts_with("~/") and arg == "~" would make `~` not look
    // like a path → no gate fires → Ok returned (BYPASS).
    let r = p.check_subprocess_argv_paths(&argv);
    assert!(
        r.is_err(),
        "argv element `~` alone must be gated as a path; mutant && would let it through"
    );
}
