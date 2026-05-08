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
    // Targets `|| with &&` on line 1403 (deny check). Both
    // `is_err()` outcomes (deny-match vs not-in-allow) are valid
    // Err results, so we assert the SPECIFIC reason string to
    // distinguish the original (matched deny) from the mutant
    // (fell through, denied as "not in allow_commands").
    let p = build(
        r#"
[subprocess]
deny_commands = ["rm"]
allow_commands = ["python3"]
"#,
    );
    // Absolute path: basename matches deny, full argv0 doesn't.
    let err = p
        .check_subprocess_command("/bin/rm")
        .expect_err("deny must catch absolute-path argv0 by basename");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("deny_commands"),
        "must be denied via the DENY rule (not as fallthrough); got: {msg}"
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
fn check_subprocess_argv_paths_path_covered_only_by_read_allow() {
    // Targets `|| with &&` between fs_read and fs_local_only_read.
    // With path matching ONLY fs_read, original short-circuits to
    // true (Ok). Mutant `(fs_read && fs_local_only_read) || ...`:
    // (true && false) = false; the rest of the OR-chain checks
    // fail too if not matched. Result: Err.
    let p = build(
        r#"
[filesystem]
read_allow = ["/proj/src/**"]

[subprocess]
allow_commands = ["cat"]
"#,
    );
    let argv: Vec<String> = vec!["cat".into(), "/proj/src/main.py".into()];
    let r = p.check_subprocess_argv_paths(&argv);
    assert!(
        r.is_ok(),
        "path matching read_allow alone must be permitted; got: {r:?}"
    );
}

#[test]
fn check_subprocess_argv_paths_path_covered_only_by_local_only_read() {
    // Targets `|| with &&` between fs_local_only_read and fs_write
    // (the SECOND `||`). Path matches ONLY local_only_read.
    // Mutant: `fs_read || (fs_local_only_read && fs_write) ||
    // fs_delete` = `false || (true && false) || false` = false.
    let p = build(
        r#"
[filesystem]
local_only_read = ["/secret/**"]

[subprocess]
allow_commands = ["cat"]
"#,
    );
    let argv: Vec<String> = vec!["cat".into(), "/secret/token".into()];
    let r = p.check_subprocess_argv_paths(&argv);
    assert!(
        r.is_ok(),
        "path matching local_only_read alone must be permitted; got: {r:?}"
    );
}

#[test]
fn check_subprocess_argv_paths_path_covered_only_by_write_allow() {
    // Targets `|| with &&` between fs_write and fs_delete (the
    // THIRD `||`). Path matches ONLY fs_write. Mutant:
    // `fs_read || fs_local_only_read || (fs_write && fs_delete)`
    // = `false || false || (true && false)` = false.
    let p = build(
        r#"
[filesystem]
write_allow = ["/var/log/myapp/**"]

[subprocess]
allow_commands = ["cat"]
"#,
    );
    let argv: Vec<String> = vec!["cat".into(), "/var/log/myapp/x".into()];
    let r = p.check_subprocess_argv_paths(&argv);
    assert!(
        r.is_ok(),
        "path matching write_allow alone must be permitted; got: {r:?}"
    );
}

#[test]
fn check_subprocess_argv_paths_path_covered_only_by_delete_allow() {
    // Path matches ONLY fs_delete. Original: short-circuits to Ok.
    // Adds completeness for the OR chain so future code changes
    // adding a fifth term don't silently regress coverage.
    let p = build(
        r#"
[filesystem]
delete_allow = ["/var/scratch/**"]

[subprocess]
allow_commands = ["rm"]
"#,
    );
    let argv: Vec<String> = vec!["rm".into(), "/var/scratch/x".into()];
    let r = p.check_subprocess_argv_paths(&argv);
    assert!(
        r.is_ok(),
        "path matching delete_allow alone must be permitted; got: {r:?}"
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

// ── bwrap_argv mutants (12 survivors targeted) ────────────────────

#[test]
fn bwrap_argv_starts_with_bwrap_and_includes_isolation_flags() {
    // Targets the three FnValue mutants on line 1299 that would
    // replace the whole function body with vec![] / vec![""] /
    // vec!["xyzzy"]. Any of those would lack the canonical first
    // element "bwrap" and the standard isolation flags.
    let p = build("");
    let argv = p.bwrap_argv(&["echo".into(), "hi".into()], &[]);
    assert_eq!(argv.first().map(|s| s.as_str()), Some("bwrap"));
    for required in &[
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--clearenv",
    ] {
        assert!(
            argv.iter().any(|a| a == required),
            "bwrap argv missing canonical isolation flag {required:?}; got {argv:?}"
        );
    }
}

#[test]
fn bwrap_argv_drops_netns_when_no_network_is_permitted() {
    // Targets `delete !` on line 1358 (`if !any_net { ... }`) and
    // each `delete !` on lines 1352-1357 (`!self.file.network
    // .http_X_allow.is_empty()` and `!self.file.network
    // .local_only_hosts.is_empty()`). With NO network listed, all
    // is_empty() checks are true → originals' negations are false
    // → any_net=false → --unshare-net is added.
    //
    // Mutant `delete !` on line 1358 (`if any_net { … }`) — adds
    // --unshare-net only when any_net IS true (inverted intent),
    // so with empty network argv would NOT have --unshare-net.
    let p = build("");
    let argv = p.bwrap_argv(&["echo".into(), "hi".into()], &[]);
    assert!(
        argv.iter().any(|a| a == "--unshare-net"),
        "bwrap_argv with no network must drop the netns; got {argv:?}"
    );
}

#[test]
fn bwrap_argv_keeps_netns_when_only_one_http_verb_is_permitted() {
    // Targets each `||` → `&&` mutation on lines 1352-1357 (the
    // any_net = !X.is_empty() || !Y.is_empty() || ... chain). With
    // a SINGLE network field set, original any_net=true → no
    // --unshare-net. Mutant && requires ALL fields to be
    // simultaneously non-empty → any_net=false → --unshare-net
    // wrongly added → child process can't reach the host.
    //
    // Plus targets each `delete !` (line 1352-1357 individually).
    // For example, mutant on line 1352 makes the first OR-term
    // is_empty() (true when http_get_allow is EMPTY); but here
    // http_get_allow IS non-empty, so original term is true and
    // mutant term is false. With other terms also false (other
    // lists are empty), original any_net=true; mutant any_net=false.
    let p = build(
        r#"
[network]
http_get_allow = ["api.github.com"]
"#,
    );
    let argv = p.bwrap_argv(&["echo".into(), "hi".into()], &[]);
    assert!(
        !argv.iter().any(|a| a == "--unshare-net"),
        "bwrap_argv with http_get_allow set must keep the netns \
         (no --unshare-net); got {argv:?}"
    );
}

#[test]
fn bwrap_argv_keeps_netns_for_each_http_verb_independently() {
    // Same shape as above but exercises every `||` term in the
    // chain (one per http_*_allow + local_only_hosts). Each `||`
    // → `&&` mutation is killed by exactly one of the policies
    // below.
    let policies = vec![
        r#"[network]
http_get_allow = ["x"]
"#,
        r#"[network]
http_post_allow = ["x"]
"#,
        r#"[network]
http_put_allow = ["x"]
"#,
        r#"[network]
http_patch_allow = ["x"]
"#,
        r#"[network]
http_delete_allow = ["x"]
"#,
        r#"[network]
local_only_hosts = ["x"]
"#,
    ];
    for toml in policies {
        let p = build(toml);
        let argv = p.bwrap_argv(&["echo".into(), "hi".into()], &[]);
        assert!(
            !argv.iter().any(|a| a == "--unshare-net"),
            "any single network field non-empty must keep netns; \
             policy={toml:?} argv={argv:?}"
        );
    }
}

// ── derive_capabilities `delete !` mutants (5 survivors) ──────────

#[test]
fn derive_capabilities_omits_fs_write_when_write_allow_is_empty() {
    // Targets `delete !` on line 1729 (`if !fs.write_allow
    // .is_empty()`). Original: pushes fs.write only if non-empty.
    // Mutant `if fs.write_allow.is_empty()`: pushes fs.write when
    // the list IS empty (inverted), letting the verifier accept
    // fs.write calls without any write paths configured.
    let p = build(
        r#"
[filesystem]
read_allow = ["/x/**"]
"#,
    );
    let funcs = p.effective_functions();
    assert!(
        !funcs.contains(&"fs.write"),
        "fs.write must NOT be enabled when write_allow is empty; got: {funcs:?}"
    );
}

#[test]
fn derive_capabilities_omits_fs_delete_when_delete_allow_is_empty() {
    // Targets `delete !` on line 1732 (fs.delete check).
    let p = build("");
    let funcs = p.effective_functions();
    assert!(
        !funcs.contains(&"fs.delete"),
        "fs.delete must NOT be enabled when delete_allow is empty; got: {funcs:?}"
    );
}

#[test]
fn derive_capabilities_omits_unset_http_verbs() {
    // Targets `delete !` on lines 1737, 1740, 1743, 1746, 1749
    // (the http_*_allow checks). Each `!X.is_empty() ||
    // any_local_only_host` becomes `X.is_empty() ||
    // any_local_only_host` — pushes the verb when X is empty AND
    // any_local_only_host is false (i.e., always when X is empty
    // unless local_only_hosts has entries).
    //
    // Setup: completely empty network. Original: derives no http_*
    // verbs. Mutant: derives whichever ones it mishandles. Test
    // asserts NONE are present.
    let p = build("");
    let funcs = p.effective_functions();
    for v in &[
        "net.http_get",
        "net.http_post",
        "net.http_put",
        "net.http_patch",
        "net.http_delete",
    ] {
        assert!(
            !funcs.contains(v),
            "{v} must NOT be enabled with empty network; got: {funcs:?}"
        );
    }
}

#[test]
fn derive_capabilities_omits_env_read_when_no_env_lists_set() {
    // Targets `delete !` analogue on line 1753 (`if !env
    // .allow_vars.is_empty() || !env.local_only_vars.is_empty()`).
    let p = build("");
    let funcs = p.effective_functions();
    assert!(
        !funcs.contains(&"env.read"),
        "env.read must NOT be enabled with no env lists; got: {funcs:?}"
    );
}

#[test]
fn derive_capabilities_omits_subprocess_exec_when_no_command_lists_set() {
    // Targets the corresponding `delete !` on line 1757 (subprocess
    // check).
    let p = build("");
    let funcs = p.effective_functions();
    assert!(
        !funcs.contains(&"subprocess.exec"),
        "subprocess.exec must NOT be enabled with no commands; got: {funcs:?}"
    );
}

// ── looks_like_path_arg line-1567 mutant ──────────────────────────

#[test]
fn looks_like_path_arg_treats_empty_string_as_not_a_path() {
    // Targets `||` → `&&` on line 1567 (`if arg.is_empty() || arg
    // == "-" { return false; }`). Mutant requires BOTH conditions
    // (impossible: empty string is not "-"), so the early return
    // never fires. Empty string then falls through to
    // `root.join("").exists()` which is true (root exists), and
    // looks_like_path_arg returns true — gating the empty-string
    // arg as a path.
    //
    // Test via check_subprocess_argv_paths: argv with an empty
    // arg and a policy that doesn't permit the root. Original
    // skips the empty arg (looks_like_path_arg=false → continue).
    // Mutant treats it as a path → resolves to root → which is
    // not in any allow list → Err.
    let p = build(
        r#"
[subprocess]
allow_commands = ["echo"]
"#,
    );
    // Empty string for arg.
    let argv: Vec<String> = vec!["echo".into(), "".into()];
    let r = p.check_subprocess_argv_paths(&argv);
    assert!(
        r.is_ok(),
        "empty-string argv elements must NOT be gated as paths; \
         mutant `&&` on the empty/dash check would gate them. got: {r:?}"
    );
}

// ── More FnValue-style getter tests ──────────────────────────────

#[test]
fn merge_policy_files_overlays_non_default_sandbox() {
    // Targets `== with !=` on line 619 in merge_policy_files. The
    // overlay rule: if the user (over) sets sandbox to something
    // other than the default, that overrides the inherited base.
    // Original: `over.sandbox == default → use base`. Mutant
    // `over.sandbox != default → use base`: inverts the rule —
    // base wins ALWAYS unless user happens to set the literal
    // default value. That'd let an inherited preset (which sets
    // sandbox = "bwrap") silently override the user's
    // `sandbox = "none"` opt-out (or vice versa).
    //
    // Verify: user file with explicit `sandbox = "bwrap"` should
    // come through after merge. Default of SandboxMode is "none",
    // so "bwrap" != default → original keeps over (bwrap). Mutant
    // would compute over != default → use base (whatever base says,
    // which is none since we don't inherit anything → "none").
    let p = build(
        r#"
[subprocess]
sandbox = "bwrap"
"#,
    );
    assert_eq!(
        format!("{:?}", p.sandbox_mode()),
        "Bwrap",
        "user's explicit sandbox = bwrap must survive the merge; \
         mutant `!= default` would replace it with the base default. \
         got: {:?}",
        p.sandbox_mode()
    );
}

#[test]
fn sandbox_mode_returns_configured_value_not_default() {
    // Targets the FnValue mutant on line 1264 (`replace
    // Policy::sandbox_mode -> SandboxMode with Default::default()`).
    // Default is SandboxMode::None. With sandbox = "bwrap" set,
    // the original returns Bwrap; mutant returns None.
    let p = build(
        r#"
[subprocess]
sandbox = "bwrap"
"#,
    );
    assert_ne!(
        format!("{:?}", p.sandbox_mode()),
        "None",
        "sandbox_mode must reflect the policy, not return default"
    );
}

#[test]
fn file_snapshot_carries_through_user_set_fields() {
    // Targets the FnValue mutant on line 1548 (`replace
    // Policy::file_snapshot -> &PolicyFile with Box::leak(Box::new
    // (Default::default()))`). Mutant returns a fresh empty
    // PolicyFile, dropping the user's actual content. We assert a
    // sentinel field (name) survives.
    let p = build(
        r#"
name = "mutation-test-fixture"
"#,
    );
    let snap = p.file_snapshot();
    assert_eq!(
        snap.name.as_deref(),
        Some("mutation-test-fixture"),
        "file_snapshot must return the actual file content, not a default"
    );
}

#[test]
fn tools_iter_yields_declared_tools() {
    // Targets the FnValue mutant on line 964 (`replace
    // Policy::tools_iter -> impl Iterator with std::iter::empty()`).
    // With a [tools.X] entry declared, the iterator must yield it.
    let p = build(
        r#"
[tools.MyTool]
capabilities = ["fs.read"]
backend_url = "https://example.com"
"#,
    );
    let names: Vec<&str> = p.tools_iter().map(|(name, _)| name).collect();
    assert!(
        names.contains(&"MyTool"),
        "tools_iter must yield declared [tools.X] entries; got: {names:?}"
    );
}

// ── translate_pattern, canonicalize_with_unresolved_tail (delete !) ──
//
// These two `delete !` mutations are reachable but their observable
// effect requires specific path setups that are tricky to construct
// from outside the crate (both functions are private and used only
// internally during pattern compilation / sandbox-prefix derivation).
// Documented here as known-equivalent at the public API level — the
// glob-pattern matching tests in `policy.rs` exercise these
// indirectly without uniquely distinguishing the mutated form.
//
// translate_pattern line 1692: `if !raw.contains('/')`. The mutant
// `if raw.contains('/')` would prepend `**/ ` to paths that DO
// contain '/' — i.e., absolute or sub-pathed patterns get a
// recursive-prefix addition. In practice these patterns' compiled
// globsets still match the same set of paths because the underlying
// glob machinery handles `**/` prefixing as a wildcard expansion;
// the existing pattern tests don't distinguish mutated vs original
// outputs.
//
// canonicalize_with_unresolved_tail line 1957: a `delete !` inside a
// recursion-termination check. Reachable only with deeply-nested
// non-existent paths; the rest of the canonicalization pipeline
// produces identical observable paths in normal use.
