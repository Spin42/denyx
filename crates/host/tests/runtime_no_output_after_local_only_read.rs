//! Integration tests for `[runtime].no_output_after_local_only_read`
//! against the native `Runner`. Mirrors `tests/taint.rs`'s fixture
//! style (variable-arg `fs.read` so the pre-exec verifier's
//! literal-arg-only `taint_flow` check doesn't short-circuit before
//! the runtime flag gets a chance to fire — see verifier.rs's module
//! doc for why that check is a naive pre-filter, not authoritative).
//!
//! Unlike the default per-value taint scrub (`tests/taint.rs`), this
//! flag refuses ANY output-producing call once ANY local-only read has
//! occurred, regardless of whether the specific value being output is
//! itself tainted — these tests specifically print an UNRELATED
//! string after the local-only read to prove that stronger property.

use std::path::PathBuf;

use denyx_host::{DenyxError, Runner};
use denyx_policy::{Policy, PolicyFile};

fn runner_for(toml: &str, root: PathBuf) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, root).unwrap();
    Runner::new(policy)
}

fn write_secret_fixture(tag: &str) -> (PathBuf, String) {
    let tmp = std::env::temp_dir();
    let path = tmp.join(format!(
        "denyx_no_output_after_local_only_read_{tag}_{}.txt",
        std::process::id()
    ));
    std::fs::write(&path, "irrelevant-secret-value").unwrap();
    let path_lit = path.to_string_lossy().replace('\\', "/");
    (path, path_lit)
}

#[test]
fn denies_unrelated_print_after_local_only_read_when_flag_set() {
    let (path, path_lit) = write_secret_fixture("deny");
    let toml = format!(
        r#"
[filesystem]
local_only_read = ["{path_lit}"]

[runtime]
no_output_after_local_only_read = true
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    let src = format!(
        r#"p = "{path_lit}"
x = fs.read(p)
print("this string has nothing to do with the secret")
"#
    );
    let err = runner
        .run("t1", &src, "test.star")
        .expect_err("output after a local-only read must be refused when the flag is set");
    assert!(
        matches!(err, DenyxError::Policy(_)),
        "expected DenyxError::Policy, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("no_output_after_local_only_read") || msg.contains("local-only read"),
        "expected a message naming the flag/property, got: {msg}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn allows_output_with_no_local_only_read_even_when_flag_set() {
    let toml = r#"
[runtime]
no_output_after_local_only_read = true
"#;
    let runner = runner_for(toml, std::env::temp_dir());
    let src = r#"print("no local-only read ever happened in this script")"#;
    let outcome = runner
        .run("t1", src, "test.star")
        .expect("no local-only read occurred, so output must be unaffected by the flag");
    assert_eq!(
        outcome.printed,
        vec!["no local-only read ever happened in this script".to_string()]
    );
}

#[test]
fn allows_output_after_local_only_read_when_flag_is_unset_default() {
    let (path, path_lit) = write_secret_fixture("default_off");
    // No [runtime] section at all — flag defaults to false, matching
    // pre-existing behavior (only the per-value taint scrub applies).
    let toml = format!(
        r#"
[filesystem]
local_only_read = ["{path_lit}"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    let src = format!(
        r#"p = "{path_lit}"
x = fs.read(p)
print("this string has nothing to do with the secret")
"#
    );
    let outcome = runner
        .run("t1", &src, "test.star")
        .expect("flag defaults to off; unrelated output after a local-only read is unaffected");
    assert_eq!(
        outcome.printed,
        vec!["this string has nothing to do with the secret".to_string()]
    );
    let _ = std::fs::remove_file(&path);
}
