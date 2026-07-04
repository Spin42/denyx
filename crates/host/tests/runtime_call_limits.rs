//! Integration tests for `[runtime].max_calls_per_capability` and
//! `[runtime].max_total_calls` against the native `Runner`. Neither
//! cap applies to `print` (it has no resource-gate `begin_call` path
//! at all — see `crates/host/src/lib.rs`'s `PrintCapture::println`),
//! so these tests exercise `fs.read` and `env.read`, the two
//! resource-gated capabilities easiest to call repeatedly from a
//! trivial fixture.

use std::path::PathBuf;

use denyx_host::{DenyxError, Runner};
use denyx_policy::{Policy, PolicyFile};

fn runner_for(toml: &str, root: PathBuf) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, root).unwrap();
    Runner::new(policy)
}

#[test]
fn max_calls_per_capability_allows_up_to_the_cap_and_denies_the_next() {
    let tmp = std::env::temp_dir();
    let path = tmp.join(format!(
        "denyx_call_limit_fixture_{}.txt",
        std::process::id()
    ));
    std::fs::write(&path, "hello").unwrap();
    let path_lit = path.to_string_lossy().replace('\\', "/");

    let toml = format!(
        r#"
[filesystem]
read_allow = ["{path_lit}"]

[runtime.max_calls_per_capability]
"fs.read" = 2
"#
    );
    let runner = runner_for(&toml, tmp);
    let src = format!(
        r#"p = "{path_lit}"
fs.read(p)
fs.read(p)
fs.read(p)
"#
    );
    let err = runner
        .run("t1", &src, "test.star")
        .expect_err("the 3rd fs.read call must be refused once the cap of 2 is reached");
    let _ = std::fs::remove_file(&path);
    assert!(
        matches!(err, DenyxError::RuntimeLimit(_)),
        "expected DenyxError::RuntimeLimit, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("max_calls_per_capability"),
        "expected a message naming the cap, got: {msg}"
    );
}

#[test]
fn max_calls_per_capability_two_calls_at_the_cap_succeed() {
    let tmp = std::env::temp_dir();
    let path = tmp.join(format!(
        "denyx_call_limit_fixture_ok_{}.txt",
        std::process::id()
    ));
    std::fs::write(&path, "hello").unwrap();
    let path_lit = path.to_string_lossy().replace('\\', "/");

    let toml = format!(
        r#"
[filesystem]
read_allow = ["{path_lit}"]

[runtime.max_calls_per_capability]
"fs.read" = 2
"#
    );
    let runner = runner_for(&toml, tmp);
    let src = format!(
        r#"p = "{path_lit}"
fs.read(p)
fs.read(p)
print("both calls succeeded")
"#
    );
    let outcome = runner
        .run("t1", &src, "test.star")
        .expect("exactly 2 calls against a cap of 2 must succeed");
    let _ = std::fs::remove_file(&path);
    assert_eq!(outcome.printed, vec!["both calls succeeded".to_string()]);
}

#[test]
fn max_total_calls_counts_across_different_capabilities() {
    let tmp = std::env::temp_dir();
    let path = tmp.join(format!(
        "denyx_total_call_limit_fixture_{}.txt",
        std::process::id()
    ));
    std::fs::write(&path, "hello").unwrap();
    let path_lit = path.to_string_lossy().replace('\\', "/");

    let toml = format!(
        r#"
[filesystem]
read_allow = ["{path_lit}"]

[environment]
allow_vars = ["PATH"]

[runtime]
max_total_calls = 2
"#
    );
    let runner = runner_for(&toml, tmp);
    // fs.read (1) + env.read (2) = at the cap; a 3rd call of either
    // kind must be refused, proving the cap is summed across
    // capabilities rather than tracked per-capability.
    let src = format!(
        r#"p = "{path_lit}"
fs.read(p)
env.read("PATH")
fs.read(p)
"#
    );
    let err = runner
        .run("t1", &src, "test.star")
        .expect_err("the 3rd call (of any capability) must be refused once max_total_calls=2");
    let _ = std::fs::remove_file(&path);
    assert!(
        matches!(err, DenyxError::RuntimeLimit(_)),
        "expected DenyxError::RuntimeLimit, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("max_total_calls"),
        "expected a message naming the cap, got: {msg}"
    );
}

#[test]
fn no_caps_configured_allows_unlimited_calls() {
    let tmp = std::env::temp_dir();
    let path = tmp.join(format!(
        "denyx_no_call_limit_fixture_{}.txt",
        std::process::id()
    ));
    std::fs::write(&path, "hello").unwrap();
    let path_lit = path.to_string_lossy().replace('\\', "/");

    let toml = format!(
        r#"
[filesystem]
read_allow = ["{path_lit}"]
"#
    );
    let runner = runner_for(&toml, tmp);
    let src = format!(
        r#"p = "{path_lit}"
def go():
    for _ in range(50):
        fs.read(p)
    print("done")
go()
"#
    );
    let outcome = runner
        .run("t1", &src, "test.star")
        .expect("with no caps configured, repeated calls are unaffected");
    let _ = std::fs::remove_file(&path);
    assert_eq!(outcome.printed, vec!["done".to_string()]);
}
