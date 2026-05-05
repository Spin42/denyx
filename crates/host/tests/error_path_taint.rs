//! Tests that taint redaction applies to the AegisError path, not
//! just to outcome.printed and audit-event payloads. A script that
//! reads a `local_only_var` and calls `fail(secret)` would
//! otherwise produce a Starlark error message containing the raw
//! value — leaking it through stderr, MCP tool results, or any
//! other consumer of AegisError::Display.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use aegis_host::Runner;
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    Runner::new(policy)
}

fn unique(prefix: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "AEGIS_TEST_{}_{}_{}",
        prefix,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

#[test]
fn fail_with_local_only_value_does_not_leak_in_starlark_error() {
    let var = unique("FAIL_LEAK");
    let value = "ek-do-not-leak-via-error-message-XYZ12345";
    std::env::set_var(&var, value);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]
"#
    );
    let runner = runner_for(&toml);
    // Starlark's `fail()` raises with the given message. Without
    // the fix, AegisError::Starlark contains the raw value. With
    // the fix, the value is replaced with [REDACTED].
    let src = format!(
        r#"k = env.read("{var}")
fail(k)
"#
    );
    let err = runner.run("t", &src, "test.star").unwrap_err();
    let msg = err.to_string();
    assert!(
        !msg.contains(value),
        "raw secret leaked through AegisError::Display: {msg}"
    );
    assert!(
        msg.contains("[REDACTED]"),
        "expected redaction sentinel in error message: {msg}"
    );

    std::env::remove_var(&var);
}

#[test]
fn local_only_value_in_runtime_panic_message_is_redacted() {
    // A different shape: the secret ends up in an error message via
    // some runtime mechanism (e.g. divide-by-zero where the divisor
    // is derived from the secret). Starlark renders the value into
    // the trace. Should be redacted on the way out.
    //
    // We can't easily force a value into a divide-by-zero, but we
    // can use indexing past end with a string slice that includes
    // the secret — Starlark's rendering will include that string.
    let var = unique("INDEX_LEAK");
    let value = "ix-still-tainted-abcdefghij";
    std::env::set_var(&var, value);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]
"#
    );
    let runner = runner_for(&toml);
    // Trigger an error whose message includes the secret. fail() is
    // the simplest reliable way — it's surfaced verbatim. Other
    // forms (index-out-of-range, type errors) might or might not
    // carry the value depending on Starlark's renderer.
    let src = format!(
        r#"k = env.read("{var}")
def boom():
    fail("bad: " + k)
boom()
"#
    );
    let err = runner.run("t", &src, "test.star").unwrap_err();
    let msg = err.to_string();
    assert!(!msg.contains(value), "leak: {msg}");
    assert!(msg.contains("[REDACTED]"));

    std::env::remove_var(&var);
}

#[test]
fn untainted_run_produces_unchanged_error_messages() {
    // Sanity: when the run has no tainted values, the redaction is
    // a no-op and error messages pass through unchanged. We don't
    // want to accidentally regress regular error reporting.
    let toml = r#"
[filesystem]
read_allow = ["/tmp/aegis_no_taint_test/**"]
"#;
    let runner = runner_for(toml);
    let src = r#"fs.read("/tmp/aegis_no_taint_test/missing")"#;
    let err = runner.run("t", src, "test.star").unwrap_err();
    let msg = err.to_string();
    // Whatever the exact wording, it shouldn't be "[REDACTED]" —
    // there's nothing to redact.
    assert!(!msg.is_empty());
    assert!(!msg.contains("[REDACTED]"));
    // PathBuf debug formatting:
    assert!(msg.contains("aegis_no_taint_test"));
}

#[test]
fn pure_redact_helper_idempotent() {
    use aegis_host::redact;
    // Sanity for the helper itself: applying redact twice produces
    // the same result as applying once. Not a security property,
    // just a developer-comfort check.
    let taints = vec!["secret-abc-123".to_string()];
    let once = redact("token=secret-abc-123 done", &taints);
    let twice = redact(&once, &taints);
    assert_eq!(once, twice);
    assert_eq!(once, "token=[REDACTED] done");
}

#[test]
fn unused_var_silences_warning() {
    // Just to satisfy clippy if any cfg surfaces a dead PathBuf import.
    let _: PathBuf = PathBuf::from("/");
}
