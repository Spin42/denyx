//! Integration tests for local-only-read taint propagation.
//!
//! Each test exercises one of the four taint sources (filesystem,
//! environment, subprocess, network) end-to-end through `Runner::run`.
//! The script reads a tainted value, prints it (sometimes embedded in
//! a larger string), and the test asserts that the printed line that
//! comes back from the runtime contains `[REDACTED]` instead of the
//! raw value.
//!
//! These tests pin the contract: a value flagged local-only is
//! readable to the script but cannot bubble up to the calling host
//! through any output boundary.

use std::path::PathBuf;

use denyx_host::Runner;
use denyx_policy::{Policy, PolicyFile};

fn runner_for(toml: &str, root: PathBuf) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, root).unwrap();
    Runner::new(policy)
}

#[test]
fn fs_local_only_read_redacts_in_printed_output() {
    let tmp = std::env::temp_dir();
    let secret_path = tmp.join(format!("denyx_taint_secret_{}.txt", std::process::id()));
    let secret_value = "supersecret-fs-token-abc123-XYZ789";
    std::fs::write(&secret_path, secret_value).unwrap();
    let path_lit = secret_path.to_string_lossy().replace('\\', "/");

    let path_holder_var = format!("DENYX_TAINT_TEST_FS_PATH_HOLDER_{}", std::process::id());
    std::env::set_var(&path_holder_var, &path_lit);

    let toml = format!(
        r#"
[filesystem]
local_only_read = ["{path}"]

[environment]
allow_vars = ["{path_holder_var}"]

[functions]
allow = ["fs.read", "env.read"]
"#,
        path = path_lit
    );
    let runner = runner_for(&toml, tmp);
    // NOTE: this test exercises the **runtime IFC scrubber**
    // (`redact_lines`) — which is the fallback layer for cases the
    // pre-exec tainted-output-flow verifier doesn't catch. The path
    // is fetched via `env.read(...)` (a call result, not statically
    // foldable) rather than a literal or a directly-foldable
    // variable, so the AST-based static pass (T6.2-T6.6) can't
    // resolve it and the runtime path does the work. The pre-exec
    // behaviour (refusal of the literal/foldable shape) has its own
    // tests in `tests/verifier.rs`.
    let src = format!(
        r#"p = env.read("{path_holder_var}")
x = fs.read(p)
print("got:", x)
print("len:", len(x))
"#
    );
    let outcome = runner.run("t-fs", &src, "test.star").unwrap();
    std::env::remove_var(&path_holder_var);
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(secret_value),
        "raw secret leaked into printed output: {joined}"
    );
    assert!(
        joined.contains("[REDACTED]"),
        "expected [REDACTED] sentinel in output: {joined}"
    );
    // Length is a derived quantity (not a substring of the secret) and
    // should pass through unredacted.
    assert!(joined.contains("len:"));

    let _ = std::fs::remove_file(&secret_path);
}

#[test]
fn env_local_only_var_redacts_in_printed_output() {
    let var = "DENYX_TAINT_TEST_VAR";
    let secret_value = "ek-zzz-zzz-this-is-the-key-do-not-leak";
    std::env::set_var(var, secret_value);
    let name_holder_var = format!("DENYX_TAINT_TEST_VAR_NAME_HOLDER_{}", std::process::id());
    std::env::set_var(&name_holder_var, var);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]
allow_vars = ["{name_holder_var}"]

[functions]
allow = ["env.read"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    // The target var's NAME is itself fetched via `env.read(...)` (a
    // call result, not statically foldable), so the AST-based static
    // pass (T6.2-T6.6) can't resolve it and the runtime IFC path
    // (`redact_lines`) is exercised here. Pre-exec literal/foldable-arg
    // refusal is covered in tests/verifier.rs.
    let src = format!(
        r#"name = env.read("{name_holder_var}")
k = env.read(name)
print("auth=Bearer", k)
"#
    );
    let outcome = runner.run("t-env", &src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(secret_value),
        "env secret leaked: {joined}"
    );
    assert!(joined.contains("[REDACTED]"), "got: {joined}");
    assert!(joined.contains("auth=Bearer"), "preamble preserved");

    std::env::remove_var(var);
    std::env::remove_var(&name_holder_var);
}

#[test]
fn env_local_only_var_redacts_after_string_concat() {
    // Even when the script tries to wrap or interpolate the value, the
    // substring check on the final printed line catches it because the
    // raw secret is still present as a substring.
    let var = "DENYX_TAINT_TEST_CONCAT";
    let secret_value = "raw-concat-secret-value-xyz0123";
    std::env::set_var(var, secret_value);
    let name_holder_var = format!("DENYX_TAINT_TEST_CONCAT_NAME_HOLDER_{}", std::process::id());
    std::env::set_var(&name_holder_var, var);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]
allow_vars = ["{name_holder_var}"]

[functions]
allow = ["env.read"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    // Same non-foldable indirection as the test above — the target
    // var's name is fetched via `env.read(...)`, keeping this test on
    // the runtime IFC path rather than the AST-based static pass.
    // Pre-exec refusal for the literal/foldable shape is in
    // tests/verifier.rs.
    let src = format!(
        r#"name = env.read("{name_holder_var}")
k = env.read(name)
print("PREFIX[" + k + "]SUFFIX")
"#
    );
    let outcome = runner.run("t-concat", &src, "test.star").unwrap();
    std::env::remove_var(&name_holder_var);
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(secret_value),
        "leaked via concat: {joined}"
    );
    assert!(joined.contains("PREFIX["));
    assert!(joined.contains("]SUFFIX"));
    assert!(joined.contains("[REDACTED]"));

    std::env::remove_var(var);
}

#[test]
fn fs_write_with_tainted_content_is_denied_at_arg_check() {
    // Pre-IFC behaviour: fs.write with the tainted secret as content
    // succeeded; reading back through fs.read re-tainted, and the
    // print scrubber caught the readback.
    //
    // Post-IFC behaviour: fs.write to a non-local-only path with
    // tainted content is **denied at the arg check**, before any
    // bytes touch the disk. The disk persistence channel is closed
    // entirely — there's no file for an out-of-band reader to find.
    // This test asserts the new (stricter) behaviour: the round-trip
    // attempt fails with a Policy error and the scratch file is
    // never created.
    let var = "DENYX_TAINT_TEST_ROUNDTRIP";
    let secret_value = "roundtrip-secret-value-9999-abcdef";
    std::env::set_var(var, secret_value);
    let tmp = std::env::temp_dir();
    let scratch = tmp.join(format!("denyx_taint_rt_{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&scratch);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]

[filesystem]
read_allow = ["{path}"]
write_allow = ["{path}"]
"#,
        path = scratch.to_string_lossy().replace('\\', "/")
    );
    let runner = runner_for(&toml, tmp);
    let path_lit = scratch.to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"k = env.read("{var}")
fs.write("{path_lit}", k)
print("after_write")
"#
    );
    let err = runner
        .run("t-rt", &src, "test.star")
        .expect_err("fs.write of tainted content to a non-local-only path must be denied");
    let msg = format!("{err}");
    assert!(msg.contains("tainted"), "error should mention taint: {msg}");
    assert!(
        msg.contains("fs.write"),
        "error should name fs.write: {msg}"
    );
    assert!(
        !scratch.exists(),
        "scratch file should never have been written: {}",
        scratch.display()
    );

    std::env::remove_var(var);
}

#[test]
fn subprocess_local_only_command_redacts_stdout() {
    // `printf` is a portable subprocess. We mark it local-only and
    // assert its stdout is redacted in the printed output.
    let secret_value = "subproc-stdout-secret-token-MNOP4321";
    let toml = r#"
[subprocess]
local_only_commands = ["printf"]

[functions]
allow = ["subprocess.exec"]
"#
    .to_string();
    let runner = runner_for(&toml, std::env::temp_dir());
    // printf "%s" "<secret>" — bare printf doesn't add a trailing
    // newline, so stdout is exactly the secret.
    let src = format!(
        r#"out = subprocess.exec(["printf", "%s", "{secret}"])
print("captured:", out)
"#,
        secret = secret_value
    );
    let outcome = runner.run("t-sp", &src, "test.star").unwrap();
    let joined = outcome.printed.join("\n");
    assert!(
        !joined.contains(secret_value),
        "subprocess stdout leaked: {joined}"
    );
    assert!(joined.contains("[REDACTED]"));
}

#[test]
fn plain_allow_does_not_redact() {
    // Sanity check: a regular allow_vars var is NOT tainted, so its
    // value passes through to the printed output unchanged.
    let var = "DENYX_TAINT_TEST_PLAIN";
    let value = "plain-not-secret-value-AAAA";
    std::env::set_var(var, value);

    let toml = format!(
        r#"
[environment]
allow_vars = ["{var}"]

[functions]
allow = ["env.read"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    let src = format!(
        r#"k = env.read("{var}")
print("v=", k)
"#
    );
    let outcome = runner.run("t-plain", &src, "test.star").unwrap();
    let joined = outcome.printed.join(" ");
    assert!(
        joined.contains(value),
        "plain value should pass through: {joined}"
    );
    assert!(!joined.contains("[REDACTED]"));

    std::env::remove_var(var);
}

#[test]
fn audit_event_payload_is_also_redacted() {
    // The audit log is one of the output boundaries. Even if a script
    // never `print`s, an audit-event field that happens to contain the
    // secret must be redacted before it reaches the sink.
    use denyx_host::{AuditEvent, AuditSink};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Capture(Mutex<Vec<AuditEvent>>);
    impl AuditSink for Capture {
        fn emit(&self, event: AuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    let var = "DENYX_TAINT_AUDIT";
    let secret = "audit-secret-do-not-leak-ABCD";
    std::env::set_var(var, secret);

    // The command is marked local-only — its argv is permitted to
    // carry tainted bytes (its stdout would also be tainted, so the
    // value can't escape via that channel). With a local-only command
    // the arg-check passes; we then assert the audit event payload
    // gets the substring scrubbing.
    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]

[subprocess]
local_only_commands = ["printf"]
"#
    );
    let file = PolicyFile::from_toml_str(&toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    let cap = Arc::new(Capture::default());
    let runner = Runner::new(policy).with_audit(cap.clone());

    // Variable-arg env.read so the pre-exec tainted-output-flow
    // refusal (literal-arg-only) doesn't fire; this test is about the
    // RUNTIME redaction of the audit-event payload.
    let src = format!(
        r#"name = "{var}"
k = env.read(name)
out = subprocess.exec(["printf", "%s", k])
"#
    );
    runner.run("t-audit", &src, "test.star").unwrap();
    let events = cap.0.lock().unwrap();
    let serialized = serde_json::to_string(&*events).unwrap();
    assert!(
        !serialized.contains(secret),
        "audit log leaked secret: {serialized}"
    );

    std::env::remove_var(var);
}

#[test]
fn subprocess_with_tainted_argv_is_denied_for_public_command() {
    // Companion to the audit-redaction test: when the command is NOT
    // local-only, passing a tainted value as argv is denied at the
    // arg check. This is the new IFC: the script can't push secret
    // bytes to a host-visible binary's stdout via argv.
    let var = "DENYX_TAINT_PUBLIC_ARGV";
    let secret = "public-argv-secret-token-9999";
    std::env::set_var(var, secret);

    let toml = format!(
        r#"
[environment]
local_only_vars = ["{var}"]

[subprocess]
allow_commands = ["printf"]
"#
    );
    let runner = runner_for(&toml, std::env::temp_dir());
    let src = format!(
        r#"k = env.read("{var}")
out = subprocess.exec(["printf", "%s", k])
print("never_reached")
"#
    );
    let err = runner
        .run("t-pa", &src, "test.star")
        .expect_err("public command must refuse tainted argv");
    let msg = format!("{err}");
    assert!(msg.contains("tainted"), "{msg}");
    assert!(msg.contains("subprocess.exec"), "{msg}");
    std::env::remove_var(var);
}
