//! Regression test for a Phase 3 (wasm/native parity review) finding:
//! `wasm_runner.rs` emitted audit events for its outbound-taint-refusal
//! denials by calling `audit.emit(...)` directly, bypassing the
//! scrubbing the in-process `Runner`'s `HostCtx::emit` always applies.
//! Those denial events build their `target` field from the RAW
//! argument value — exactly the local-only bytes the taint layer
//! exists to keep off the runtime boundary — so the raw secret was
//! written to the audit log in plaintext on the (default) wasm path
//! whenever an outbound-taint refusal fired, while the native path
//! correctly redacted the same case.
//!
//! Fixed via `wasm_runner.rs`'s new `emit_scrubbed` helper, which every
//! wasm audit emission now routes through. This test asserts BOTH
//! runners produce a redacted audit payload for the identical policy
//! and script, so a future reimplementation drift on either side fails
//! loudly instead of silently reopening this leak.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use denyx_host::{AuditEvent, AuditSink, Runner, WasmRunner};
use denyx_policy::{Policy, PolicyFile};

#[derive(Default)]
struct Capture(Mutex<Vec<AuditEvent>>);
impl AuditSink for Capture {
    fn emit(&self, event: AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn fixture() -> (PathBuf, String, &'static str) {
    let tmp = std::env::temp_dir();
    let path = tmp.join(format!(
        "denyx_audit_scrub_parity_secret_{}.txt",
        std::process::id()
    ));
    let secret = "TOPSECRET-audit-leak-check-XYZ789";
    std::fs::write(&path, secret).unwrap();
    let path_lit = path.to_string_lossy().replace('\\', "/");
    (path, path_lit, secret)
}

fn policy_for(secret_path_lit: &str, out_path_lit: &str) -> Policy {
    let toml = format!(
        r#"
[filesystem]
local_only_read = ["{secret_path_lit}"]
write_allow = ["{out_path_lit}"]
"#
    );
    let file = PolicyFile::from_toml_str(&toml).unwrap();
    Policy::from_file(file, std::env::temp_dir()).unwrap()
}

fn script_for(secret_path_lit: &str, out_path_lit: &str) -> String {
    // Variable-arg fs.read so the pre-exec verifier's literal-arg-only
    // taint_flow check doesn't short-circuit before the runtime
    // outbound-taint gate (and its audit emission) fires.
    format!(
        r#"p = "{secret_path_lit}"
secret = fs.read(p)
fs.write("{out_path_lit}", secret)
"#
    )
}

fn assert_no_secret_leaked_in_audit(events: &[AuditEvent], secret: &str) {
    assert!(
        !events.is_empty(),
        "expected at least one audit event (the denied fs.write)"
    );
    for event in events {
        let serialized = serde_json::to_string(&event.detail).unwrap();
        assert!(
            !serialized.contains(secret),
            "raw secret leaked into an audit event: {serialized}"
        );
    }
}

#[test]
fn native_runner_scrubs_secret_from_denied_outbound_taint_audit_event() {
    let (secret_path, secret_path_lit, secret) = fixture();
    let out_path = std::env::temp_dir().join(format!(
        "denyx_audit_scrub_parity_out_native_{}.txt",
        std::process::id()
    ));
    let out_path_lit = out_path.to_string_lossy().replace('\\', "/");

    let policy = policy_for(&secret_path_lit, &out_path_lit);
    let cap = Arc::new(Capture::default());
    let runner = Runner::new(policy).with_audit(cap.clone());
    let src = script_for(&secret_path_lit, &out_path_lit);
    let result = runner.run("t1", &src, "test.star");
    let _ = std::fs::remove_file(&secret_path);
    let _ = std::fs::remove_file(&out_path);

    assert!(
        result.is_err(),
        "outbound taint refusal must deny the write"
    );
    assert_no_secret_leaked_in_audit(&cap.0.lock().unwrap(), secret);
}

#[test]
fn wasm_runner_scrubs_secret_from_denied_outbound_taint_audit_event() {
    let (secret_path, secret_path_lit, secret) = fixture();
    let out_path = std::env::temp_dir().join(format!(
        "denyx_audit_scrub_parity_out_wasm_{}.txt",
        std::process::id()
    ));
    let out_path_lit = out_path.to_string_lossy().replace('\\', "/");

    let policy = policy_for(&secret_path_lit, &out_path_lit);
    let cap = Arc::new(Capture::default());
    let runner = WasmRunner::new(policy).with_audit(cap.clone());
    let src = script_for(&secret_path_lit, &out_path_lit);
    let result = runner.run("t1", &src, "test.star");
    let _ = std::fs::remove_file(&secret_path);
    let _ = std::fs::remove_file(&out_path);

    assert!(
        result.is_err(),
        "outbound taint refusal must deny the write"
    );
    assert_no_secret_leaked_in_audit(&cap.0.lock().unwrap(), secret);
}
