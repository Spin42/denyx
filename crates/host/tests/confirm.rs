//! Tests for `requires_approval` plumbing through the embedded host.
//! Uses a recording `ConfirmHook` to assert which capabilities asked
//! for confirmation, in what order, with what summary.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aegis_host::{AegisError, ConfirmDecision, ConfirmHook, ConfirmRequest, Runner};
use aegis_policy::{Policy, PolicyFile};

struct Recording {
    seen: Mutex<Vec<(String, String)>>,
    answer: ConfirmDecision,
}
impl ConfirmHook for Recording {
    fn confirm(&self, req: &ConfirmRequest) -> ConfirmDecision {
        self.seen
            .lock()
            .unwrap()
            .push((req.capability.clone(), req.summary.clone()));
        self.answer
    }
}

fn make(toml: &str, answer: ConfirmDecision) -> (Runner, Arc<Recording>) {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, std::env::temp_dir()).unwrap();
    let hook = Arc::new(Recording {
        seen: Mutex::new(Vec::new()),
        answer,
    });
    let runner = Runner::new(policy).with_confirm_hook(hook.clone());
    (runner, hook)
}

#[test]
fn requires_approval_fires_on_listed_capability() {
    let toml = r#"
requires_approval = ["fs.delete"]

[filesystem]
write_allow  = ["/tmp/aegis_confirm_test/**"]
delete_allow = ["/tmp/aegis_confirm_test/**"]
"#;
    let (runner, hook) = make(toml, ConfirmDecision::Allow);
    std::fs::create_dir_all("/tmp/aegis_confirm_test").unwrap();
    std::fs::write("/tmp/aegis_confirm_test/x", "").unwrap();

    let src = r#"fs.delete("/tmp/aegis_confirm_test/x")"#;
    runner.run("t", src, "test.star").unwrap();

    let seen = hook.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "exactly one confirm call expected: {seen:?}");
    assert_eq!(seen[0].0, "fs.delete");
    assert!(seen[0].1.contains("/tmp/aegis_confirm_test/x"));
}

#[test]
fn requires_approval_does_not_fire_on_unlisted_capability() {
    // fs.write is NOT in requires_approval, so the hook should never
    // be called even though the script does a write.
    let toml = r#"
requires_approval = ["fs.delete"]

[filesystem]
write_allow = ["/tmp/aegis_confirm_test/**"]
"#;
    let (runner, hook) = make(toml, ConfirmDecision::Deny);
    std::fs::create_dir_all("/tmp/aegis_confirm_test").unwrap();

    let src = r#"fs.write("/tmp/aegis_confirm_test/y", "ok")"#;
    runner.run("t", src, "test.star").unwrap();

    assert!(hook.seen.lock().unwrap().is_empty());
}

#[test]
fn deny_decision_surfaces_as_typed_error() {
    let toml = r#"
requires_approval = ["fs.delete"]

[filesystem]
delete_allow = ["/tmp/aegis_confirm_test/**"]
"#;
    let (runner, hook) = make(toml, ConfirmDecision::Deny);
    std::fs::create_dir_all("/tmp/aegis_confirm_test").unwrap();
    std::fs::write("/tmp/aegis_confirm_test/z", "").unwrap();

    let err = runner
        .run(
            "t",
            r#"fs.delete("/tmp/aegis_confirm_test/z")"#,
            "test.star",
        )
        .unwrap_err();
    match err {
        AegisError::ConfirmDenied(cap) => assert_eq!(cap, "fs.delete"),
        other => panic!("expected ConfirmDenied, got: {other:?}"),
    }
    // Hook was actually called.
    assert_eq!(hook.seen.lock().unwrap().len(), 1);
    // File still exists — denial happened before delete.
    assert!(std::path::Path::new("/tmp/aegis_confirm_test/z").exists());
    let _ = std::fs::remove_file("/tmp/aegis_confirm_test/z");
}

#[test]
fn confirm_request_summary_includes_resource() {
    // The summary surfaced to the hook should be useful for a UI
    // prompt — name the resource the call is acting on.
    let toml = r#"
requires_approval = ["subprocess.exec"]

[subprocess]
allow_commands = ["true"]
"#;
    let (runner, hook) = make(toml, ConfirmDecision::Allow);
    let _ = runner.run("t", r#"subprocess.exec(["true"])"#, "test.star");
    let seen = hook.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "subprocess.exec");
    assert!(
        seen[0].1.contains("true"),
        "summary should name the command: {:?}",
        seen[0]
    );
}

#[test]
fn pure_policy_requires_approval() {
    // Direct check that Policy::requires_approval reads the field
    // correctly, so embedders building their own ConfirmHook can
    // pre-classify capabilities.
    let toml = r#"
requires_approval = ["fs.delete", "subprocess.exec"]
"#;
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let p = Policy::from_file(file, PathBuf::from("/")).unwrap();
    assert!(p.requires_approval("fs.delete"));
    assert!(p.requires_approval("subprocess.exec"));
    assert!(!p.requires_approval("fs.read"));
}
