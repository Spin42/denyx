//! AEG-PEN-R5-020: the argv path gate resolves a bare-name argument
//! against the policy root, so the child must run there too. Otherwise
//! the gate checks one file and the child opens another.

#![cfg(unix)]

use std::path::PathBuf;

use denyx_host::{DenyxError, RunOutcome, Runner, WasmRunner};
use denyx_policy::{Policy, PolicyFile};

struct Root(PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn policy(root: &Root) -> Policy {
    let file = PolicyFile::from_toml_str(
        r#"
requires_approval = []
[filesystem]
read_allow = ["notes.txt"]
[subprocess]
sandbox = "none"
allow_commands = ["cat"]
"#,
    )
    .unwrap();
    Policy::from_file(file, root.0.clone()).unwrap()
}

fn printed(r: &Result<RunOutcome, DenyxError>) -> String {
    match r {
        Ok(o) => o.printed.join("\n"),
        Err(e) => format!("{e}"),
    }
}

#[test]
fn child_runs_in_the_policy_root() {
    let root = Root(std::env::temp_dir().join(format!(
        "denyx_r5_020_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir_all(&root.0).unwrap();
    std::fs::write(root.0.join("notes.txt"), "ROOT_NOTES").unwrap();
    assert_ne!(std::env::current_dir().unwrap(), root.0);

    let script = r#"print(subprocess.exec(["cat", "notes.txt"]).strip())"#;
    for (name, r) in [
        (
            "native",
            Runner::new(policy(&root)).run("t", script, "test.star"),
        ),
        (
            "wasm",
            WasmRunner::new(policy(&root)).run("t", script, "test.star"),
        ),
    ] {
        assert_eq!(
            printed(&r),
            "ROOT_NOTES",
            "{name}: child did not run in the policy root"
        );
    }
}
