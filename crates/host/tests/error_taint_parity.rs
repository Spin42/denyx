//! Local-only bytes must never leave either runner through an error.
//!
//! - AEG-PEN-R5-005: a tainted value passed as the argument of a denied
//!   call is echoed in the denial message; the message must be scrubbed.
//! - AEG-PEN-R5-006: a `local_only_commands` child's stderr is just as
//!   local-only as its stdout and must be tainted before it reaches the
//!   non-zero-exit error.

#![cfg(unix)]

use std::path::PathBuf;

use denyx_host::{DenyxError, RunOutcome, Runner, WasmRunner};
use denyx_policy::{Policy, PolicyFile};

const SECRET: &str = "R5canaryLOCALONLY987";

struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "denyx_r5_err_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(p.join("lo")).unwrap();
        std::fs::create_dir_all(p.join("data")).unwrap();
        std::fs::write(p.join("lo/key.txt"), SECRET).unwrap();
        std::fs::write(p.join("data/token.txt"), SECRET).unwrap();
        Root(p)
    }

    fn policy(&self, toml: &str) -> Policy {
        let file = PolicyFile::from_toml_str(toml)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        Policy::from_file(file, self.0.clone()).unwrap()
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_both(
    root: &Root,
    toml: &str,
    script: &str,
) -> Vec<(&'static str, Result<RunOutcome, DenyxError>)> {
    vec![
        (
            "native",
            Runner::new(root.policy(toml)).run("t", script, "test.star"),
        ),
        (
            "wasm",
            WasmRunner::new(root.policy(toml)).run("t", script, "test.star"),
        ),
    ]
}

fn rendered(r: &Result<RunOutcome, DenyxError>) -> String {
    match r {
        Ok(o) => o.printed.join("\n"),
        Err(e) => format!("{e} | {e:?}"),
    }
}

#[test]
fn tainted_argument_of_denied_fs_read_is_scrubbed_from_error() {
    let root = Root::new("fsarg");
    let toml = r#"
[filesystem]
read_allow = ["lo/**"]
local_only_read = ["lo/**"]
"#;
    let script = r#"s = fs.read("/".join(["lo", "key.txt"]))
fs.read(s)"#;
    for (name, r) in run_both(&root, toml, script) {
        assert!(r.is_err(), "{name}: second read should be denied");
        assert!(
            !rendered(&r).contains(SECRET),
            "{name}: local-only value leaked through the denial message: {}",
            rendered(&r)
        );
    }
}

#[test]
fn local_only_command_stderr_is_scrubbed_from_nonzero_exit_error() {
    let root = Root::new("stderr");
    let toml = r#"
[filesystem]
read_allow = ["data/**"]
[subprocess]
allow_commands = ["date"]
local_only_commands = ["date"]
"#;
    let token = root.0.join("data/token.txt");
    let script = format!(
        "subprocess.exec([\"date\", \"-f\", {:?}])",
        token.to_string_lossy()
    );
    for (name, r) in run_both(&root, toml, &script) {
        assert!(
            r.is_err(),
            "{name}: date -f on a non-date should exit non-zero"
        );
        assert!(
            !rendered(&r).contains(SECRET),
            "{name}: local-only command stderr leaked: {}",
            rendered(&r)
        );
    }
}
