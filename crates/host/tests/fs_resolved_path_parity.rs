//! AEG-PEN-R5-001: every `fs.*` capability must perform its IO (and its
//! local-only taint decision) on the policy-resolved path, never on the
//! raw string the script passed. `resolve_path` collapses `..`
//! lexically, so `<dirlink>/../x` is gated as `<parent-of-dirlink>/x`
//! while the kernel would resolve it as `<target-of-dirlink>/../x`.
//! Both runners must act on the gated path.

#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::PathBuf;

use denyx_host::{DenyxError, RunOutcome, Runner, WasmRunner};
use denyx_policy::{Policy, PolicyFile};

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    outside: PathBuf,
}

impl Fixture {
    /// `<base>/root/work/dirlink -> <base>/outside/dir`, so
    /// `work/dirlink/..` is `<base>/outside` to the kernel and
    /// `<base>/root/work` to the lexical gate.
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "denyx_r5_001_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("work")).unwrap();
        std::fs::create_dir_all(root.join("lo")).unwrap();
        std::fs::create_dir_all(outside.join("dir")).unwrap();
        std::fs::write(outside.join("secret.txt"), "OUTSIDE_SECRET").unwrap();
        std::fs::write(outside.join("victim.txt"), "victim").unwrap();
        std::fs::write(root.join("lo/key.txt"), "LOCAL_ONLY_SECRET").unwrap();
        symlink(outside.join("dir"), root.join("work/dirlink")).unwrap();
        Fixture {
            base,
            root,
            outside,
        }
    }

    fn policy(&self) -> Policy {
        let toml = r#"
[filesystem]
read_allow = ["work/**", "lo/**"]
write_allow = ["work/**"]
delete_allow = ["work/**"]
local_only_read = ["lo/**"]
"#;
        let file = PolicyFile::from_toml_str(toml)
            .unwrap()
            .resolve_inheritance()
            .unwrap();
        Policy::from_file(file, self.root.clone()).unwrap()
    }

    fn abs(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn run_both(fx: &Fixture, script: &str) -> [(&'static str, Result<RunOutcome, DenyxError>); 2] {
    [
        ("native", run_one("native", fx, script)),
        ("wasm", run_one("wasm", fx, script)),
    ]
}

fn run_one(runner: &str, fx: &Fixture, script: &str) -> Result<RunOutcome, DenyxError> {
    match runner {
        "native" => Runner::new(fx.policy()).run("t", script, "test.star"),
        _ => WasmRunner::new(fx.policy()).run("t", script, "test.star"),
    }
}

fn printed(r: &Result<RunOutcome, DenyxError>) -> String {
    match r {
        Ok(o) => o.printed.join("\n"),
        Err(e) => format!("{e}"),
    }
}

#[test]
fn read_through_dirlink_dotdot_never_reaches_symlink_target_parent() {
    let fx = Fixture::new("read");
    let p = fx.abs("work/dirlink/../secret.txt");
    let script = format!("print(fs.read({p:?}))");
    for (name, r) in run_both(&fx, &script) {
        assert!(
            !printed(&r).contains("OUTSIDE_SECRET"),
            "{name}: read escaped the allow-list through dirlink/..: {r:?}"
        );
    }
}

#[test]
fn read_range_through_dirlink_dotdot_never_reaches_symlink_target_parent() {
    let fx = Fixture::new("range");
    let p = fx.abs("work/dirlink/../secret.txt");
    let script = format!("print(fs.read_range({p:?}, 0, 64))");
    for (name, r) in run_both(&fx, &script) {
        assert!(
            !printed(&r).contains("OUTSIDE_SECRET"),
            "{name}: read_range escaped the allow-list through dirlink/..: {r:?}"
        );
    }
}

#[test]
fn write_through_dirlink_dotdot_never_creates_file_outside_root() {
    for name in ["native", "wasm"] {
        let fx = Fixture::new("write");
        let p = fx.abs("work/dirlink/../planted.txt");
        let _ = run_one(name, &fx, &format!("fs.write({p:?}, \"PLANTED\")"));
        assert!(
            !fx.outside.join("planted.txt").exists(),
            "{name}: write escaped write_allow through dirlink/.."
        );
    }
}

#[test]
fn delete_through_dirlink_dotdot_never_removes_file_outside_root() {
    for name in ["native", "wasm"] {
        let fx = Fixture::new("delete");
        let p = fx.abs("work/dirlink/../victim.txt");
        let _ = run_one(name, &fx, &format!("fs.delete({p:?})"));
        assert!(
            fx.outside.join("victim.txt").exists(),
            "{name}: delete escaped delete_allow through dirlink/.."
        );
    }
}

#[test]
fn relative_path_resolves_against_policy_root_not_process_cwd() {
    let fx = Fixture::new("rel");
    std::fs::write(fx.root.join("work/notes.txt"), "IN_ROOT").unwrap();
    let script = r#"print(fs.read("work/notes.txt"))"#;
    for (name, r) in run_both(&fx, script) {
        assert_eq!(
            printed(&r),
            "IN_ROOT",
            "{name}: relative read did not resolve against the policy root"
        );
    }
    assert_ne!(
        std::env::current_dir().unwrap(),
        fx.root,
        "fixture precondition: process cwd must differ from policy root"
    );
}

#[test]
fn relative_local_only_read_is_tainted() {
    let fx = Fixture::new("taint");
    let script = r#"p = "/".join(["lo", "key.txt"])
print(fs.read(p))"#;
    for (name, r) in run_both(&fx, script) {
        let out = printed(&r);
        assert!(
            !out.contains("LOCAL_ONLY_SECRET") && out.contains("[REDACTED]"),
            "{name}: relative local-only read was not read-and-redacted: {r:?}"
        );
    }
}
