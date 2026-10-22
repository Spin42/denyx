//! Regression test for the pentest finding that `find`'s
//! filesystem-mutating primaries bypassed the capability gates.
//!
//! `secure-defaults` previously denied only `find -exec`/`-execdir`,
//! leaving `-delete` (unlink) and `-fprintf`/`-fls` (write) free to
//! mutate the filesystem through find's own syscalls, outside
//! `[filesystem].delete_allow`/`write_allow`. The preset must now deny
//! every such primary while leaving read-only ones (`-print`, `-ls`)
//! usable.

use denyx_policy::{Policy, PolicyFile};

fn secure_defaults_policy() -> Policy {
    let file = PolicyFile::from_toml_str(
        r#"
inherits = 'secure-defaults'
name = 'find-deny-args-regression'
[subprocess]
allow_commands = ['find']
"#,
    )
    .expect("parse policy")
    .resolve_inheritance()
    .expect("resolve inheritance");
    Policy::from_file(file, std::path::PathBuf::from("/tmp")).expect("build policy")
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[test]
fn find_filesystem_mutating_primaries_are_denied() {
    let policy = secure_defaults_policy();
    for bad in [
        vec!["find", ".", "-delete"],
        vec!["find", ".", "-exec", "sh", "-c", "id", ";"],
        vec!["find", ".", "-execdir", "sh", "-c", "id", ";"],
        vec!["find", ".", "-fprintf", "/tmp/x", "%p"],
        vec!["find", ".", "-fprint", "/tmp/x"],
        vec!["find", ".", "-fls", "/tmp/x"],
        vec!["find", ".", "-ok", "rm", "{}", ";"],
    ] {
        assert!(
            policy.check_subprocess_args(&argv(&bad)).is_err(),
            "expected `find {:?}` to be denied by secure-defaults deny_args",
            bad
        );
    }
}

#[test]
fn find_read_only_primaries_are_allowed() {
    let policy = secure_defaults_policy();
    for ok in [
        vec!["find", ".", "-print"],
        vec!["find", ".", "-printf", "%p"],
        vec!["find", ".", "-ls"],
        vec!["find", ".", "-name", "x"],
    ] {
        assert!(
            policy.check_subprocess_args(&argv(&ok)).is_ok(),
            "expected read-only `find {:?}` to be allowed",
            ok
        );
    }
}
