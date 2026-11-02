//! AEG-PEN-R5-003: a short-flag `deny_args` entry such as `-c` must
//! also catch that flag inside a combined short-option cluster
//! (`-Ic`, `-lc`, `-ec`), which shells and interpreters accept.

use std::path::PathBuf;

use denyx_policy::{Policy, PolicyFile};

fn build(toml: &str) -> Policy {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    Policy::from_file(file, PathBuf::from("/tmp")).unwrap()
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

const POLICY: &str = r#"
[subprocess]
allow_commands = ["python3", "bash", "sh"]
[subprocess.deny_args]
python3 = ["-c"]
bash = ["-c"]
sh = ["-c"]
"#;

#[test]
fn short_flag_inside_cluster_is_denied() {
    let p = build(POLICY);
    for a in [
        &["python3", "-Ic", "print(1)"][..],
        &["bash", "-lc", "id"],
        &["sh", "-ec", "id"],
        &["bash", "-xc", "id"],
    ] {
        assert!(
            p.check_subprocess_args(&argv(a)).is_err(),
            "{a:?} must be denied"
        );
    }
}

#[test]
fn short_flag_inside_cluster_still_requires_approval() {
    let p = build(
        r#"
[subprocess]
allow_commands = ["bash"]
[subprocess.requires_approval_args]
bash = ["-c"]
"#,
    );
    assert_eq!(
        p.subprocess_argv_requires_approval(&argv(&["bash", "-lc", "id"])),
        Some("-c")
    );
}

#[test]
fn long_options_and_unrelated_clusters_are_not_denied() {
    let p = build(POLICY);
    for a in [
        &["python3", "-I", "script.py"][..],
        &["bash", "--norc", "script.sh"],
        &["bash", "-x", "script.sh"],
    ] {
        assert!(
            p.check_subprocess_args(&argv(a)).is_ok(),
            "{a:?} must be allowed"
        );
    }
}
