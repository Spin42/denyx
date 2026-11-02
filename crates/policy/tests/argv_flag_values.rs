//! AEG-PEN-R5-018: a path attached to a flag (`--out=/x`, `-o/x`) is
//! as much a path argument as a bare one and must pass the same gate.

use std::path::PathBuf;

use denyx_policy::{Policy, PolicyFile};

fn build() -> Policy {
    let file = PolicyFile::from_toml_str(
        r#"
[filesystem]
read_allow = ["src/**"]
write_allow = ["out/**"]
[subprocess]
allow_commands = ["cp", "tool", "git"]
"#,
    )
    .unwrap();
    Policy::from_file(file, PathBuf::from("/work")).unwrap()
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn path_in_long_option_value_is_gated() {
    let p = build();
    for a in [
        &["cp", "--target-directory=/etc/cron.d", "src/a"][..],
        &["tool", "--output=../outside/x"],
        &["tool", "--config=~/.ssh/config"],
    ] {
        assert!(
            p.check_subprocess_argv_paths(&argv(a)).is_err(),
            "{a:?} must be denied"
        );
    }
}

#[test]
fn path_attached_to_short_option_is_gated() {
    let p = build();
    assert!(p
        .check_subprocess_argv_paths(&argv(&["tool", "-o/etc/x"]))
        .is_err());
}

#[test]
fn allowed_paths_and_non_path_values_pass() {
    let p = build();
    for a in [
        &["tool", "--output=./out/report.txt"][..],
        &["tool", "-o/work/out/x"],
        &["git", "log", "--format=%H/%s"],
        &["tool", "-n1"],
    ] {
        assert!(
            p.check_subprocess_argv_paths(&argv(a)).is_ok(),
            "{a:?} must be allowed"
        );
    }
}
