//! AEG-PEN-R5-019: a subprocess argument passes the path gate when it
//! matches ANY allow list, read_allow included, because the gate cannot
//! tell whether the binary reads or writes it. The loaded policy file
//! itself is never a valid subprocess argument: `cp evil.toml
//! policy.toml` would replace the rules the next run loads.

#![cfg(unix)]

use std::path::PathBuf;

use denyx_policy::Policy;

struct Root(PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn loaded_policy_file_is_never_a_subprocess_argument() {
    let root = Root(std::env::temp_dir().join(format!(
        "denyx_r5_019_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir_all(root.0.join("out")).unwrap();
    let path = root.0.join("policy.toml");
    std::fs::write(
        &path,
        r#"
[filesystem]
read_allow = ["*.toml"]
write_allow = ["out/**"]
[subprocess]
allow_commands = ["cp"]
"#,
    )
    .unwrap();
    let p = Policy::load(&path).unwrap();

    for a in [
        &["cp", "out/evil.toml", "policy.toml"][..],
        &["cp", "out/evil.toml", "./policy.toml"],
        &["cp", "out/evil.toml", path.to_str().unwrap()],
        &["cp", "--target-directory=./out", "./policy.toml"],
    ] {
        assert!(
            p.check_subprocess_argv_paths(&argv(a)).is_err(),
            "{a:?} must be denied"
        );
    }
    assert!(p
        .check_subprocess_argv_paths(&argv(&["cp", "./other.toml", "out/x"]))
        .is_ok());
}
