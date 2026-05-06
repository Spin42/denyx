//! Tests for the symlink canonicalization fix. The headline
//! property: a symlink under an allow-listed prefix that points
//! OUTSIDE the prefix is rejected by the policy check, because the
//! check sees the canonical target, not the symlink source.

#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::PathBuf;

use aegis_host::{AegisError, Runner};
use aegis_policy::{Policy, PolicyFile};

fn runner_for(toml: &str, root: PathBuf) -> Runner {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    let policy = Policy::from_file(file, root).unwrap();
    Runner::new(policy)
}

fn fresh_dir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "aegis_symlink_{}_{}_{}",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn fs_read_via_symlink_to_outside_target_is_blocked() {
    // Setup: <root>/src/secret is a symlink to a file outside <root>.
    // The policy allows reads under src/. The symlink path matches
    // read_allow lexically, but the canonical target doesn't, so the
    // read must be rejected.
    let root = fresh_dir("read_block");
    std::fs::create_dir_all(root.join("src")).unwrap();
    let outside = std::env::temp_dir().join(format!(
        "aegis_outside_target_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&outside, "secret content").unwrap();
    symlink(&outside, root.join("src/secret")).unwrap();

    let abs = root.to_string_lossy().replace('\\', "/");
    let toml = format!(
        r#"
[filesystem]
read_allow = ["{abs}/src/**"]
"#
    );
    let runner = runner_for(&toml, root.clone());
    let path_lit = root.join("src/secret").to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"x = fs.read("{path_lit}")
print(x)
"#
    );
    let err = runner.run("t", &src, "test.star").unwrap_err();
    assert!(
        matches!(err, AegisError::Policy(_)),
        "symlink target outside allow should be denied; got: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_file(&outside);
}

#[test]
fn fs_read_via_symlink_to_inside_target_is_permitted() {
    // Sanity: a symlink whose canonical target IS in read_allow
    // should still work after canonicalization.
    let root = fresh_dir("read_ok");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/real.txt"), "real content").unwrap();
    symlink(root.join("src/real.txt"), root.join("src/link.txt")).unwrap();

    let abs = root.to_string_lossy().replace('\\', "/");
    let toml = format!(
        r#"
[filesystem]
read_allow = ["{abs}/src/**"]
"#
    );
    let runner = runner_for(&toml, root.clone());
    let path_lit = root
        .join("src/link.txt")
        .to_string_lossy()
        .replace('\\', "/");
    let src = format!(
        r#"x = fs.read("{path_lit}")
print(x)
"#
    );
    let outcome = runner.run("t", &src, "test.star").unwrap();
    assert!(outcome.printed.iter().any(|l| l.contains("real content")));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fs_write_via_symlink_to_outside_target_is_blocked() {
    // Symlink at <root>/build/out is a symlink to /tmp/elsewhere/out.
    // write_allow covers build/, so a naive check would let
    // `fs.write("<root>/build/out", "x")` proceed — and the OS
    // would write through the symlink to /tmp/elsewhere/out. The
    // canonicalization fix resolves the symlink first; the write
    // is checked against /tmp/elsewhere/out which isn't in any
    // allow list.
    let root = fresh_dir("write_block");
    std::fs::create_dir_all(root.join("build")).unwrap();
    let outside_dir = std::env::temp_dir().join(format!(
        "aegis_outside_write_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&outside_dir).unwrap();
    let outside_target = outside_dir.join("out");
    // Pre-create so the symlink target exists for canonicalization.
    std::fs::write(&outside_target, "").unwrap();
    symlink(&outside_target, root.join("build/out")).unwrap();

    let abs = root.to_string_lossy().replace('\\', "/");
    let toml = format!(
        r#"
[filesystem]
write_allow = ["{abs}/build/**"]
"#
    );
    let runner = runner_for(&toml, root.clone());
    let path_lit = root.join("build/out").to_string_lossy().replace('\\', "/");
    let src = format!(
        r#"fs.write("{path_lit}", "should-not-write")
"#
    );
    let err = runner.run("t", &src, "test.star").unwrap_err();
    assert!(
        matches!(err, AegisError::Policy(_)),
        "symlink-redirected write must be denied; got: {err:?}"
    );
    // Confirm the outside file wasn't actually overwritten.
    let outside_content = std::fs::read_to_string(&outside_target).unwrap();
    assert_eq!(
        outside_content, "",
        "outside file should not have been touched"
    );

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside_dir);
}

#[test]
fn fs_write_to_new_file_in_allowed_dir_still_works() {
    // Sanity: writing a NEW file (path doesn't exist yet) inside an
    // allowed directory must still work. Canonicalization falls
    // back to canonicalizing the existing parent + appending the
    // new leaf.
    let root = fresh_dir("write_new");
    std::fs::create_dir_all(root.join("build")).unwrap();

    let abs = root.to_string_lossy().replace('\\', "/");
    let toml = format!(
        r#"
[filesystem]
write_allow = ["{abs}/build/**"]
"#
    );
    let runner = runner_for(&toml, root.clone());
    let path_lit = root
        .join("build/new.txt")
        .to_string_lossy()
        .replace('\\', "/");
    let src = format!(
        r#"fs.write("{path_lit}", "ok")
"#
    );
    runner.run("t", &src, "test.star").unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("build/new.txt")).unwrap(),
        "ok"
    );
    let _ = std::fs::remove_dir_all(&root);
}
