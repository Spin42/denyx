//! AEG-PEN-R5-012: a symlink that does not (yet) resolve must be
//! checked as the path the kernel will create through it, not as the
//! link's own name. Otherwise `fs.write` follows it with O_CREAT and
//! lands outside `write_allow`.

#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::PathBuf;

use denyx_policy::{Policy, PolicyFile};

struct Fx {
    base: PathBuf,
    root: PathBuf,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "denyx_r5_012_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("root");
        std::fs::create_dir_all(root.join("work")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        Fx { base, root }
    }

    fn policy(&self) -> Policy {
        let file = PolicyFile::from_toml_str(
            r#"
[filesystem]
read_allow = ["work/**"]
write_allow = ["work/**"]
"#,
        )
        .unwrap();
        Policy::from_file(file, self.root.clone()).unwrap()
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn dangling_leaf_pointing_outside_is_denied_for_write() {
    let fx = Fx::new("leaf");
    symlink(
        fx.base.join("outside/new.txt"),
        fx.root.join("work/dangling"),
    )
    .unwrap();
    let r = fx.policy().check_fs_write(&fx.root.join("work/dangling"));
    assert!(r.is_err(), "write through dangling link was allowed: {r:?}");
}

#[test]
fn relative_dangling_leaf_pointing_outside_is_denied_for_write() {
    let fx = Fx::new("relleaf");
    symlink("../../outside/new.txt", fx.root.join("work/dangling")).unwrap();
    let r = fx.policy().check_fs_write(&fx.root.join("work/dangling"));
    assert!(
        r.is_err(),
        "write through relative dangling link was allowed: {r:?}"
    );
}

#[test]
fn dangling_directory_component_pointing_outside_is_denied_for_write() {
    let fx = Fx::new("dir");
    symlink(fx.base.join("outside/newdir"), fx.root.join("work/dl")).unwrap();
    let r = fx.policy().check_fs_write(&fx.root.join("work/dl/x.txt"));
    assert!(
        r.is_err(),
        "write through dangling dir link was allowed: {r:?}"
    );
}

#[test]
fn dangling_leaf_pointing_inside_resolves_to_its_target() {
    let fx = Fx::new("inside");
    symlink(fx.root.join("work/real.txt"), fx.root.join("work/alias")).unwrap();
    let resolved = fx
        .policy()
        .check_fs_write(&fx.root.join("work/alias"))
        .expect("in-tree dangling link should be writable");
    assert_eq!(
        resolved.file_name().and_then(|s| s.to_str()),
        Some("real.txt")
    );
}

#[test]
fn symlink_loop_is_not_followed_forever() {
    let fx = Fx::new("loop");
    symlink(fx.root.join("work/b"), fx.root.join("work/a")).unwrap();
    symlink(fx.root.join("work/a"), fx.root.join("work/b")).unwrap();
    let _ = fx.policy().check_fs_write(&fx.root.join("work/a"));
}
