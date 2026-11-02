//! A pattern written as `./X` names X relative to the policy root, the
//! form `examples/denyx-setup-prompt.md` tells agents to use for memory
//! files. It must match the resolved path, and stay anchored at the
//! root rather than matching an X anywhere below it.

use std::path::{Path, PathBuf};

use denyx_policy::{Policy, PolicyFile};

fn build(toml: &str) -> Policy {
    let file = PolicyFile::from_toml_str(toml).unwrap();
    Policy::from_file(file, PathBuf::from("/work")).unwrap()
}

#[test]
fn dot_slash_patterns_match_paths_under_the_root() {
    let p = build(
        r#"
[filesystem]
read_allow = ["./CLAUDE.md", "./src/**"]
write_allow = ["./.claude/CLAUDE.md"]
"#,
    );
    assert!(p.check_fs_read(Path::new("/work/CLAUDE.md")).is_ok());
    assert!(p.check_fs_read(Path::new("/work/src/lib.rs")).is_ok());
    assert!(p
        .check_fs_write(Path::new("/work/.claude/CLAUDE.md"))
        .is_ok());
}

#[test]
fn dot_slash_bare_name_stays_anchored_at_the_root() {
    let p = build(
        r#"
[filesystem]
read_allow = ["./CLAUDE.md"]
"#,
    );
    assert!(p.check_fs_read(Path::new("/work/sub/CLAUDE.md")).is_err());
}
