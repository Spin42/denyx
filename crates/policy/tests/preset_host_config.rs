//! AEG-PEN-R5-016: files an agent host or git executes or trusts on the
//! next session must stay out of reach under secure-defaults, even with
//! a broad write grant: writing them widens the next session's tools,
//! permissions or hooks.

use std::path::{Path, PathBuf};

use denyx_policy::{Policy, PolicyFile};

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/x"))
}

#[test]
fn secure_defaults_denies_host_and_hook_configuration() {
    let file = PolicyFile::from_toml_str(
        r#"
inherits = "secure-defaults"
[filesystem]
read_allow = ["**"]
write_allow = ["**"]
"#,
    )
    .unwrap()
    .resolve_inheritance()
    .unwrap();
    let p = Policy::from_file(file, PathBuf::from("/work")).unwrap();
    let targets = [
        PathBuf::from("/work/.mcp.json"),
        PathBuf::from("/work/sub/.mcp.json"),
        PathBuf::from("/work/.claude/settings.local.json"),
        PathBuf::from("/work/opencode.json"),
        PathBuf::from("/work/.git/hooks/pre-commit"),
        home().join(".claude/settings.json"),
        home().join(".config/opencode/opencode.json"),
    ];
    for t in &targets {
        assert!(
            p.check_fs_write(Path::new(t)).is_err(),
            "secure-defaults allowed writing {t:?}"
        );
    }
    assert!(p.check_fs_write(Path::new("/work/src/main.rs")).is_ok());
}
