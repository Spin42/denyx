//! AEG-PEN-R5-010: the OS sandbox only receives grants, so a denied
//! entry inside a granted prefix was readable by the child. The grants
//! handed to Landlock and bwrap must never cover a denied entry, while
//! the allowed rest of the prefix stays reachable.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use denyx_policy::{Policy, PolicyFile};

struct Fx(PathBuf);

impl Fx {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "denyx_r5_010_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("data/sub")).unwrap();
        std::fs::create_dir_all(root.join("data/secrets")).unwrap();
        std::fs::create_dir_all(root.join("data/out")).unwrap();
        std::fs::write(root.join("data/ok.txt"), "ok").unwrap();
        std::fs::write(root.join("data/.env"), "SECRET").unwrap();
        std::fs::write(root.join("data/sub/also_ok.txt"), "ok").unwrap();
        std::fs::write(root.join("data/sub/.env"), "SECRET").unwrap();
        std::fs::write(root.join("data/secrets/k"), "SECRET").unwrap();
        Fx(std::fs::canonicalize(root).unwrap())
    }

    fn policy(&self) -> Policy {
        let file = PolicyFile::from_toml_str(
            r#"
[filesystem]
read_allow = ["data/**"]
write_allow = ["data/sub/**", "data/out/**"]
deny = ["**/.env", "data/secrets/**"]
"#,
        )
        .unwrap();
        Policy::from_file(file, self.0.clone()).unwrap()
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn denied(fx: &Fx) -> Vec<PathBuf> {
    vec![
        fx.0.join("data/.env"),
        fx.0.join("data/sub/.env"),
        fx.0.join("data/secrets"),
        fx.0.join("data/secrets/k"),
    ]
}

fn covers(grant: &Path, target: &Path) -> bool {
    target.starts_with(grant)
}

#[test]
fn landlock_grants_never_cover_a_denied_entry() {
    let fx = Fx::new("landlock");
    let (read, write) = fx.policy().sandbox_fs_paths();
    for g in read.iter().chain(&write) {
        for d in denied(&fx) {
            assert!(!covers(g, &d), "grant {g:?} covers denied {d:?}");
        }
    }
    for allowed in ["data/ok.txt", "data/sub/also_ok.txt"] {
        let target = fx.0.join(allowed);
        assert!(
            read.iter().chain(&write).any(|g| covers(g, &target)),
            "allowed {target:?} is no longer reachable"
        );
    }
    // A writable dir holding no denied entry stays whole, so new files
    // can still be created in it.
    assert!(
        write.contains(&fx.0.join("data/out")),
        "a writable dir without denied entries was split: {write:?}"
    );
}

#[test]
fn bwrap_binds_never_cover_a_denied_entry() {
    let fx = Fx::new("bwrap");
    let argv = fx.policy().bwrap_argv(&["true".to_string()], &[]);
    let binds: Vec<PathBuf> = argv
        .windows(3)
        .filter(|w| w[0] == "--ro-bind-try" || w[0] == "--bind-try")
        .map(|w| PathBuf::from(&w[1]))
        .filter(|p| p.starts_with(&fx.0))
        .collect();
    for g in &binds {
        for d in denied(&fx) {
            assert!(!covers(g, &d), "bind {g:?} covers denied {d:?}");
        }
    }
    assert!(binds.iter().any(|g| covers(g, &fx.0.join("data/ok.txt"))));
}
