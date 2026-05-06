#![no_main]
//! Fuzz target for the glob-pattern compilation + path-matching
//! pipeline. Drives a synthesised policy whose allow/deny lists are
//! taken directly from the fuzz input, then feeds the same bytes back
//! as a path to check. Goal: every check_fs_* path returns Ok or a
//! typed PolicyError; nothing panics.
//!
//! Run with nightly: `cargo +nightly fuzz run policy_globs`.

use libfuzzer_sys::fuzz_target;

use aegis_policy::{Policy, PolicyFile};
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Cap at 4 KiB — beyond that the input rarely yields useful new
    // structure and the glob compiler can pathologically blow up,
    // which is its own concern but masks parser-level bugs.
    if s.len() > 4096 {
        return;
    }
    // Embed the input as both a glob pattern and the path it's matched
    // against. We pick the FIRST line as the pattern and the SECOND as
    // the path; missing lines fall back to defaults.
    let mut lines = s.lines();
    let pattern = lines.next().unwrap_or("**").to_string();
    let path = lines.next().unwrap_or("a.txt").to_string();

    let toml = format!(
        r#"
[filesystem]
read_allow = ["{}"]
write_allow = ["{}"]
delete_allow = ["{}"]
"#,
        // TOML doesn't tolerate raw quotes / backslashes inside basic
        // strings. Use a literal-string conversion: escape backslashes
        // and double-quotes in the simplest way. Any pattern that
        // doesn't survive this sanitisation is just dropped — the
        // fuzzer will explore other shapes.
        sanitize(&pattern),
        sanitize(&pattern),
        sanitize(&pattern),
    );
    let Ok(file) = PolicyFile::from_toml_str(&toml) else {
        return;
    };
    let Ok(policy) = Policy::from_file(file, std::path::PathBuf::from("/tmp/aegis_fuzz")) else {
        return;
    };
    let p = Path::new(&path);
    let _ = policy.check_fs_read(p);
    let _ = policy.check_fs_write(p);
    let _ = policy.check_fs_delete(p);
});

fn sanitize(s: &str) -> String {
    s.replace('\\', "/").replace('"', "'").replace('\n', " ")
}
