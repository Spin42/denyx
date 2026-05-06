#![no_main]
//! Fuzz target for the pre-execution verifier's string/comment stripper
//! and capability scanner. Goal: no panic, no unwind, no infinite loop
//! on any input — even malformed UTF-8 sequences, unbalanced quotes,
//! truncated triple-quoted strings, mixed `#` / `'` / `"` regions.
//!
//! Run with nightly: `cargo +nightly fuzz run verifier`.

use libfuzzer_sys::fuzz_target;

use aegis_host::verifier::verify;
use aegis_policy::{Policy, PolicyFile};

fn empty_policy() -> Policy {
    let file = PolicyFile::from_toml_str("").unwrap();
    Policy::from_file(file, std::path::PathBuf::from("/tmp")).unwrap()
}

fuzz_target!(|data: &[u8]| {
    // The verifier accepts &str. Anything that isn't valid UTF-8 is the
    // parser's problem (which we drive separately); the scanner itself
    // operates on the byte buffer of a String, so we feed it lossy.
    let s = String::from_utf8_lossy(data).into_owned();
    let policy = empty_policy();
    // We don't care about the result — only that we don't panic.
    let _ = verify(&s, &policy);
});
