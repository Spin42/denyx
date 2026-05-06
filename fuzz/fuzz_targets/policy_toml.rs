#![no_main]
//! Fuzz target for the TOML deserializer + policy resolver. Goal: no
//! panic on any input, even when the bytes happen to parse as TOML
//! that violates Denyx's structural assumptions (deeply nested arrays,
//! pathological string sizes, exotic glob patterns, missing fields,
//! invalid CIDR / URL host literals).
//!
//! Run with nightly: `cargo +nightly fuzz run policy_toml`.

use libfuzzer_sys::fuzz_target;

use denyx_policy::{Policy, PolicyFile};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Step 1: TOML parse. Errors are fine; panics are not.
    let Ok(file) = PolicyFile::from_toml_str(s) else {
        return;
    };
    // Step 2: resolve into a Policy (compiles globsets, parses CIDRs,
    // applies inheritance). Errors fine; panics not.
    let _ = Policy::from_file(file, std::path::PathBuf::from("/tmp/denyx_fuzz"));
});
