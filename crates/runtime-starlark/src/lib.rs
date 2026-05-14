//! Pre-built wasm32-wasip1 Starlark interpreter for denyx.
//!
//! Exposes the `.wasm` artefact built from the (non-published)
//! `denyx-interpreter` crate as a byte slice. Consumers (currently
//! `denyx-host` / `denyx-cli` from Phase 5 onward) load it into
//! wasmtime, instantiate with their import set, and run gated
//! Starlark scripts inside the sandbox.
//!
//! This crate is the distribution form of the Starlark interpreter.
//! End users do not need the `wasm32-wasip1` Rust target installed —
//! the .wasm ships pre-built in this crate.
//!
//! See `README.md` for reproducibility: the .wasm is build-from-source
//! at the same git tag as this crate's version.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

/// The pre-compiled Starlark interpreter, as a `wasm32-wasip1` module.
///
/// Hand this to `wasmtime::Module::new(&engine, STARLARK_INTERPRETER_WASM)`.
pub const STARLARK_INTERPRETER_WASM: &[u8] = include_bytes!("../starlark_interpreter.wasm");

/// Version of the upstream `starlark` crate the interpreter was built
/// against. Set by `build.rs` from the `STARLARK_VERSION` env var;
/// defaults to `"dev"` when unset (local dev builds).
pub const STARLARK_VERSION: &str = env!("STARLARK_VERSION");

/// Timestamp (or label) recording when the `.wasm` was built. Set by
/// `build.rs` from the `INTERPRETER_BUILT_AT` env var; CI exports the
/// release timestamp, local dev builds get `"dev"`.
pub const INTERPRETER_BUILT_AT: &str = env!("INTERPRETER_BUILT_AT");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_byte_slice_is_non_empty_and_starts_with_magic() {
        assert!(!STARLARK_INTERPRETER_WASM.is_empty(), "wasm slice is empty");
        // wasm binary magic: 0x00 0x61 0x73 0x6d, then version 0x01 0x00 0x00 0x00
        assert_eq!(
            &STARLARK_INTERPRETER_WASM[..8],
            &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            "wasm magic bytes missing — artefact is not a valid Wasm module"
        );
    }
}
