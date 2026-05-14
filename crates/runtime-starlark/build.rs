// Build script for denyx-runtime-starlark.
//
// 1. Validate that the `.wasm` artefact is present. If not, emit a
//    friendly error pointing the developer at the stage script.
// 2. Forward `STARLARK_VERSION` and `INTERPRETER_BUILT_AT` env vars
//    through to compile-time `env!()` constants via cargo:rustc-env.

use std::path::Path;

fn main() {
    let wasm_path = "starlark_interpreter.wasm";
    if !Path::new(wasm_path).exists() {
        panic!(
            "{}",
            concat!(
                "\n\n",
                "denyx-runtime-starlark: starlark_interpreter.wasm is missing.\n",
                "This file is the pre-compiled wasm32-wasip1 Starlark interpreter.\n",
                "It is gitignored locally; stage it by running:\n",
                "\n",
                "    ./scripts/build-runtime-starlark.sh\n",
                "\n",
                "from the repository root, then re-run cargo build. CI stages\n",
                "it equivalently before `cargo publish`.\n\n",
            )
        );
    }
    println!("cargo:rerun-if-changed={wasm_path}");

    let starlark_version = std::env::var("STARLARK_VERSION").unwrap_or_else(|_| "dev".to_string());
    let built_at = std::env::var("INTERPRETER_BUILT_AT").unwrap_or_else(|_| "dev".to_string());
    println!("cargo:rustc-env=STARLARK_VERSION={starlark_version}");
    println!("cargo:rustc-env=INTERPRETER_BUILT_AT={built_at}");
    println!("cargo:rerun-if-env-changed=STARLARK_VERSION");
    println!("cargo:rerun-if-env-changed=INTERPRETER_BUILT_AT");
}
