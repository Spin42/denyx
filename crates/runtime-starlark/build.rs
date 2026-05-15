// Build script for denyx-runtime-starlark.
//
// 1. Validate that the `.wasm` artefact is present. If not, emit a
//    friendly error pointing the developer at the stage script.
// 2. AOT-compile the `.wasm` to a `.cwasm` (wasmtime serialized
//    module) targeting the host architecture. The result is written
//    to `$OUT_DIR/starlark_interpreter.cwasm` and exposed at
//    runtime via the `STARLARK_INTERPRETER_CWASM` const in lib.rs.
//    Loading a `.cwasm` is single-digit ms; loading the raw `.wasm`
//    is ~470 ms (wasmtime JIT-compiling the 5MB interpreter).
// 3. Forward `STARLARK_VERSION` and `INTERPRETER_BUILT_AT` env vars
//    through to compile-time `env!()` constants via cargo:rustc-env.
//
// Trust note: the `.cwasm` is produced from the in-tree `.wasm` at
// build time on the same host that's running the build. It is NOT
// consumed from untrusted sources at runtime. If a consumer's
// wasmtime version or Config flags don't match the build-time
// configuration, `Module::deserialize` returns Err and `WasmRunner`
// falls back to JIT-compiling the raw `.wasm` (same behaviour as
// before this commit). See `crates/host/src/wasm_runner.rs`.

use std::path::{Path, PathBuf};

fn main() {
    let wasm_path = PathBuf::from("starlark_interpreter.wasm");
    if !Path::new(&wasm_path).exists() {
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
    println!("cargo:rerun-if-changed={}", wasm_path.display());

    // AOT-compile via wasmtime. The Config flags MUST match what
    // crates/host/src/wasm_runner.rs uses at runtime, otherwise
    // Module::deserialize will refuse the cwasm at load time and
    // the runtime will fall back to JIT.
    let wasm_bytes = std::fs::read(&wasm_path).expect("read .wasm");
    let mut config = wasmtime::Config::new();
    config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
    config.consume_fuel(true);
    let engine = wasmtime::Engine::new(&config)
        .expect("wasmtime engine for AOT compile in denyx-runtime-starlark/build.rs");
    let module = wasmtime::Module::new(&engine, &wasm_bytes)
        .expect("wasmtime compile of starlark_interpreter.wasm");
    let cwasm_bytes = module
        .serialize()
        .expect("wasmtime serialize of compiled module");

    let out_dir = std::env::var_os("OUT_DIR").expect("OUT_DIR not set by cargo");
    let cwasm_path = PathBuf::from(out_dir).join("starlark_interpreter.cwasm");
    std::fs::write(&cwasm_path, &cwasm_bytes).expect("write .cwasm to OUT_DIR");
    println!(
        "cargo:rustc-env=STARLARK_CWASM_PATH={}",
        cwasm_path.display()
    );

    // Build metadata env vars (existing — preserved).
    let starlark_version = std::env::var("STARLARK_VERSION").unwrap_or_else(|_| "dev".to_string());
    let built_at = std::env::var("INTERPRETER_BUILT_AT").unwrap_or_else(|_| "dev".to_string());
    println!("cargo:rustc-env=STARLARK_VERSION={starlark_version}");
    println!("cargo:rustc-env=INTERPRETER_BUILT_AT={built_at}");
    println!("cargo:rerun-if-env-changed=STARLARK_VERSION");
    println!("cargo:rerun-if-env-changed=INTERPRETER_BUILT_AT");
}
