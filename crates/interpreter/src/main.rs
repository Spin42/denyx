// denyx-interpreter — Starlark evaluator compiled to wasm32-wasip1.
//
// This is the .wasm source for the Wasmtime-sandbox migration: the same
// starlark-rust library denyx uses today, repackaged so it runs inside
// a Wasmtime sandbox instead of in-process with the host. Once Phase 5
// lands, denyx-cli will load the pre-compiled .wasm (via the
// denyx-runtime-starlark crate), instantiate it under Wasmtime with
// fuel-based preemption, and provide the gated builtins as Wasm imports.
//
// Wire protocol (Option 1 from the migration plan — WASI stdin/stdout):
//   stdin:  JSON `Request` (script source + metadata)
//   stdout: JSON `Response` (verdict + result)
//   imports: `denyx::host_*` Wasm functions, hand-wired by the host
//
// The native target builds a stub that prints a usage hint and exits
// non-zero, so `cargo build --workspace` keeps working on a regular host.

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    task_id: String,
    #[serde(default = "default_source_path")]
    source_path: String,
    source: String,
}

fn default_source_path() -> String {
    "script.star".to_string()
}

#[derive(Serialize)]
struct Response {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorInfo>,
}

#[derive(Serialize)]
struct ErrorInfo {
    kind: &'static str,
    message: String,
}

fn main() {
    #[cfg(not(target_arch = "wasm32"))]
    {
        eprintln!(
            "denyx-interpreter is built for wasm32-wasip1; this native stub \
             exists only so `cargo build --workspace` succeeds. Build with \
             `cargo build -p denyx-interpreter --target wasm32-wasip1 --release`."
        );
        std::process::exit(1);
    }

    #[cfg(target_arch = "wasm32")]
    wasm_main();
}

#[cfg(target_arch = "wasm32")]
fn wasm_main() {
    use std::io::Read;

    let mut buf = String::new();
    let resp = match std::io::stdin().read_to_string(&mut buf) {
        Err(e) => err_response("io", format!("stdin read: {e}")),
        Ok(_) => match serde_json::from_str::<Request>(&buf) {
            Err(e) => err_response("protocol", format!("parse request: {e}")),
            Ok(req) => evaluate(&req),
        },
    };
    print_response(&resp);
}

#[cfg(target_arch = "wasm32")]
fn evaluate(req: &Request) -> Response {
    use starlark::environment::{Globals, Module};
    use starlark::eval::Evaluator;
    use starlark::syntax::{AstModule, Dialect};

    let _ = req.task_id.len(); // reserved for audit correlation, Phase 5+

    let ast = match AstModule::parse(&req.source_path, req.source.clone(), &Dialect::Standard) {
        Ok(a) => a,
        Err(e) => return err_response("starlark-parse", e.to_string()),
    };
    let globals = Globals::standard();
    let module = Module::new();
    // Declare the print handler before the Evaluator so it outlives the
    // borrow set_print_handler() takes. Rust drops locals in reverse
    // declaration order; getting this wrong is an E0597 at build time.
    let print_handler = HostPrintHandler;
    let mut eval = Evaluator::new(&module);
    eval.set_print_handler(&print_handler);
    match eval.eval_module(ast, &globals) {
        Ok(value) => ok_response(value.to_string()),
        Err(e) => err_response("starlark-eval", e.to_string()),
    }
}

fn ok_response(value: String) -> Response {
    Response {
        status: "ok",
        result: Some(value),
        error: None,
    }
}

fn err_response(kind: &'static str, message: String) -> Response {
    Response {
        status: "error",
        result: None,
        error: Some(ErrorInfo { kind, message }),
    }
}

fn print_response(resp: &Response) {
    match serde_json::to_string(resp) {
        Ok(body) => println!("{body}"),
        Err(_) => println!(
            r#"{{"status":"error","error":{{"kind":"protocol","message":"serialize response failed"}}}}"#
        ),
    }
}

// ── Wasm imports the host provides ─────────────────────────────────────
//
// Each function corresponds to a denyx capability; the host (Phase 4)
// implements them via wasmtime Linker::func_wrap, gating each call
// through the existing policy enforcement before performing the
// operation. From inside the interpreter we declare them as plain
// `extern "C"` imports and call them directly.
//
// String values cross via (ptr: u32, len: u32) pairs into the
// interpreter's linear memory.
//
// For Phase 2 only `host_print` is declared. Phase 4 adds the rest.

#[cfg(target_arch = "wasm32")]
mod host {
    #[link(wasm_import_module = "denyx")]
    extern "C" {
        /// Receive a `print()` output line. The host buffers these in the
        /// run-result; depending on host policy it may also stream them
        /// to its own stdout.
        pub fn host_print(ptr: u32, len: u32);
    }
}

#[cfg(target_arch = "wasm32")]
struct HostPrintHandler;

#[cfg(target_arch = "wasm32")]
impl starlark::PrintHandler for HostPrintHandler {
    fn println(&self, text: &str) -> starlark::Result<()> {
        unsafe {
            host::host_print(text.as_ptr() as u32, text.len() as u32);
        }
        Ok(())
    }
}
