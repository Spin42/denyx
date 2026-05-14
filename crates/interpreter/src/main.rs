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
//   exports: `denyx_alloc` / `denyx_dealloc` — the host uses these to
//            return byte-buffers (string payloads from gated builtins)
//            back into the interpreter's linear memory.
//
// Return-string convention for gated builtins:
//   The host's import returns a single `u64` packed as:
//       (ptr as u64) << 32 | (len as u64)
//   The interpreter unpacks, reads `len` UTF-8 bytes from `ptr`, takes
//   ownership, and frees the buffer via denyx_dealloc.
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

/// Starlark prelude evaluated before the user script. Binds the
/// underscored builtin functions (`_denyx_fs_read`, …) to capability-
/// grouped struct namespaces (`fs.read`, …) so scripts can use the
/// familiar denyx surface.
#[cfg(target_arch = "wasm32")]
const PRELUDE: &str = r#"
fs = struct(
    read = _denyx_fs_read,
)
"#;

#[cfg(target_arch = "wasm32")]
fn evaluate(req: &Request) -> Response {
    use starlark::environment::{GlobalsBuilder, LibraryExtension, Module};
    use starlark::eval::Evaluator;
    use starlark::syntax::{AstModule, Dialect};

    let _ = req.task_id.len(); // reserved for audit correlation, Phase 5+

    let user_ast = match AstModule::parse(&req.source_path, req.source.clone(), &Dialect::Standard)
    {
        Ok(a) => a,
        Err(e) => return err_response("starlark-parse", e.to_string()),
    };
    // Globals = Starlark standard library + Bazel-flavored extensions
    // PRELUDE relies on (Print for `print()`, StructType for `struct(…)`)
    // + denyx's gated builtins. Extensions are listed explicitly rather
    // than using `Globals::extended()` so any future surface change is
    // a deliberate decision rather than a silent inheritance.
    let globals =
        GlobalsBuilder::extended_by(&[LibraryExtension::Print, LibraryExtension::StructType])
            .with(denyx_builtins)
            .build();
    let module = Module::new();
    // Declare the print handler before the Evaluator so it outlives the
    // borrow set_print_handler() takes. Rust drops locals in reverse
    // declaration order; getting this wrong is an E0597 at build time.
    let print_handler = HostPrintHandler;
    let mut eval = Evaluator::new(&module);
    eval.set_print_handler(&print_handler);

    // Evaluate the prelude into the module's namespace. PRELUDE is a
    // hardcoded constant — failure here means the interpreter is
    // broken, not the user's script.
    let prelude_ast =
        AstModule::parse("denyx_prelude.star", PRELUDE.to_owned(), &Dialect::Standard)
            .expect("PRELUDE is a hardcoded constant; should always parse");
    if let Err(e) = eval.eval_module(prelude_ast, &globals) {
        return err_response("starlark-prelude", e.to_string());
    }

    match eval.eval_module(user_ast, &globals) {
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
// interpreter's linear memory. Imports that return strings pack the
// result `(ptr, len)` into a single `u64`: `(ptr as u64) << 32 | len`.

#[cfg(target_arch = "wasm32")]
mod host {
    #[link(wasm_import_module = "denyx")]
    extern "C" {
        /// Receive a `print()` output line. The host buffers these in the
        /// run-result; depending on host policy it may also stream them
        /// to its own stdout.
        pub fn host_print(ptr: u32, len: u32);

        /// Read a file. Argument: UTF-8 path slice at `(path_ptr,
        /// path_len)` in guest memory. Returns the file contents as a
        /// packed `(ptr: u64<<32, len: u64 & 0xFFFFFFFF)` u64 pointing
        /// into a freshly `denyx_alloc`-allocated guest buffer the
        /// caller must free with `denyx_dealloc`.
        ///
        /// Policy denials trap the instance — host catches the trap
        /// and surfaces `DenyxError::Policy`.
        pub fn host_fs_read(path_ptr: u32, path_len: u32) -> u64;
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

// ── Gated builtins (Starlark globals) ──────────────────────────────────
//
// These functions are visible in Starlark as `_denyx_fs_read`, etc.
// PRELUDE re-binds them under capability-grouped structs so scripts
// use the public `fs.read`, `net.http_get`, … forms.
//
// Each function unpacks the host's packed-u64 return, copies the
// payload into an owned `String`, frees the host-allocated buffer via
// `denyx_dealloc`, and returns. Host-side denials surface here as
// Starlark errors propagated from the wasmtime trap.

#[cfg(target_arch = "wasm32")]
#[starlark::starlark_module]
fn denyx_builtins(builder: &mut starlark::environment::GlobalsBuilder) {
    /// Implementation for `fs.read(path)`.
    fn _denyx_fs_read(path: &str) -> anyhow::Result<String> {
        let packed = unsafe { host::host_fs_read(path.as_ptr() as u32, path.len() as u32) };
        unpack_string(packed)
    }
}

/// Helper used by every string-returning builtin: unpack the host's
/// packed-u64 return, copy the payload, free the host buffer.
#[cfg(target_arch = "wasm32")]
fn unpack_string(packed: u64) -> anyhow::Result<String> {
    let ptr = (packed >> 32) as u32;
    let len = (packed & 0xFFFF_FFFF) as u32;
    if ptr == 0 || len == 0 {
        return Ok(String::new());
    }
    // SAFETY: host wrote `len` bytes at `ptr` via denyx_alloc; we own
    // this buffer until we call denyx_dealloc below.
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let result = std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|e| anyhow::anyhow!("host-returned string is not valid UTF-8: {e}"));
    // SAFETY: pairing the denyx_alloc(len) call the host made for us.
    unsafe { denyx_dealloc(ptr, len) };
    result
}

// ── Allocator exports the host calls ───────────────────────────────────
//
// Phase 4.2 — the host uses these to return byte-buffers across the
// import boundary. Convention:
//
//   1. Host has a string `s` to give back (e.g. `fs.read` result).
//   2. Host calls guest's `denyx_alloc(s.len() as u32)` and receives
//      a pointer into the guest's linear memory.
//   3. Host writes `s.as_bytes()` to that pointer (via wasmtime's
//      `Memory::write`).
//   4. Host returns the (ptr, len) pair as the import's multi-value
//      result (or via a known out-pointer convention, TBD per import).
//   5. Guest reads UTF-8 from (ptr, len), takes ownership, and frees
//      via `denyx_dealloc(ptr, len)`.
//
// The implementation leaks a `Vec<u8>` of the requested capacity. The
// guest is responsible for the matching `denyx_dealloc` to reclaim
// the storage. Mismatched calls leak the buffer permanently — same
// invariant the wasm-bindgen ABI relies on.

/// Allocate a `len`-byte buffer in the interpreter's linear memory
/// and return the pointer.
///
/// Returns `0` if `len == 0` (no allocation needed; reading 0 bytes
/// at any pointer is a no-op).
///
/// # Safety
///
/// Caller must pair every successful `denyx_alloc(len)` with exactly
/// one `denyx_dealloc(ptr, len)`. Leaked buffers stay until the
/// instance is dropped.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn denyx_alloc(len: u32) -> u32 {
    if len == 0 {
        return 0;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr() as u32;
    std::mem::forget(buf);
    ptr
}

/// Free a buffer previously returned by `denyx_alloc`.
///
/// `len` must match the `len` passed to the original `denyx_alloc`
/// call. Mismatch is undefined behaviour (Vec::from_raw_parts
/// invariant).
///
/// # Safety
///
/// `ptr` must be a pointer returned by a prior `denyx_alloc(len)`
/// call on this instance, and not yet freed.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn denyx_dealloc(ptr: u32, len: u32) {
    if len == 0 {
        return;
    }
    let _ = Vec::from_raw_parts(ptr as *mut u8, 0, len as usize);
}
