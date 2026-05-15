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
    read_range = _denyx_fs_read_range,
    write = _denyx_fs_write,
    delete = _denyx_fs_delete,
)

env = struct(
    read = _denyx_env_read,
)

subprocess = struct(
    exec = _denyx_subprocess_exec,
)

net = struct(
    http_get = _denyx_net_http_get,
    http_post = _denyx_net_http_post,
    http_put = _denyx_net_http_put,
    http_patch = _denyx_net_http_patch,
    http_delete = _denyx_net_http_delete,
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
    let globals = GlobalsBuilder::extended_by(&[
        LibraryExtension::Print,
        LibraryExtension::StructType,
        LibraryExtension::NamespaceType,
        LibraryExtension::Json,
        LibraryExtension::Map,
        LibraryExtension::Filter,
        LibraryExtension::Debug,
    ])
    .with(denyx_builtins)
    .build();
    let module = Module::new();
    let print_handler = HostPrintHandler;
    let mut eval = Evaluator::new(&module);
    eval.set_print_handler(&print_handler);

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

#[cfg(target_arch = "wasm32")]
mod host {
    #[link(wasm_import_module = "denyx")]
    extern "C" {
        pub fn host_print(ptr: u32, len: u32);
        pub fn host_fs_read(path_ptr: u32, path_len: u32) -> u64;

        /// Bounded read: open file, seek to `offset`, read at most
        /// `limit` bytes. Returned via the same packed-u64 alloc
        /// convention as host_fs_read.
        pub fn host_fs_read_range(path_ptr: u32, path_len: u32, offset: u64, limit: u64) -> u64;
        pub fn host_fs_write(path_ptr: u32, path_len: u32, content_ptr: u32, content_len: u32);
        pub fn host_fs_delete(path_ptr: u32, path_len: u32);
        pub fn host_env_read(name_ptr: u32, name_len: u32) -> u64;
        pub fn host_subprocess_exec(argv_json_ptr: u32, argv_json_len: u32) -> u64;
        pub fn host_net_http_get(url_ptr: u32, url_len: u32) -> u64;
        pub fn host_net_http_post(url_ptr: u32, url_len: u32, body_ptr: u32, body_len: u32) -> u64;
        pub fn host_net_http_put(url_ptr: u32, url_len: u32, body_ptr: u32, body_len: u32) -> u64;
        pub fn host_net_http_patch(url_ptr: u32, url_len: u32, body_ptr: u32, body_len: u32)
            -> u64;
        pub fn host_net_http_delete(url_ptr: u32, url_len: u32) -> u64;
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

#[cfg(target_arch = "wasm32")]
#[starlark::starlark_module]
fn denyx_builtins(builder: &mut starlark::environment::GlobalsBuilder) {
    fn _denyx_fs_read(path: &str) -> anyhow::Result<String> {
        let packed = unsafe { host::host_fs_read(path.as_ptr() as u32, path.len() as u32) };
        unpack_string(packed)
    }

    /// `fs.read_range(path, offset, limit)` — bounded read at the IO
    /// layer. Same gate as fs.read; smaller wire payload AND smaller
    /// disk read for surgical reads of large files.
    fn _denyx_fs_read_range(path: &str, offset: u64, limit: u64) -> anyhow::Result<String> {
        let packed = unsafe {
            host::host_fs_read_range(path.as_ptr() as u32, path.len() as u32, offset, limit)
        };
        unpack_string(packed)
    }

    fn _denyx_fs_write(
        path: &str,
        content: &str,
    ) -> anyhow::Result<starlark::values::none::NoneType> {
        unsafe {
            host::host_fs_write(
                path.as_ptr() as u32,
                path.len() as u32,
                content.as_ptr() as u32,
                content.len() as u32,
            );
        }
        Ok(starlark::values::none::NoneType)
    }

    fn _denyx_fs_delete(path: &str) -> anyhow::Result<starlark::values::none::NoneType> {
        unsafe {
            host::host_fs_delete(path.as_ptr() as u32, path.len() as u32);
        }
        Ok(starlark::values::none::NoneType)
    }

    fn _denyx_env_read(name: &str) -> anyhow::Result<String> {
        let packed = unsafe { host::host_env_read(name.as_ptr() as u32, name.len() as u32) };
        unpack_string(packed)
    }

    fn _denyx_subprocess_exec(
        argv: starlark::values::list::UnpackList<String>,
    ) -> anyhow::Result<String> {
        let argv_vec: Vec<String> = argv.items;
        let argv_json = serde_json::to_string(&argv_vec)
            .map_err(|e| anyhow::anyhow!("subprocess.exec: serialize argv: {e}"))?;
        let packed = unsafe {
            host::host_subprocess_exec(argv_json.as_ptr() as u32, argv_json.len() as u32)
        };
        unpack_string(packed)
    }

    fn _denyx_net_http_get(url: &str) -> anyhow::Result<String> {
        let packed = unsafe { host::host_net_http_get(url.as_ptr() as u32, url.len() as u32) };
        unpack_string(packed)
    }

    fn _denyx_net_http_post(url: &str, body: &str) -> anyhow::Result<String> {
        let packed = unsafe {
            host::host_net_http_post(
                url.as_ptr() as u32,
                url.len() as u32,
                body.as_ptr() as u32,
                body.len() as u32,
            )
        };
        unpack_string(packed)
    }

    fn _denyx_net_http_put(url: &str, body: &str) -> anyhow::Result<String> {
        let packed = unsafe {
            host::host_net_http_put(
                url.as_ptr() as u32,
                url.len() as u32,
                body.as_ptr() as u32,
                body.len() as u32,
            )
        };
        unpack_string(packed)
    }

    fn _denyx_net_http_patch(url: &str, body: &str) -> anyhow::Result<String> {
        let packed = unsafe {
            host::host_net_http_patch(
                url.as_ptr() as u32,
                url.len() as u32,
                body.as_ptr() as u32,
                body.len() as u32,
            )
        };
        unpack_string(packed)
    }

    fn _denyx_net_http_delete(url: &str) -> anyhow::Result<String> {
        let packed = unsafe { host::host_net_http_delete(url.as_ptr() as u32, url.len() as u32) };
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
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let result = std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|e| anyhow::anyhow!("host-returned string is not valid UTF-8: {e}"));
    unsafe { denyx_dealloc(ptr, len) };
    result
}

// ── Allocator exports the host calls ───────────────────────────────────

/// Allocate a `len`-byte buffer in the interpreter's linear memory.
/// Pair every successful `denyx_alloc(len)` with one `denyx_dealloc(ptr, len)`.
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
/// # Safety
///
/// `ptr` must be a pointer returned by a prior `denyx_alloc(len)`
/// call on this instance, and `len` must match.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn denyx_dealloc(ptr: u32, len: u32) {
    if len == 0 {
        return;
    }
    let _ = Vec::from_raw_parts(ptr as *mut u8, 0, len as usize);
}
