//! WasmRunner — parallel Starlark runner that evaluates inside a
//! wasmtime sandbox.
//!
//! Phase 4 of the wasmtime-sandbox migration. The in-process
//! [`Runner`](crate::Runner) is the default until Phase 5 flips the
//! `denyx-cli` call site. Both runners coexist on the same `Policy`
//! and `AuditSink` / `ConfirmHook` machinery.
//!
//! ## Wire model
//!
//! The Wasm guest is the pre-built `denyx-interpreter.wasm` artefact
//! re-exported by [`denyx_runtime_starlark::STARLARK_INTERPRETER_WASM`].
//! Communication is the same JSON wire protocol the standalone
//! `examples/wasm-smoke` harness exercises:
//!
//! - stdin:  `{"task_id": "...", "source_path": "...", "source": "..."}`
//! - stdout: `{"status": "ok"|"error", "result": "...", "error": {...}}`
//! - imports under module `"denyx"`: `host_print` (4.1), `host_fs_read`
//!   (4.3), `host_fs_write` (4.4); the rest wired one capability at a
//!   time in subsequent Phase 4 commits.
//! - exports: `denyx_alloc(len)` / `denyx_dealloc(ptr, len)` — the host
//!   calls these to return byte-buffer payloads (string results from
//!   gated builtins) back into the interpreter's linear memory.
//!
//! ## Return-string convention
//!
//! Imports that return a string pack the result as
//! `(ptr as u64) << 32 | (len as u64)`. The guest unpacks, copies the
//! UTF-8 payload into an owned `String`, and frees the host-allocated
//! buffer via `denyx_dealloc`. `(0, 0)` represents the empty string.
//! Imports that produce no result (e.g. `fs.write`) are plain void
//! functions; failure surfaces as a trap.
//!
//! ## Error mapping
//!
//! Imports that fail (policy denial, IO error, …) set
//! `WasmState::captured_error` *before* returning a [`wasmtime::Error`]
//! from the import closure. The wasmtime trap unwinds to
//! [`WasmRunner::run`], which checks the captured slot and surfaces
//! the typed [`DenyxError`] variant rather than a generic
//! `DenyxError::Other("wasm trap: …")`.

use std::sync::Arc;

use wasmtime::{Caller, Config, Engine, Extern, Linker, Module, Store};
use wasmtime_wasi::p1::{add_to_linker_sync, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::WasiCtxBuilder;

use denyx_policy::Policy;
use denyx_runtime_starlark::STARLARK_INTERPRETER_WASM;

use crate::{AuditSink, ConfirmHook, DenyAllConfirm, DenyxError, NullAuditSink, RunOutcome};

/// A Starlark runner that evaluates inside a wasmtime sandbox.
///
/// Mirrors [`Runner`](crate::Runner)'s builder API so the swap in
/// Phase 5 is a single call-site change.
pub struct WasmRunner {
    policy: Arc<Policy>,
    audit: Arc<dyn AuditSink>,
    confirm: Arc<dyn ConfirmHook>,
}

impl WasmRunner {
    /// Construct a WasmRunner bound to a policy. Defaults to a no-op
    /// audit sink and a deny-everything confirm hook — caller is
    /// expected to override both with [`with_audit`](Self::with_audit)
    /// and [`with_confirm_hook`](Self::with_confirm_hook) in any non-
    /// test context.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(policy),
            audit: Arc::new(NullAuditSink),
            confirm: Arc::new(DenyAllConfirm),
        }
    }

    /// Attach an audit sink. Same semantics as [`Runner::with_audit`](crate::Runner::with_audit).
    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = sink;
        self
    }

    /// Attach a confirm hook. Same semantics as
    /// [`Runner::with_confirm_hook`](crate::Runner::with_confirm_hook).
    pub fn with_confirm_hook(mut self, hook: Arc<dyn ConfirmHook>) -> Self {
        self.confirm = hook;
        self
    }

    /// Reference to the bound policy. Mirrors [`Runner::policy`](crate::Runner::policy).
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Run a Starlark script inside the wasmtime sandbox.
    pub fn run(
        &self,
        task_id: &str,
        source: &str,
        script_name: &str,
    ) -> Result<RunOutcome, DenyxError> {
        let request = serde_json::json!({
            "task_id": task_id,
            "source_path": script_name,
            "source": source,
        });
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| DenyxError::Other(format!("serialize wasm request: {e}")))?;

        let mut config = Config::new();
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        let engine =
            Engine::new(&config).map_err(|e| DenyxError::Other(format!("wasmtime engine: {e}")))?;
        let module = Module::new(&engine, STARLARK_INTERPRETER_WASM)
            .map_err(|e| DenyxError::Other(format!("wasmtime module load: {e}")))?;

        let stdout_pipe = MemoryOutputPipe::new(64 * 1024);
        let stdin_pipe = MemoryInputPipe::new(request_bytes);
        let wasi = WasiCtxBuilder::new()
            .stdin(stdin_pipe)
            .stdout(stdout_pipe.clone())
            .inherit_stderr()
            .build_p1();

        let state = WasmState {
            wasi,
            printed: Vec::new(),
            captured_error: None,
        };
        let mut store = Store::new(&engine, state);

        let mut linker: Linker<WasmState> = Linker::new(&engine);
        add_to_linker_sync(&mut linker, |s: &mut WasmState| &mut s.wasi)
            .map_err(|e| DenyxError::Other(format!("wasi linker: {e}")))?;

        // ── host_print (Phase 4.1) ────────────────────────────────
        linker
            .func_wrap(
                "denyx",
                "host_print",
                |mut caller: Caller<'_, WasmState>,
                 ptr: u32,
                 len: u32|
                 -> Result<(), wasmtime::Error> {
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let mut buf = vec![0u8; len as usize];
                    memory.read(&caller, ptr as usize, &mut buf).map_err(|e| {
                        wasmtime::Error::msg(format!("host_print: memory read: {e}"))
                    })?;
                    let text = String::from_utf8(buf).map_err(|e| {
                        wasmtime::Error::msg(format!("host_print: utf8 decode: {e}"))
                    })?;
                    caller.data_mut().printed.push(text);
                    Ok(())
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_print: {e}")))?;

        // ── host_fs_read (Phase 4.3) ──────────────────────────────
        let fs_read_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_fs_read",
                move |mut caller: Caller<'_, WasmState>,
                      path_ptr: u32,
                      path_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    // 1. Read path from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let mut path_buf = vec![0u8; path_len as usize];
                    memory
                        .read(&caller, path_ptr as usize, &mut path_buf)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_fs_read: path read: {e}"))
                        })?;
                    let path = match std::str::from_utf8(&path_buf) {
                        Ok(s) => s.to_owned(),
                        Err(e) => {
                            return Err(wasmtime::Error::msg(format!(
                                "host_fs_read: non-utf8 path: {e}"
                            )));
                        }
                    };

                    // 2. Gate through policy.
                    let path_obj = std::path::Path::new(&path);
                    if let Err(e) = fs_read_policy.check_fs_read(path_obj) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("fs.read({path:?}): {e}")));
                        return Err(wasmtime::Error::msg("fs.read denied by policy"));
                    }

                    // 3. Perform the IO.
                    let content = match std::fs::read_to_string(path_obj) {
                        Ok(c) => c,
                        Err(e) => {
                            caller.data_mut().captured_error = Some(DenyxError::Io(e));
                            return Err(wasmtime::Error::msg("fs.read: io error"));
                        }
                    };
                    let content_bytes = content.into_bytes();

                    // 4. Empty-content fast path. Convention: (0, 0).
                    if content_bytes.is_empty() {
                        return Ok(0);
                    }

                    // 5. Allocate buffer in guest memory via denyx_alloc.
                    let alloc = caller
                        .get_export("denyx_alloc")
                        .and_then(Extern::into_func)
                        .ok_or_else(|| {
                            wasmtime::Error::msg("guest missing `denyx_alloc` export")
                        })?;
                    let typed_alloc = alloc.typed::<u32, u32>(&caller).map_err(|e| {
                        wasmtime::Error::msg(format!("denyx_alloc signature mismatch: {e}"))
                    })?;
                    let dest_ptr = typed_alloc
                        .call(&mut caller, content_bytes.len() as u32)
                        .map_err(|e| wasmtime::Error::msg(format!("denyx_alloc call: {e}")))?;

                    // 6. Write content into the allocated buffer. The
                    //    memory's data pointer may have shifted across
                    //    the alloc call, but the Memory handle re-
                    //    acquires the current view internally.
                    memory
                        .write(&mut caller, dest_ptr as usize, &content_bytes)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_fs_read: write content: {e}"))
                        })?;

                    // 7. Pack (ptr, len) into u64.
                    let packed = ((dest_ptr as u64) << 32) | (content_bytes.len() as u64);
                    Ok(packed)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_fs_read: {e}")))?;

        // ── host_fs_write (Phase 4.4) ─────────────────────────────
        let fs_write_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_fs_write",
                move |mut caller: Caller<'_, WasmState>,
                      path_ptr: u32,
                      path_len: u32,
                      content_ptr: u32,
                      content_len: u32|
                      -> Result<(), wasmtime::Error> {
                    // 1. Read path and content from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let mut path_buf = vec![0u8; path_len as usize];
                    memory
                        .read(&caller, path_ptr as usize, &mut path_buf)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_fs_write: path read: {e}"))
                        })?;
                    let path = match std::str::from_utf8(&path_buf) {
                        Ok(s) => s.to_owned(),
                        Err(e) => {
                            return Err(wasmtime::Error::msg(format!(
                                "host_fs_write: non-utf8 path: {e}"
                            )));
                        }
                    };
                    let mut content_buf = vec![0u8; content_len as usize];
                    memory
                        .read(&caller, content_ptr as usize, &mut content_buf)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_fs_write: content read: {e}"))
                        })?;

                    // 2. Gate through policy.
                    let path_obj = std::path::Path::new(&path);
                    if let Err(e) = fs_write_policy.check_fs_write(path_obj) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("fs.write({path:?}): {e}")));
                        return Err(wasmtime::Error::msg("fs.write denied by policy"));
                    }

                    // 3. Perform the IO. We accept arbitrary bytes
                    //    from the guest (content is treated as opaque
                    //    bytes here, not necessarily UTF-8). Starlark
                    //    strings are UTF-8 so this is a no-op for
                    //    well-typed input, but the host shouldn't
                    //    impose a tighter contract than the wire
                    //    protocol demands.
                    if let Err(e) = std::fs::write(path_obj, &content_buf) {
                        caller.data_mut().captured_error = Some(DenyxError::Io(e));
                        return Err(wasmtime::Error::msg("fs.write: io error"));
                    }

                    Ok(())
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_fs_write: {e}")))?;

        // Instantiate and run `_start`.
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| DenyxError::Other(format!("wasm instantiate: {e}")))?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| DenyxError::Other(format!("missing _start: {e}")))?;

        if let Err(wasm_err) = start.call(&mut store, ()) {
            // An import closure may have set captured_error before
            // returning a wasmtime::Error. If so, surface the typed
            // DenyxError variant; otherwise this is a real Wasm trap.
            if let Some(captured) = store.data_mut().captured_error.take() {
                return Err(captured);
            }
            return Err(DenyxError::Other(format!("wasm trap: {wasm_err}")));
        }

        // Collect the interpreter's response from the stdout pipe and
        // the printed lines from host_print.
        let raw = stdout_pipe.contents();
        let stdout_str = std::str::from_utf8(&raw)
            .map_err(|e| DenyxError::Other(format!("wasm stdout not utf8: {e}")))?;
        let response: InterpreterResponse =
            serde_json::from_str(stdout_str.trim()).map_err(|e| {
                DenyxError::Other(format!(
                    "parse interpreter response: {e}; raw: {:?}",
                    stdout_str
                ))
            })?;

        match response.status.as_str() {
            "ok" => Ok(RunOutcome {
                printed: store.into_data().printed,
            }),
            "error" => {
                let (kind, message) = match response.error {
                    Some(e) => (e.kind, e.message),
                    None => (String::new(), "(no error info)".to_string()),
                };
                let formatted = if kind.is_empty() {
                    message
                } else {
                    format!("{kind}: {message}")
                };
                let mapped = match kind.as_str() {
                    "starlark-parse" | "starlark-eval" | "starlark-prelude" | "io" | "protocol" => {
                        DenyxError::Starlark(formatted)
                    }
                    _ => DenyxError::Other(formatted),
                };
                Err(mapped)
            }
            other => Err(DenyxError::Other(format!(
                "unknown interpreter status: {other:?}"
            ))),
        }
    }
}

/// State carried by wasmtime's `Store<T>`. Holds the WASI ctx so WASI
/// imports can find it, plus the print accumulator the `host_print`
/// import writes into, plus a slot for import closures to surface a
/// typed [`DenyxError`] across the trap boundary.
struct WasmState {
    wasi: WasiP1Ctx,
    printed: Vec<String>,
    captured_error: Option<DenyxError>,
}

#[derive(serde::Deserialize)]
struct InterpreterResponse {
    status: String,
    #[allow(dead_code)] // populated by the interpreter; not surfaced via RunOutcome
    result: Option<String>,
    error: Option<InterpreterError>,
}

#[derive(serde::Deserialize)]
struct InterpreterError {
    kind: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secure_defaults_policy() -> Policy {
        Policy::secure_defaults_at(std::env::current_dir().unwrap()).expect("secure-defaults loads")
    }

    /// Allocate a unique scratch path under /tmp so parallel test runs
    /// don't collide. Using just `std::process::id()` was insufficient:
    /// `cargo test` runs every test in the same process by default, and
    /// every helper call would have returned the same path, letting one
    /// test overwrite another's fixture mid-run.
    fn unique_tmp_path(prefix: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "denyx_wasm_runner_{prefix}_{pid}_{n}",
            pid = std::process::id()
        ))
    }

    fn write_temp_policy(tag: &str, toml_body: &str) -> std::path::PathBuf {
        let path = unique_tmp_path(&format!("policy_{tag}"));
        std::fs::write(&path, toml_body).expect("write temp policy");
        path
    }

    /// The Phase 4.1 smoke parity test: a script that calls `print()`
    /// round-trips through the WasmRunner and the call gets observed
    /// via the `host_print` import.
    #[test]
    fn smoke_print_through_wasm() {
        let runner = WasmRunner::new(secure_defaults_policy());
        let outcome = runner
            .run("test", "print('hello'); 1 + 2", "smoke.star")
            .expect("WasmRunner runs");
        assert_eq!(outcome.printed, vec!["hello".to_string()]);
    }

    /// Negative path: a parse error should surface as DenyxError::Starlark.
    #[test]
    fn smoke_parse_error_surfaces() {
        let runner = WasmRunner::new(secure_defaults_policy());
        let err = runner
            .run("test", "this is not valid starlark $", "smoke.star")
            .expect_err("parse should fail");
        match err {
            DenyxError::Starlark(_) => {}
            other => panic!("expected DenyxError::Starlark, got {other:?}"),
        }
    }

    /// Phase 4.2 structural check: the interpreter exposes the
    /// `denyx_alloc` / `denyx_dealloc` export pair that string-
    /// returning imports use to write back into guest memory.
    #[test]
    fn interpreter_exports_allocator() {
        let engine = Engine::new(&Config::new()).expect("wasmtime engine");
        let module = Module::new(&engine, STARLARK_INTERPRETER_WASM).expect("wasm module loads");
        let names: Vec<&str> = module.exports().map(|e| e.name()).collect();
        assert!(
            names.contains(&"denyx_alloc"),
            "denyx_alloc missing from interpreter exports: {names:?}"
        );
        assert!(
            names.contains(&"denyx_dealloc"),
            "denyx_dealloc missing from interpreter exports: {names:?}"
        );
    }

    /// Phase 4.3 — allow path. A policy that lists the target file in
    /// `read_allow` lets the script read it and print the contents.
    /// Verifies the full path: gate accepts → IO succeeds → content
    /// crosses the allocator → guest reads + prints.
    #[test]
    fn fs_read_allowed_path_returns_content() {
        let file_path = unique_tmp_path("fs_read_ok");
        std::fs::write(&file_path, "phase-4.3 content").expect("write fixture");
        let policy_path = write_temp_policy(
            "fs_read_ok",
            &format!(
                "[filesystem]\nread_allow = [{:?}]\n",
                file_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!("print(fs.read({:?}))", file_path.display().to_string());
        let outcome = runner
            .run("test", &script, "fs_read_ok.star")
            .expect("runs");
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        assert_eq!(outcome.printed, vec!["phase-4.3 content".to_string()]);
    }

    /// Phase 4.3 — deny path. A policy that does NOT list the target
    /// surfaces the denial as `DenyxError::Policy` (not a generic
    /// wasm trap), validating the captured_error round-trip.
    #[test]
    fn fs_read_denied_path_surfaces_typed_error() {
        let file_path = unique_tmp_path("fs_read_denied");
        std::fs::write(&file_path, "should-not-be-read").expect("write fixture");
        // No read_allow entry covers this path.
        let policy_path = write_temp_policy("fs_read_denied", "[filesystem]\nread_allow = []\n");
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!("print(fs.read({:?}))", file_path.display().to_string());
        let err = runner
            .run("test", &script, "fs_read_denied.star")
            .expect_err("denied path should error");
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::Policy(_) => {}
            other => panic!("expected DenyxError::Policy, got {other:?}"),
        }
    }

    /// Phase 4.4 — allow path. A policy with the target in
    /// `write_allow` lets the script create the file with the
    /// supplied content. Validates: gate accepts → IO succeeds →
    /// file contents match.
    #[test]
    fn fs_write_allowed_path_creates_file() {
        let file_path = unique_tmp_path("fs_write_ok");
        let _ = std::fs::remove_file(&file_path);
        let policy_path = write_temp_policy(
            "fs_write_ok",
            &format!(
                "[filesystem]\nwrite_allow = [{:?}]\n",
                file_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!(
            "fs.write({:?}, \"phase-4.4 content\")",
            file_path.display().to_string()
        );
        let outcome = runner
            .run("test", &script, "fs_write_ok.star")
            .expect("runs");

        let written = std::fs::read_to_string(&file_path).expect("file was written");
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        assert_eq!(written, "phase-4.4 content");
        assert!(
            outcome.printed.is_empty(),
            "fs.write should not produce printed output, got {:?}",
            outcome.printed
        );
    }

    /// Phase 4.4 — deny path. A policy with empty `write_allow`
    /// surfaces the denial as `DenyxError::Policy`. The target file
    /// must not exist after the run.
    #[test]
    fn fs_write_denied_path_surfaces_typed_error() {
        let file_path = unique_tmp_path("fs_write_denied");
        let _ = std::fs::remove_file(&file_path);
        let policy_path = write_temp_policy("fs_write_denied", "[filesystem]\nwrite_allow = []\n");
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!(
            "fs.write({:?}, \"should not appear\")",
            file_path.display().to_string()
        );
        let err = runner
            .run("test", &script, "fs_write_denied.star")
            .expect_err("denied write should error");
        let exists_after = file_path.exists();
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::Policy(_) => {}
            other => panic!("expected DenyxError::Policy, got {other:?}"),
        }
        assert!(
            !exists_after,
            "denied fs.write must not create the target file"
        );
    }
}
