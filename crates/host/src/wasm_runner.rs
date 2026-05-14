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
//!   (4.3), `host_fs_write` (4.4), `host_fs_delete` (4.5),
//!   `host_env_read` (4.6), `host_subprocess_exec` (4.7),
//!   `host_net_http_{get,post,put,patch,delete}` (4.8). Phase 4
//!   wrap-up wires audit + confirm hooks across the set.
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

/// Default Wasm fuel budget per `WasmRunner::run` call. Each Wasm
/// instruction the guest executes consumes one unit of fuel; running
/// out causes a `Trap::OutOfFuel` which `run()` maps to
/// [`DenyxError::RuntimeLimit`]. The number is picked so a runaway
/// Starlark loop like `for _ in range(10**9): pass` trips within ~1
/// second of CPU on contemporary hardware (the Starlark interpreter
/// emits many Wasm ops per Starlark op, so this is an upper bound on
/// legitimate-script cost rather than a tight fit). Operators can
/// tune via a future policy `runtime.max_wasm_fuel` field; for now
/// the default is hardcoded.
const DEFAULT_WASM_FUEL: u64 = 200_000_000;

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
        config.consume_fuel(true);
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
        store
            .set_fuel(DEFAULT_WASM_FUEL)
            .map_err(|e| DenyxError::Other(format!("set wasm fuel: {e}")))?;

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

        // ── host_fs_delete (Phase 4.5) ────────────────────────────
        let fs_delete_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_fs_delete",
                move |mut caller: Caller<'_, WasmState>,
                      path_ptr: u32,
                      path_len: u32|
                      -> Result<(), wasmtime::Error> {
                    // 1. Read path from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let mut path_buf = vec![0u8; path_len as usize];
                    memory
                        .read(&caller, path_ptr as usize, &mut path_buf)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_fs_delete: path read: {e}"))
                        })?;
                    let path = match std::str::from_utf8(&path_buf) {
                        Ok(s) => s.to_owned(),
                        Err(e) => {
                            return Err(wasmtime::Error::msg(format!(
                                "host_fs_delete: non-utf8 path: {e}"
                            )));
                        }
                    };

                    // 2. Gate through policy.
                    let path_obj = std::path::Path::new(&path);
                    if let Err(e) = fs_delete_policy.check_fs_delete(path_obj) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("fs.delete({path:?}): {e}")));
                        return Err(wasmtime::Error::msg("fs.delete denied by policy"));
                    }

                    // 3. Perform the IO. remove_file matches the
                    //    in-process Runner's behaviour: fs.delete is
                    //    file-targeted, not recursive directory
                    //    removal.
                    if let Err(e) = std::fs::remove_file(path_obj) {
                        caller.data_mut().captured_error = Some(DenyxError::Io(e));
                        return Err(wasmtime::Error::msg("fs.delete: io error"));
                    }

                    Ok(())
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_fs_delete: {e}")))?;

        // ── host_env_read (Phase 4.6) ─────────────────────────────
        let env_read_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_env_read",
                move |mut caller: Caller<'_, WasmState>,
                      name_ptr: u32,
                      name_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    // 1. Read name from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let mut name_buf = vec![0u8; name_len as usize];
                    memory
                        .read(&caller, name_ptr as usize, &mut name_buf)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_env_read: name read: {e}"))
                        })?;
                    let name = match std::str::from_utf8(&name_buf) {
                        Ok(s) => s.to_owned(),
                        Err(e) => {
                            return Err(wasmtime::Error::msg(format!(
                                "host_env_read: non-utf8 name: {e}"
                            )));
                        }
                    };

                    // 2. Gate through policy.
                    if let Err(e) = env_read_policy.check_env_read(&name) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("env.read({name:?}): {e}")));
                        return Err(wasmtime::Error::msg("env.read denied by policy"));
                    }

                    // 3. Read the env var. Missing var surfaces as
                    //    DenyxError::Other — matches the in-process
                    //    Runner, which raises a Starlark error rather
                    //    than returning an empty string.
                    let value = match std::env::var(&name) {
                        Ok(v) => v,
                        Err(e) => {
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("env.read({name:?}): {e}")));
                            return Err(wasmtime::Error::msg("env.read: lookup error"));
                        }
                    };
                    let value_bytes = value.into_bytes();

                    // 4. Empty fast path.
                    if value_bytes.is_empty() {
                        return Ok(0);
                    }

                    // 5. Allocate buffer in guest memory + write.
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
                        .call(&mut caller, value_bytes.len() as u32)
                        .map_err(|e| wasmtime::Error::msg(format!("denyx_alloc call: {e}")))?;
                    memory
                        .write(&mut caller, dest_ptr as usize, &value_bytes)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_env_read: write value: {e}"))
                        })?;
                    let packed = ((dest_ptr as u64) << 32) | (value_bytes.len() as u64);
                    Ok(packed)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_env_read: {e}")))?;

        // ── host_subprocess_exec (Phase 4.7) ──────────────────────
        let subprocess_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_subprocess_exec",
                move |mut caller: Caller<'_, WasmState>,
                      argv_json_ptr: u32,
                      argv_json_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    // 1. Read argv JSON from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let mut argv_buf = vec![0u8; argv_json_len as usize];
                    memory
                        .read(&caller, argv_json_ptr as usize, &mut argv_buf)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_subprocess_exec: argv read: {e}"))
                        })?;
                    let argv_json = match std::str::from_utf8(&argv_buf) {
                        Ok(s) => s,
                        Err(e) => {
                            return Err(wasmtime::Error::msg(format!(
                                "host_subprocess_exec: non-utf8 argv json: {e}"
                            )));
                        }
                    };
                    let argv: Vec<String> = match serde_json::from_str(argv_json) {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(wasmtime::Error::msg(format!(
                                "host_subprocess_exec: parse argv json: {e}"
                            )));
                        }
                    };
                    if argv.is_empty() {
                        caller.data_mut().captured_error = Some(DenyxError::Policy(
                            "subprocess.exec: empty argv".to_string(),
                        ));
                        return Err(wasmtime::Error::msg("subprocess.exec: empty argv"));
                    }

                    // 2. Gate through policy. Three checks mirror the
                    //    in-process Runner: command (argv[0] basename),
                    //    arg-substring deny patterns, and argv path
                    //    resolution (catches `bash -c '/etc/passwd'`
                    //    style smuggling of unreachable paths).
                    if let Err(e) = subprocess_policy.check_subprocess_command(&argv[0]) {
                        caller.data_mut().captured_error = Some(DenyxError::Policy(format!(
                            "subprocess.exec({:?}): {e}",
                            argv[0]
                        )));
                        return Err(wasmtime::Error::msg("subprocess.exec: command denied"));
                    }
                    if let Err(e) = subprocess_policy.check_subprocess_args(&argv) {
                        caller.data_mut().captured_error = Some(DenyxError::Policy(format!(
                            "subprocess.exec({:?}): {e}",
                            argv
                        )));
                        return Err(wasmtime::Error::msg("subprocess.exec: args denied"));
                    }
                    if let Err(e) = subprocess_policy.check_subprocess_argv_paths(&argv) {
                        caller.data_mut().captured_error = Some(DenyxError::Policy(format!(
                            "subprocess.exec({:?}): {e}",
                            argv
                        )));
                        return Err(wasmtime::Error::msg("subprocess.exec: argv path denied"));
                    }

                    // 3. Spawn the process. env_clear() + a single
                    //    PATH passthrough is a minimal-secure default
                    //    for Phase 4.7 — the in-process Runner does
                    //    per-policy `allow_vars` filtering, which is
                    //    deferred to a later Phase 4 sub-commit
                    //    alongside audit + confirm wiring.
                    let mut cmd = std::process::Command::new(&argv[0]);
                    cmd.args(&argv[1..]);
                    cmd.env_clear();
                    if let Ok(path) = std::env::var("PATH") {
                        cmd.env("PATH", path);
                    }
                    let output = match cmd.output() {
                        Ok(o) => o,
                        Err(e) => {
                            caller.data_mut().captured_error = Some(DenyxError::Io(e));
                            return Err(wasmtime::Error::msg("subprocess.exec: spawn / io error"));
                        }
                    };
                    if !output.status.success() {
                        let code = output
                            .status
                            .code()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "(signalled)".to_string());
                        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                        caller.data_mut().captured_error = Some(DenyxError::Other(format!(
                            "subprocess.exec({:?}) exited {code}: {stderr}",
                            argv
                        )));
                        return Err(wasmtime::Error::msg("subprocess.exec: non-zero exit"));
                    }

                    let stdout_bytes = output.stdout;
                    if stdout_bytes.is_empty() {
                        return Ok(0);
                    }

                    // 4. Allocate + write stdout into guest memory.
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
                        .call(&mut caller, stdout_bytes.len() as u32)
                        .map_err(|e| wasmtime::Error::msg(format!("denyx_alloc call: {e}")))?;
                    memory
                        .write(&mut caller, dest_ptr as usize, &stdout_bytes)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_subprocess_exec: write stdout: {e}"))
                        })?;
                    let packed = ((dest_ptr as u64) << 32) | (stdout_bytes.len() as u64);
                    Ok(packed)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_subprocess_exec: {e}")))?;

        // ── host_net_http_get (Phase 4.8) ─────────────────────────
        let http_get_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_net_http_get",
                move |mut caller: Caller<'_, WasmState>,
                      url_ptr: u32,
                      url_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    if let Err(e) = http_get_policy.check_http_get(&url) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("net.http_get({url:?}): {e}")));
                        return Err(wasmtime::Error::msg("net.http_get denied"));
                    }
                    let body = match crate::no_redirect_agent().get(&url).call() {
                        Ok(resp) => match resp.into_string() {
                            Ok(s) => s,
                            Err(e) => {
                                caller.data_mut().captured_error = Some(DenyxError::Other(
                                    format!("net.http_get({url:?}): body read: {e}"),
                                ));
                                return Err(wasmtime::Error::msg("net.http_get: body read"));
                            }
                        },
                        Err(e) => {
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_get({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_get: request failed"));
                        }
                    };
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_get: {e}")))?;

        // ── host_net_http_post (Phase 4.8) ────────────────────────
        let http_post_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_net_http_post",
                move |mut caller: Caller<'_, WasmState>,
                      url_ptr: u32,
                      url_len: u32,
                      body_ptr: u32,
                      body_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    let req_body = read_string_from_guest(&mut caller, body_ptr, body_len, "body")?;
                    if let Err(e) = http_post_policy.check_http_post(&url) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("net.http_post({url:?}): {e}")));
                        return Err(wasmtime::Error::msg("net.http_post denied"));
                    }
                    let body = match crate::no_redirect_agent().post(&url).send_string(&req_body) {
                        Ok(resp) => match resp.into_string() {
                            Ok(s) => s,
                            Err(e) => {
                                caller.data_mut().captured_error = Some(DenyxError::Other(
                                    format!("net.http_post({url:?}): body read: {e}"),
                                ));
                                return Err(wasmtime::Error::msg("net.http_post: body read"));
                            }
                        },
                        Err(e) => {
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_post({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_post: request failed"));
                        }
                    };
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_post: {e}")))?;

        // ── host_net_http_put (Phase 4.8) ─────────────────────────
        let http_put_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_net_http_put",
                move |mut caller: Caller<'_, WasmState>,
                      url_ptr: u32,
                      url_len: u32,
                      body_ptr: u32,
                      body_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    let req_body = read_string_from_guest(&mut caller, body_ptr, body_len, "body")?;
                    if let Err(e) = http_put_policy.check_http_put(&url) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("net.http_put({url:?}): {e}")));
                        return Err(wasmtime::Error::msg("net.http_put denied"));
                    }
                    let body = match crate::no_redirect_agent().put(&url).send_string(&req_body) {
                        Ok(resp) => match resp.into_string() {
                            Ok(s) => s,
                            Err(e) => {
                                caller.data_mut().captured_error = Some(DenyxError::Other(
                                    format!("net.http_put({url:?}): body read: {e}"),
                                ));
                                return Err(wasmtime::Error::msg("net.http_put: body read"));
                            }
                        },
                        Err(e) => {
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_put({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_put: request failed"));
                        }
                    };
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_put: {e}")))?;

        // ── host_net_http_patch (Phase 4.8) ───────────────────────
        let http_patch_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_net_http_patch",
                move |mut caller: Caller<'_, WasmState>,
                      url_ptr: u32,
                      url_len: u32,
                      body_ptr: u32,
                      body_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    let req_body = read_string_from_guest(&mut caller, body_ptr, body_len, "body")?;
                    if let Err(e) = http_patch_policy.check_http_patch(&url) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("net.http_patch({url:?}): {e}")));
                        return Err(wasmtime::Error::msg("net.http_patch denied"));
                    }
                    let body = match crate::no_redirect_agent()
                        .request("PATCH", &url)
                        .send_string(&req_body)
                    {
                        Ok(resp) => match resp.into_string() {
                            Ok(s) => s,
                            Err(e) => {
                                caller.data_mut().captured_error = Some(DenyxError::Other(
                                    format!("net.http_patch({url:?}): body read: {e}"),
                                ));
                                return Err(wasmtime::Error::msg("net.http_patch: body read"));
                            }
                        },
                        Err(e) => {
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_patch({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_patch: request failed"));
                        }
                    };
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_patch: {e}")))?;

        // ── host_net_http_delete (Phase 4.8) ──────────────────────
        let http_delete_policy = self.policy.clone();
        linker
            .func_wrap(
                "denyx",
                "host_net_http_delete",
                move |mut caller: Caller<'_, WasmState>,
                      url_ptr: u32,
                      url_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    if let Err(e) = http_delete_policy.check_http_delete(&url) {
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("net.http_delete({url:?}): {e}")));
                        return Err(wasmtime::Error::msg("net.http_delete denied"));
                    }
                    let body = match crate::no_redirect_agent().delete(&url).call() {
                        Ok(resp) => match resp.into_string() {
                            Ok(s) => s,
                            Err(e) => {
                                caller.data_mut().captured_error = Some(DenyxError::Other(
                                    format!("net.http_delete({url:?}): body read: {e}"),
                                ));
                                return Err(wasmtime::Error::msg("net.http_delete: body read"));
                            }
                        },
                        Err(e) => {
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_delete({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_delete: request failed"));
                        }
                    };
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_delete: {e}")))?;

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
            // DenyxError variant first.
            if let Some(captured) = store.data_mut().captured_error.take() {
                return Err(captured);
            }
            // Fuel exhaustion is the gap-closing case from the
            // migration plan: a runaway Starlark loop traps cleanly
            // rather than running forever. Map it to RuntimeLimit so
            // denyx-cli exits with code 6 (the same code the in-
            // process Runner uses for wall-time deadline overruns).
            if let Some(wasmtime::Trap::OutOfFuel) =
                wasm_err.downcast_ref::<wasmtime::Trap>().copied()
            {
                return Err(DenyxError::RuntimeLimit(format!(
                    "wasm fuel exhausted after {DEFAULT_WASM_FUEL} units"
                )));
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
/// Read a UTF-8 string from guest linear memory at `(ptr, len)`.
/// Used by every import that takes a string arg. The `tag` is for
/// the error message — "url", "path", "body" etc.
fn read_string_from_guest(
    caller: &mut Caller<'_, WasmState>,
    ptr: u32,
    len: u32,
    tag: &str,
) -> Result<String, wasmtime::Error> {
    let memory = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
    let mut buf = vec![0u8; len as usize];
    memory
        .read(&*caller, ptr as usize, &mut buf)
        .map_err(|e| wasmtime::Error::msg(format!("read {tag}: {e}")))?;
    std::str::from_utf8(&buf)
        .map(|s| s.to_owned())
        .map_err(|e| wasmtime::Error::msg(format!("non-utf8 {tag}: {e}")))
}

/// Write a UTF-8 string into guest linear memory via `denyx_alloc`,
/// returning the packed `(ptr << 32) | len` u64 the guest expects.
/// Empty string short-circuits to 0.
fn write_string_to_guest(
    caller: &mut Caller<'_, WasmState>,
    s: &str,
) -> Result<u64, wasmtime::Error> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Ok(0);
    }
    let alloc = caller
        .get_export("denyx_alloc")
        .and_then(Extern::into_func)
        .ok_or_else(|| wasmtime::Error::msg("guest missing `denyx_alloc` export"))?;
    let typed_alloc = alloc
        .typed::<u32, u32>(&*caller)
        .map_err(|e| wasmtime::Error::msg(format!("denyx_alloc signature mismatch: {e}")))?;
    let dest_ptr = typed_alloc
        .call(&mut *caller, bytes.len() as u32)
        .map_err(|e| wasmtime::Error::msg(format!("denyx_alloc call: {e}")))?;
    let memory = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
    memory
        .write(&mut *caller, dest_ptr as usize, bytes)
        .map_err(|e| wasmtime::Error::msg(format!("write string: {e}")))?;
    Ok(((dest_ptr as u64) << 32) | (bytes.len() as u64))
}

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

    /// Phase 4.5 — allow path. A policy with the target in
    /// `delete_allow` lets the script remove the file. Validates:
    /// gate accepts → remove_file succeeds → file no longer exists.
    #[test]
    fn fs_delete_allowed_path_removes_file() {
        let file_path = unique_tmp_path("fs_delete_ok");
        std::fs::write(&file_path, "soon to be gone").expect("write fixture");
        let policy_path = write_temp_policy(
            "fs_delete_ok",
            &format!(
                "[filesystem]\ndelete_allow = [{:?}]\n",
                file_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!("fs.delete({:?})", file_path.display().to_string());
        runner
            .run("test", &script, "fs_delete_ok.star")
            .expect("runs");

        let exists_after = file_path.exists();
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        assert!(!exists_after, "fs.delete should have removed the file");
    }

    /// Phase 4.5 — deny path. Empty `delete_allow` surfaces the
    /// denial as `DenyxError::Policy`. The target file must still
    /// exist after the run.
    #[test]
    fn fs_delete_denied_path_surfaces_typed_error() {
        let file_path = unique_tmp_path("fs_delete_denied");
        std::fs::write(&file_path, "should remain").expect("write fixture");
        let policy_path =
            write_temp_policy("fs_delete_denied", "[filesystem]\ndelete_allow = []\n");
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!("fs.delete({:?})", file_path.display().to_string());
        let err = runner
            .run("test", &script, "fs_delete_denied.star")
            .expect_err("denied delete should error");
        let exists_after = file_path.exists();
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::Policy(_) => {}
            other => panic!("expected DenyxError::Policy, got {other:?}"),
        }
        assert!(
            exists_after,
            "denied fs.delete must not remove the target file"
        );
    }

    /// Phase 4.6 — allow path. Setting the env var on the test
    /// process, listing it in `[environment].allow_vars`, and reading
    /// from a script should return the value.
    #[test]
    fn env_read_allowed_var_returns_value() {
        // SAFETY: unsynchronised env mutation is racy across threads
        // in general, but this test sets a variable that no other
        // test reads, and reads it back within the same test.
        // unsafe { std::env::set_var(...) } is required as of Rust
        // 2024 edition; we're on 2021 so the safe form works.
        let var_name = format!("DENYX_WASM_RUNNER_TEST_VAR_{}", std::process::id());
        std::env::set_var(&var_name, "phase-4.6 value");
        let policy_path = write_temp_policy(
            "env_read_ok",
            &format!("[environment]\nallow_vars = [{var_name:?}]\n"),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!("print(env.read({var_name:?}))");
        let outcome = runner
            .run("test", &script, "env_read_ok.star")
            .expect("runs");
        std::env::remove_var(&var_name);
        let _ = std::fs::remove_file(&policy_path);

        assert_eq!(outcome.printed, vec!["phase-4.6 value".to_string()]);
    }

    /// Phase 4.6 — deny path. Empty allow_vars surfaces denial as
    /// DenyxError::Policy.
    #[test]
    fn env_read_denied_var_surfaces_typed_error() {
        let var_name = format!("DENYX_WASM_RUNNER_TEST_DENIED_{}", std::process::id());
        std::env::set_var(&var_name, "should-not-be-read");
        let policy_path = write_temp_policy("env_read_denied", "[environment]\nallow_vars = []\n");
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!("print(env.read({var_name:?}))");
        let err = runner
            .run("test", &script, "env_read_denied.star")
            .expect_err("denied env.read should error");
        std::env::remove_var(&var_name);
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::Policy(_) => {}
            other => panic!("expected DenyxError::Policy, got {other:?}"),
        }
    }

    /// Phase 4.7 — allow path. A policy that lists `echo` in
    /// subprocess.allow_commands lets the script spawn /bin/echo and
    /// receive its stdout. The deny-deny order matters: empty
    /// allow_commands by itself would let everything through under
    /// some Policy variants, so we list `echo` explicitly.
    #[test]
    fn subprocess_exec_allowed_command_returns_stdout() {
        let policy_path = write_temp_policy(
            "subprocess_exec_ok",
            "[subprocess]\nallow_commands = [\"echo\"]\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = r#"print(subprocess.exec(["echo", "phase-4.7"]))"#;
        let outcome = runner
            .run("test", script, "subprocess_exec_ok.star")
            .expect("runs");
        let _ = std::fs::remove_file(&policy_path);

        // /bin/echo appends a newline; trim it for the assertion.
        assert_eq!(
            outcome.printed,
            vec!["phase-4.7\n".to_string()],
            "subprocess.exec stdout (raw) should reach print"
        );
    }

    /// Phase 4.7 — deny path. A policy that does NOT list the command
    /// surfaces the denial as DenyxError::Policy.
    #[test]
    fn subprocess_exec_denied_command_surfaces_typed_error() {
        let policy_path = write_temp_policy(
            "subprocess_exec_denied",
            "[subprocess]\nallow_commands = []\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = r#"print(subprocess.exec(["echo", "should not run"]))"#;
        let err = runner
            .run("test", script, "subprocess_exec_denied.star")
            .expect_err("denied command should error");
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::Policy(_) => {}
            other => panic!("expected DenyxError::Policy, got {other:?}"),
        }
    }

    /// Phase 4.8 — deny paths for all 5 net.http_* verbs. We don't
    /// run an HTTP server in this unit-test crate, so only the deny
    /// path (which doesn't touch the network) is asserted here.
    /// Allow-path correctness is structural-equivalent to the fs.read
    /// and subprocess.exec tests — same packed-u64 return + same
    /// read_string_from_guest / write_string_to_guest helpers.
    #[test]
    fn net_http_get_denied_url_surfaces_typed_error() {
        let policy_path =
            write_temp_policy("net_http_get_denied", "[network]\nhttp_get_allow = []\n");
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let err = runner
            .run("t", "net.http_get(\"https://example.com\")", "x.star")
            .expect_err("denied URL should error");
        let _ = std::fs::remove_file(&policy_path);
        assert!(matches!(err, DenyxError::Policy(_)), "got {err:?}");
    }

    #[test]
    fn net_http_post_denied_url_surfaces_typed_error() {
        let policy_path =
            write_temp_policy("net_http_post_denied", "[network]\nhttp_post_allow = []\n");
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let err = runner
            .run(
                "t",
                "net.http_post(\"https://example.com\", \"body\")",
                "x.star",
            )
            .expect_err("denied URL should error");
        let _ = std::fs::remove_file(&policy_path);
        assert!(matches!(err, DenyxError::Policy(_)), "got {err:?}");
    }

    #[test]
    fn net_http_put_denied_url_surfaces_typed_error() {
        let policy_path =
            write_temp_policy("net_http_put_denied", "[network]\nhttp_put_allow = []\n");
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let err = runner
            .run(
                "t",
                "net.http_put(\"https://example.com\", \"body\")",
                "x.star",
            )
            .expect_err("denied URL should error");
        let _ = std::fs::remove_file(&policy_path);
        assert!(matches!(err, DenyxError::Policy(_)), "got {err:?}");
    }

    #[test]
    fn net_http_patch_denied_url_surfaces_typed_error() {
        let policy_path = write_temp_policy(
            "net_http_patch_denied",
            "[network]\nhttp_patch_allow = []\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let err = runner
            .run(
                "t",
                "net.http_patch(\"https://example.com\", \"body\")",
                "x.star",
            )
            .expect_err("denied URL should error");
        let _ = std::fs::remove_file(&policy_path);
        assert!(matches!(err, DenyxError::Policy(_)), "got {err:?}");
    }

    #[test]
    fn net_http_delete_denied_url_surfaces_typed_error() {
        let policy_path = write_temp_policy(
            "net_http_delete_denied",
            "[network]\nhttp_delete_allow = []\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let err = runner
            .run("t", "net.http_delete(\"https://example.com\")", "x.star")
            .expect_err("denied URL should error");
        let _ = std::fs::remove_file(&policy_path);
        assert!(matches!(err, DenyxError::Policy(_)), "got {err:?}");
    }

    /// Phase 5 acceptance criterion #4: a script with a runaway loop
    /// traps on Wasm fuel exhaustion rather than running forever. The
    /// trap surfaces as `DenyxError::RuntimeLimit`, mapping to exit
    /// code 6 in the CLI (parity with the in-process Runner's
    /// wall-time deadline behaviour).
    ///
    /// Note: the assertion is on the typed error, not on wall-clock
    /// time — flaky wall-clock assertions in unit tests are a known
    /// pain point and we have no way to confirm "within 1 second" on
    /// arbitrary CI hardware. The fact that the test completes at
    /// all (rather than hanging) is the structural proof; CI's
    /// per-test timeout catches the regression case.
    #[test]
    fn fuel_exhaustion_traps_runaway_loop() {
        let runner = WasmRunner::new(secure_defaults_policy());
        // 10**9 iterations would consume hundreds of millions of Wasm
        // ops in the Starlark interpreter; well past DEFAULT_WASM_FUEL.
        let script = r#"
def runaway():
    for _ in range(1000000000):
        pass

runaway()
"#;
        let err = runner
            .run("test", script, "runaway.star")
            .expect_err("runaway loop should trip the fuel limit");
        match err {
            DenyxError::RuntimeLimit(_) => {}
            other => panic!("expected DenyxError::RuntimeLimit, got {other:?}"),
        }
    }
}
