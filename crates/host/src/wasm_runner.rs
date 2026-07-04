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
use std::time::Instant;

use wasmtime::{Caller, Config, Engine, Extern, Linker, Memory, Module, Store};
use wasmtime_wasi::p1::{add_to_linker_sync, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::WasiCtxBuilder;

/// Wall-time deadline check for the wasm path. Mirrors the in-process
/// Runner's `HostCtx::check_deadline` (lib.rs:376): if the policy
/// declares `[runtime].max_seconds = N`, every effecting builtin
/// inspects elapsed wall-clock since script start and refuses the
/// call with `DenyxError::RuntimeLimit` once N seconds have passed.
///
/// Called at the TOP of every effecting Func closure, BEFORE the
/// policy gate / outbound-taint / confirm-hook / IO work. A
/// deadline-exceeded script fails cleanly before any side effect
/// runs.
///
/// Returns `Ok(())` when the deadline hasn't been exceeded (or the
/// policy doesn't declare one). Returns `Err` after emitting an
/// audit-denied event and stashing `DenyxError::RuntimeLimit` into
/// the captured_error slot — the wasmtime trap surfaces back to
/// `WasmRunner::run` which checks the slot and produces the typed
/// error to the caller.
fn check_wasm_deadline(
    caller: &mut Caller<'_, WasmState>,
    policy: &denyx_policy::Policy,
    audit: &Arc<dyn crate::AuditSink>,
    task_id: &str,
    capability: &'static str,
) -> Result<(), wasmtime::Error> {
    let Some(max_seconds) = policy.runtime_max_seconds() else {
        return Ok(());
    };
    let elapsed = caller.data().start_time.elapsed();
    if elapsed.as_secs() < max_seconds {
        return Ok(());
    }
    let step = caller
        .data()
        .step_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let msg = format!(
        "wall-time deadline of {max_seconds}s exceeded ({:.1}s elapsed) at {capability}",
        elapsed.as_secs_f64()
    );
    emit_scrubbed(
        caller,
        audit,
        crate::AuditEvent::denied(task_id, step, capability, "deadline", &msg),
    );
    caller.data_mut().captured_error = Some(crate::DenyxError::RuntimeLimit(msg));
    Err(wasmtime::Error::msg("deadline exceeded"))
}

/// Wasm-path mirror of `HostCtx::check_no_output_after_local_only_read`
/// (native runner, `crates/host/src/lib.rs`). Called at the top of
/// every OUTPUT-producing import (`host_print`, `host_fs_write`,
/// `host_fs_delete`, `host_net_http_*`, `host_subprocess_exec`) —
/// never from a read-only import. See
/// `denyx_policy::RuntimePolicy::no_output_after_local_only_read`'s
/// doc for why this is stronger than the default per-value taint scrub.
fn check_wasm_no_output_after_local_only_read(
    caller: &mut Caller<'_, WasmState>,
    policy: &denyx_policy::Policy,
    audit: &Arc<dyn crate::AuditSink>,
    task_id: &str,
    capability: &'static str,
) -> Result<(), wasmtime::Error> {
    if !policy.no_output_after_local_only_read() || caller.data().taint_registry.is_empty() {
        return Ok(());
    }
    let step = caller
        .data()
        .step_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let msg = format!(
        "policy sets [runtime].no_output_after_local_only_read = true and a \
         local-only read has already occurred this run; {capability} (an \
         output-producing call) is refused regardless of whether its specific \
         arguments are tainted"
    );
    emit_scrubbed(
        caller,
        audit,
        crate::AuditEvent::denied(
            task_id,
            step,
            capability,
            "no-output-after-local-only-read",
            &msg,
        ),
    );
    caller.data_mut().captured_error = Some(crate::DenyxError::Policy(msg));
    Err(wasmtime::Error::msg("output refused after local-only read"))
}

/// Emit an audit event after scrubbing any known-tainted substring
/// from its detail payload — the wasm-path equivalent of the
/// in-process Runner's `HostCtx::emit` (`crates/host/src/lib.rs`).
///
/// EVERY wasm audit emission must go through this, never
/// `audit.emit(...)` directly: several denial paths (outbound-taint
/// refusal in particular) build their event detail from the RAW
/// argument value — exactly the local-only bytes the taint layer
/// exists to keep off the runtime boundary. The audit log is itself
/// an outbound channel (it can be forwarded to a remote
/// `HttpAuditSink`), so it needs the same scrub every other output
/// boundary already gets. Before this function existed, wasm's audit
/// emission bypassed scrubbing entirely — a tainted value flowing
/// through an outbound-taint-refusal denial's `target` field was
/// written to the audit log unredacted, in plaintext, on the (default)
/// wasm path, while the native `Runner` correctly redacted the same
/// case via `HostCtx::emit`. Found during the Phase 3 wasm/native
/// parity review; see the fix's commit for a live reproducer.
fn emit_scrubbed(
    caller: &Caller<'_, WasmState>,
    audit: &Arc<dyn crate::AuditSink>,
    event: crate::AuditEvent,
) {
    crate::emit_with_taint_scrub(audit, &caller.data().taint_registry, event);
}

/// Wasm-path mirror of `HostCtx::check_call_limits` (native runner,
/// `crates/host/src/lib.rs`). Called at the top of EVERY effecting
/// import (read and write alike — a runaway loop calling an
/// allow-listed *read* capability many times is exactly the same
/// "agentic mistake" shape as a write loop). Checked before
/// `call_counts` is incremented, so the Nth call against a cap of N
/// is allowed and the (N+1)th is refused.
fn check_wasm_call_limits(
    caller: &mut Caller<'_, WasmState>,
    policy: &denyx_policy::Policy,
    audit: &Arc<dyn crate::AuditSink>,
    task_id: &str,
    capability: &'static str,
) -> Result<(), wasmtime::Error> {
    let max_total = policy.max_total_calls();
    let max_for_cap = policy.max_calls_per_capability().get(capability).copied();
    if max_total.is_none() && max_for_cap.is_none() {
        return Ok(());
    }
    let counts = &caller.data().call_counts;
    if let Some(max_total) = max_total {
        let total_so_far: u64 = counts.values().sum();
        if total_so_far >= max_total {
            let msg = format!(
                "[runtime].max_total_calls = {max_total} reached ({total_so_far} \
                 calls already made this run); {capability} refused"
            );
            return Err(deny_wasm_call_limit(
                caller, audit, task_id, capability, msg,
            ));
        }
    }
    if let Some(max_for_cap) = max_for_cap {
        let count_so_far = *counts.get(capability).unwrap_or(&0);
        if count_so_far >= max_for_cap {
            let msg = format!(
                "[runtime].max_calls_per_capability[{capability:?}] = {max_for_cap} \
                 reached ({count_so_far} calls already made this run)"
            );
            return Err(deny_wasm_call_limit(
                caller, audit, task_id, capability, msg,
            ));
        }
    }
    caller
        .data_mut()
        .call_counts
        .entry(capability.to_string())
        .and_modify(|c| *c += 1)
        .or_insert(1);
    Ok(())
}

fn deny_wasm_call_limit(
    caller: &mut Caller<'_, WasmState>,
    audit: &Arc<dyn crate::AuditSink>,
    task_id: &str,
    capability: &'static str,
    msg: String,
) -> wasmtime::Error {
    let step = caller
        .data()
        .step_counter
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    emit_scrubbed(
        caller,
        audit,
        crate::AuditEvent::denied(task_id, step, capability, "call-limit", &msg),
    );
    caller.data_mut().captured_error = Some(crate::DenyxError::RuntimeLimit(msg));
    wasmtime::Error::msg("call limit reached")
}

use denyx_policy::Policy;
use denyx_runtime_starlark::{STARLARK_INTERPRETER_CWASM, STARLARK_INTERPRETER_WASM};

use crate::taint::{redact_lines, TaintRegistry};
use crate::{
    AuditEvent, AuditSink, ConfirmDecision, ConfirmHook, ConfirmRequest, DenyAllConfirm,
    DenyxError, NullAuditSink, RunOutcome,
};

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
    /// Cached wasmtime engine. Reused across every `run()` call so
    /// the JIT-compile cost is paid once per WasmRunner instance,
    /// not once per script. `Engine` is `Clone`-cheap (internally
    /// Arc-shared) so storing by value is fine.
    engine: Engine,
    /// Cached compiled module — same logic as `engine`. The Starlark
    /// interpreter compiles in ~50-100ms; caching avoids paying that
    /// on every gated MCP tool call.
    module: Module,
}

impl WasmRunner {
    /// Construct a WasmRunner bound to a policy. Defaults to a no-op
    /// audit sink and a deny-everything confirm hook — caller is
    /// expected to override both with [`with_audit`](Self::with_audit)
    /// and [`with_confirm_hook`](Self::with_confirm_hook) in any non-
    /// test context.
    pub fn new(policy: Policy) -> Self {
        // The embedded .wasm is build-time-known-good (see
        // denyx-runtime-starlark's build.rs + tests). Engine + Module
        // construction failures here would mean the .wasm is corrupt
        // — a programmer error, not a runtime condition. expect()'ing
        // keeps the constructor infallible at the API surface.
        let mut config = Config::new();
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        config.consume_fuel(true);
        let engine = Engine::new(&config)
            .expect("wasmtime engine: embedded .wasm build config is known-good");
        // Prefer the AOT-compiled `.cwasm` shipped by denyx-runtime-
        // starlark — single-digit ms to load. If deserialize fails
        // (different wasmtime version, mismatched Config flags,
        // target-architecture mismatch), fall back to JIT-compiling
        // the raw `.wasm` — same behaviour as before AOT existed,
        // ~470ms slower but always correct. Safety: the cwasm bytes
        // come from our own build.rs of the in-tree .wasm; they are
        // not loaded from any external source.
        let module = match unsafe { Module::deserialize(&engine, STARLARK_INTERPRETER_CWASM) } {
            Ok(m) => m,
            Err(_) => Module::new(&engine, STARLARK_INTERPRETER_WASM).expect(
                "wasmtime module: embedded .wasm is known-good (see denyx-runtime-starlark)",
            ),
        };
        Self {
            policy: Arc::new(policy),
            audit: Arc::new(NullAuditSink),
            confirm: Arc::new(DenyAllConfirm),
            engine,
            module,
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
        // Pre-execution verifier — same Rust code, same Policy, as
        // the in-process Runner (crates/host/src/lib.rs:248). Rejects
        // scripts whose static AST pairs a literal-argument local-
        // only read with an output-producing call. The IFC defence-
        // in-depth layer that catches `print(len(secret))` and
        // similar before any evaluator runs.
        crate::verifier::verify(source, &self.policy)
            .map_err(|e| DenyxError::Verifier(e.to_string()))?;

        let request = serde_json::json!({
            "task_id": task_id,
            "source_path": script_name,
            "source": source,
        });
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| DenyxError::Other(format!("serialize wasm request: {e}")))?;

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
            step_counter: std::sync::atomic::AtomicU32::new(0),
            taint_registry: TaintRegistry::default(),
            start_time: Instant::now(),
            call_counts: std::collections::HashMap::new(),
        };
        let mut store = Store::new(&self.engine, state);
        store
            .set_fuel(DEFAULT_WASM_FUEL)
            .map_err(|e| DenyxError::Other(format!("set wasm fuel: {e}")))?;

        let mut linker: Linker<WasmState> = Linker::new(&self.engine);
        add_to_linker_sync(&mut linker, |s: &mut WasmState| &mut s.wasi)
            .map_err(|e| DenyxError::Other(format!("wasi linker: {e}")))?;

        // ── host_print (Phase 4.1) ────────────────────────────────
        let print_policy = self.policy.clone();
        let print_audit = self.audit.clone();
        let print_task_id = task_id.to_owned();
        linker
            .func_wrap(
                "denyx",
                "host_print",
                move |mut caller: Caller<'_, WasmState>,
                      ptr: u32,
                      len: u32|
                      -> Result<(), wasmtime::Error> {
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &print_policy,
                        &print_audit,
                        &print_task_id,
                        "print",
                    )?;
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let len = checked_guest_len(&memory, &caller, ptr, len, "host_print")?;
                    let mut buf = vec![0u8; len];
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
        let fs_read_audit = self.audit.clone();
        let fs_read_confirm = self.confirm.clone();
        let fs_read_task_id = task_id.to_owned();
        linker
            .func_wrap(
                "denyx",
                "host_fs_read",
                move |mut caller: Caller<'_, WasmState>,
                      path_ptr: u32,
                      path_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    check_wasm_deadline(
                        &mut caller,
                        &fs_read_policy,
                        &fs_read_audit,
                        &fs_read_task_id,
                        "fs.read",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &fs_read_policy,
                        &fs_read_audit,
                        &fs_read_task_id,
                        "fs.read",
                    )?;
                    // 1. Read path from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let path_len = checked_guest_len(&memory, &caller, path_ptr, path_len, "path")?;
                    let mut path_buf = vec![0u8; path_len];
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
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &fs_read_audit,
                            AuditEvent::denied(
                                &fs_read_task_id,
                                step,
                                "fs.read",
                                &path,
                                &format!("{e}"),
                            ),
                        );
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("fs.read({path:?}): {e}")));
                        return Err(wasmtime::Error::msg("fs.read denied by policy"));
                    }

                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if fs_read_policy.requires_approval("fs.read") {
                        let decision = fs_read_confirm.confirm(&ConfirmRequest {
                            task_id: fs_read_task_id.clone(),
                            capability: "fs.read".to_string(),
                            summary: format!("fs.read: {path}"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &fs_read_audit,
                                AuditEvent::denied(
                                    &fs_read_task_id,
                                    step,
                                    "fs.read",
                                    &path,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "fs.read denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    // 3. Perform the IO.
                    let content = match std::fs::read_to_string(path_obj) {
                        Ok(c) => c,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &fs_read_audit,
                                AuditEvent::fs(
                                    &fs_read_task_id,
                                    step,
                                    "fs.read",
                                    path_obj,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::Io(e));
                            return Err(wasmtime::Error::msg("fs.read: io error"));
                        }
                    };
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &fs_read_audit,
                        AuditEvent::fs(&fs_read_task_id, step, "fs.read", path_obj, true, None),
                    );

                    // 3b. Register content as tainted if the path is
                    //     declared local-only — its bytes must not
                    //     leak out via print/network at output time.
                    if fs_read_policy.fs_read_is_local_only(path_obj) {
                        caller.data().taint_registry.add(&content);
                    }

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

        // ── host_fs_read_range (perf — bounded read at IO layer) ─
        let fs_read_range_policy = self.policy.clone();
        let fs_read_range_audit = self.audit.clone();
        let fs_read_range_task_id = task_id.to_owned();
        let fs_read_range_confirm = self.confirm.clone();
        linker
            .func_wrap(
                "denyx",
                "host_fs_read_range",
                move |mut caller: Caller<'_, WasmState>,
                      path_ptr: u32,
                      path_len: u32,
                      offset: u64,
                      limit: u64|
                      -> Result<u64, wasmtime::Error> {
                    check_wasm_deadline(
                        &mut caller,
                        &fs_read_range_policy,
                        &fs_read_range_audit,
                        &fs_read_range_task_id,
                        "fs.read",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &fs_read_range_policy,
                        &fs_read_range_audit,
                        &fs_read_range_task_id,
                        "fs.read",
                    )?;
                    use std::io::{Read, Seek, SeekFrom};
                    // 1. Read path from guest memory.
                    let path = read_string_from_guest(&mut caller, path_ptr, path_len, "path")?;

                    // 2. Gate through policy (same as fs.read).
                    let path_obj = std::path::Path::new(&path);
                    if let Err(e) = fs_read_range_policy.check_fs_read(path_obj) {
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &fs_read_range_audit,
                            AuditEvent::denied(
                                &fs_read_range_task_id,
                                step,
                                "fs.read",
                                &path,
                                &format!("{e}"),
                            ),
                        );
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("fs.read({path:?}): {e}")));
                        return Err(wasmtime::Error::msg("fs.read denied by policy"));
                    }

                    // 3. Capability-level confirm gate.
                    if fs_read_range_policy.requires_approval("fs.read") {
                        let decision = fs_read_range_confirm.confirm(&ConfirmRequest {
                            task_id: fs_read_range_task_id.clone(),
                            capability: "fs.read".to_string(),
                            summary: format!("fs.read_range: {path} [{offset}..+{limit}]"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &fs_read_range_audit,
                                AuditEvent::denied(
                                    &fs_read_range_task_id,
                                    step,
                                    "fs.read",
                                    &path,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "fs.read denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    // 4. Perform the bounded IO. File::open + seek +
                    //    take(limit). Avoids loading the whole file
                    //    into memory for surgical reads.
                    let content_bytes: Vec<u8> = match (|| -> std::io::Result<Vec<u8>> {
                        let mut file = std::fs::File::open(path_obj)?;
                        file.seek(SeekFrom::Start(offset))?;
                        let mut buf = Vec::new();
                        file.take(limit).read_to_end(&mut buf)?;
                        Ok(buf)
                    })() {
                        Ok(b) => b,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &fs_read_range_audit,
                                AuditEvent::fs(
                                    &fs_read_range_task_id,
                                    step,
                                    "fs.read",
                                    path_obj,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::Io(e));
                            return Err(wasmtime::Error::msg("fs.read_range: io error"));
                        }
                    };

                    // 5. Success audit.
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &fs_read_range_audit,
                        AuditEvent::fs(
                            &fs_read_range_task_id,
                            step,
                            "fs.read",
                            path_obj,
                            true,
                            None,
                        ),
                    );

                    // 6. Taint registration if path is local-only.
                    if fs_read_range_policy.fs_read_is_local_only(path_obj) {
                        if let Ok(s) = std::str::from_utf8(&content_bytes) {
                            caller.data().taint_registry.add(s);
                        }
                    }

                    if content_bytes.is_empty() {
                        return Ok(0);
                    }

                    // 7. Allocate buffer in guest memory + write.
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
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    memory
                        .write(&mut caller, dest_ptr as usize, &content_bytes)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_fs_read_range: write content: {e}"))
                        })?;
                    Ok(((dest_ptr as u64) << 32) | (content_bytes.len() as u64))
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_fs_read_range: {e}")))?;

        // ── host_fs_write (Phase 4.4) ─────────────────────────────
        let fs_write_policy = self.policy.clone();
        let fs_write_audit = self.audit.clone();
        let fs_write_confirm = self.confirm.clone();
        let fs_write_task_id = task_id.to_owned();
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
                    check_wasm_deadline(
                        &mut caller,
                        &fs_write_policy,
                        &fs_write_audit,
                        &fs_write_task_id,
                        "fs.write",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &fs_write_policy,
                        &fs_write_audit,
                        &fs_write_task_id,
                        "fs.write",
                    )?;
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &fs_write_policy,
                        &fs_write_audit,
                        &fs_write_task_id,
                        "fs.write",
                    )?;
                    // 1. Read path and content from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let path_len = checked_guest_len(&memory, &caller, path_ptr, path_len, "path")?;
                    let mut path_buf = vec![0u8; path_len];
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
                    let content_len =
                        checked_guest_len(&memory, &caller, content_ptr, content_len, "content")?;
                    let mut content_buf = vec![0u8; content_len];
                    memory
                        .read(&caller, content_ptr as usize, &mut content_buf)
                        .map_err(|e| {
                            wasmtime::Error::msg(format!("host_fs_write: content read: {e}"))
                        })?;

                    // 2. Gate through policy.
                    let path_obj = std::path::Path::new(&path);
                    if let Err(e) = fs_write_policy.check_fs_write(path_obj) {
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &fs_write_audit,
                            AuditEvent::denied(
                                &fs_write_task_id,
                                step,
                                "fs.write",
                                &path,
                                &format!("{e}"),
                            ),
                        );
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("fs.write({path:?}): {e}")));
                        return Err(wasmtime::Error::msg("fs.write denied by policy"));
                    }

                    // Outbound taint refusal. Shared with the native Runner via
                    // `crate::check_outbound_taint` — see that function's doc for
                    // why this used to be hand-duplicated per runner.
                    let content_str = std::str::from_utf8(&content_buf).unwrap_or("");
                    let summary = format!("write {path} ({} bytes)", content_buf.len());
                    if let Some(msg) = crate::check_outbound_taint(
                        &caller.data().taint_registry,
                        &fs_write_audit,
                        &fs_write_task_id,
                        "fs.write",
                        &summary,
                        &[("path", path.as_str()), ("content", content_str)],
                        || {
                            caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        },
                    ) {
                        caller.data_mut().captured_error = Some(DenyxError::Policy(msg));
                        return Err(wasmtime::Error::msg("outbound taint refused"));
                    }

                    // 3. Perform the IO. We accept arbitrary bytes
                    //    from the guest (content is treated as opaque
                    //    bytes here, not necessarily UTF-8). Starlark
                    //    strings are UTF-8 so this is a no-op for
                    //    well-typed input, but the host shouldn't
                    //    impose a tighter contract than the wire
                    //    protocol demands.
                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if fs_write_policy.requires_approval("fs.write") {
                        let decision = fs_write_confirm.confirm(&ConfirmRequest {
                            task_id: fs_write_task_id.clone(),
                            capability: "fs.write".to_string(),
                            summary: format!("fs.write: {path} ({} bytes)", content_buf.len()),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &fs_write_audit,
                                AuditEvent::denied(
                                    &fs_write_task_id,
                                    step,
                                    "fs.write",
                                    &path,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "fs.write denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    if let Err(e) = std::fs::write(path_obj, &content_buf) {
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &fs_write_audit,
                            AuditEvent::fs(
                                &fs_write_task_id,
                                step,
                                "fs.write",
                                path_obj,
                                false,
                                Some(format!("io: {e}")),
                            ),
                        );
                        caller.data_mut().captured_error = Some(DenyxError::Io(e));
                        return Err(wasmtime::Error::msg("fs.write: io error"));
                    }
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &fs_write_audit,
                        AuditEvent::fs(&fs_write_task_id, step, "fs.write", path_obj, true, None),
                    );

                    Ok(())
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_fs_write: {e}")))?;

        // ── host_fs_delete (Phase 4.5) ────────────────────────────
        let fs_delete_policy = self.policy.clone();
        let fs_delete_audit = self.audit.clone();
        let fs_delete_confirm = self.confirm.clone();
        let fs_delete_task_id = task_id.to_owned();
        linker
            .func_wrap(
                "denyx",
                "host_fs_delete",
                move |mut caller: Caller<'_, WasmState>,
                      path_ptr: u32,
                      path_len: u32|
                      -> Result<(), wasmtime::Error> {
                    check_wasm_deadline(
                        &mut caller,
                        &fs_delete_policy,
                        &fs_delete_audit,
                        &fs_delete_task_id,
                        "fs.delete",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &fs_delete_policy,
                        &fs_delete_audit,
                        &fs_delete_task_id,
                        "fs.delete",
                    )?;
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &fs_delete_policy,
                        &fs_delete_audit,
                        &fs_delete_task_id,
                        "fs.delete",
                    )?;
                    // 1. Read path from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let path_len = checked_guest_len(&memory, &caller, path_ptr, path_len, "path")?;
                    let mut path_buf = vec![0u8; path_len];
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
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &fs_delete_audit,
                            AuditEvent::denied(
                                &fs_delete_task_id,
                                step,
                                "fs.delete",
                                &path,
                                &format!("{e}"),
                            ),
                        );
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("fs.delete({path:?}): {e}")));
                        return Err(wasmtime::Error::msg("fs.delete denied by policy"));
                    }

                    // Outbound taint refusal. Shared with the native Runner via
                    // `crate::check_outbound_taint`.
                    let summary = format!("delete {path}");
                    if let Some(msg) = crate::check_outbound_taint(
                        &caller.data().taint_registry,
                        &fs_delete_audit,
                        &fs_delete_task_id,
                        "fs.delete",
                        &summary,
                        &[("path", path.as_str())],
                        || {
                            caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        },
                    ) {
                        caller.data_mut().captured_error = Some(DenyxError::Policy(msg));
                        return Err(wasmtime::Error::msg("outbound taint refused"));
                    }

                    // 3. Perform the IO. remove_file matches the
                    //    in-process Runner's behaviour: fs.delete is
                    //    file-targeted, not recursive directory
                    //    removal.
                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if fs_delete_policy.requires_approval("fs.delete") {
                        let decision = fs_delete_confirm.confirm(&ConfirmRequest {
                            task_id: fs_delete_task_id.clone(),
                            capability: "fs.delete".to_string(),
                            summary: format!("fs.delete: {path}"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &fs_delete_audit,
                                AuditEvent::denied(
                                    &fs_delete_task_id,
                                    step,
                                    "fs.delete",
                                    &path,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "fs.delete denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    if let Err(e) = std::fs::remove_file(path_obj) {
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &fs_delete_audit,
                            AuditEvent::fs(
                                &fs_delete_task_id,
                                step,
                                "fs.delete",
                                path_obj,
                                false,
                                Some(format!("io: {e}")),
                            ),
                        );
                        caller.data_mut().captured_error = Some(DenyxError::Io(e));
                        return Err(wasmtime::Error::msg("fs.delete: io error"));
                    }
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &fs_delete_audit,
                        AuditEvent::fs(&fs_delete_task_id, step, "fs.delete", path_obj, true, None),
                    );

                    Ok(())
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_fs_delete: {e}")))?;

        // ── host_env_read (Phase 4.6) ─────────────────────────────
        let env_read_policy = self.policy.clone();
        let env_read_audit = self.audit.clone();
        let env_read_confirm = self.confirm.clone();
        let env_read_task_id = task_id.to_owned();
        linker
            .func_wrap(
                "denyx",
                "host_env_read",
                move |mut caller: Caller<'_, WasmState>,
                      name_ptr: u32,
                      name_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    check_wasm_deadline(
                        &mut caller,
                        &env_read_policy,
                        &env_read_audit,
                        &env_read_task_id,
                        "env.read",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &env_read_policy,
                        &env_read_audit,
                        &env_read_task_id,
                        "env.read",
                    )?;
                    // 1. Read name from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let name_len = checked_guest_len(&memory, &caller, name_ptr, name_len, "name")?;
                    let mut name_buf = vec![0u8; name_len];
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
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &env_read_audit,
                            AuditEvent::denied(
                                &env_read_task_id,
                                step,
                                "env.read",
                                &name,
                                &format!("{e}"),
                            ),
                        );
                        caller.data_mut().captured_error =
                            Some(DenyxError::Policy(format!("env.read({name:?}): {e}")));
                        return Err(wasmtime::Error::msg("env.read denied by policy"));
                    }

                    // 3. Read the env var. Missing var surfaces as
                    //    DenyxError::Other — matches the in-process
                    //    Runner, which raises a Starlark error rather
                    //    than returning an empty string.
                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if env_read_policy.requires_approval("env.read") {
                        let decision = env_read_confirm.confirm(&ConfirmRequest {
                            task_id: env_read_task_id.clone(),
                            capability: "env.read".to_string(),
                            summary: format!("env.read: {name}"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &env_read_audit,
                                AuditEvent::denied(
                                    &env_read_task_id,
                                    step,
                                    "env.read",
                                    &name,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "env.read denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    let value = match std::env::var(&name) {
                        Ok(v) => v,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &env_read_audit,
                                AuditEvent::env(
                                    &env_read_task_id,
                                    step,
                                    &name,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("env.read({name:?}): {e}")));
                            return Err(wasmtime::Error::msg("env.read: lookup error"));
                        }
                    };
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &env_read_audit,
                        AuditEvent::env(&env_read_task_id, step, &name, true, None),
                    );

                    // Register tainted value if the var is declared
                    // local-only.
                    if env_read_policy.env_is_local_only(&name) {
                        caller.data().taint_registry.add(&value);
                    }

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
        let subprocess_audit = self.audit.clone();
        let subprocess_confirm = self.confirm.clone();
        let subprocess_task_id = task_id.to_owned();
        linker
            .func_wrap(
                "denyx",
                "host_subprocess_exec",
                move |mut caller: Caller<'_, WasmState>,
                      argv_json_ptr: u32,
                      argv_json_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    check_wasm_deadline(
                        &mut caller,
                        &subprocess_policy,
                        &subprocess_audit,
                        &subprocess_task_id,
                        "subprocess.exec",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &subprocess_policy,
                        &subprocess_audit,
                        &subprocess_task_id,
                        "subprocess.exec",
                    )?;
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &subprocess_policy,
                        &subprocess_audit,
                        &subprocess_task_id,
                        "subprocess.exec",
                    )?;
                    // 1. Read argv JSON from guest memory.
                    let memory = caller
                        .get_export("memory")
                        .and_then(Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("guest missing `memory` export"))?;
                    let argv_json_len =
                        checked_guest_len(&memory, &caller, argv_json_ptr, argv_json_len, "argv")?;
                    let mut argv_buf = vec![0u8; argv_json_len];
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
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &subprocess_audit,
                            AuditEvent::denied(
                                &subprocess_task_id,
                                step,
                                "subprocess.exec",
                                "",
                                "empty argv",
                            ),
                        );
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
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &subprocess_audit,
                            AuditEvent::subprocess(
                                &subprocess_task_id,
                                step,
                                &argv,
                                None,
                                false,
                                Some(format!("policy: {e}")),
                            ),
                        );
                        caller.data_mut().captured_error = Some(DenyxError::Policy(format!(
                            "subprocess.exec({:?}): {e}",
                            argv[0]
                        )));
                        return Err(wasmtime::Error::msg("subprocess.exec: command denied"));
                    }
                    if let Err(e) = subprocess_policy.check_subprocess_args(&argv) {
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &subprocess_audit,
                            AuditEvent::subprocess(
                                &subprocess_task_id,
                                step,
                                &argv,
                                None,
                                false,
                                Some(format!("policy: {e}")),
                            ),
                        );
                        caller.data_mut().captured_error = Some(DenyxError::Policy(format!(
                            "subprocess.exec({:?}): {e}",
                            argv
                        )));
                        return Err(wasmtime::Error::msg("subprocess.exec: args denied"));
                    }
                    if let Err(e) = subprocess_policy.check_subprocess_argv_paths(&argv) {
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &subprocess_audit,
                            AuditEvent::subprocess(
                                &subprocess_task_id,
                                step,
                                &argv,
                                None,
                                false,
                                Some(format!("policy: {e}")),
                            ),
                        );
                        caller.data_mut().captured_error = Some(DenyxError::Policy(format!(
                            "subprocess.exec({:?}): {e}",
                            argv
                        )));
                        return Err(wasmtime::Error::msg("subprocess.exec: argv path denied"));
                    }

                    // Outbound taint refusal. Shared with the native Runner via
                    // `crate::check_outbound_taint`. Skipped when the command
                    // itself is local-only (its output is also tainted, so a
                    // secret passed to it can't escape via that channel) —
                    // matches the native Runner's guard exactly. This closure
                    // previously applied the check unconditionally, denying
                    // legitimate local-only-command use that native allowed.
                    if !subprocess_policy.subprocess_is_local_only(&argv[0]) {
                        let cmd_summary = argv.join(" ");
                        let pairs: Vec<(String, String)> = argv
                            .iter()
                            .enumerate()
                            .map(|(i, v)| (format!("argv[{i}]"), v.clone()))
                            .collect();
                        let pair_refs: Vec<(&str, &str)> = pairs
                            .iter()
                            .map(|(l, v)| (l.as_str(), v.as_str()))
                            .collect();
                        if let Some(msg) = crate::check_outbound_taint(
                            &caller.data().taint_registry,
                            &subprocess_audit,
                            &subprocess_task_id,
                            "subprocess.exec",
                            &format!("exec: {cmd_summary}"),
                            &pair_refs,
                            || {
                                caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            },
                        ) {
                            caller.data_mut().captured_error = Some(DenyxError::Policy(msg));
                            return Err(wasmtime::Error::msg("outbound taint refused"));
                        }
                    }

                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if subprocess_policy.requires_approval("subprocess.exec") {
                        let decision = subprocess_confirm.confirm(&ConfirmRequest {
                            task_id: subprocess_task_id.clone(),
                            capability: "subprocess.exec".to_string(),
                            summary: format!("subprocess.exec: {}", argv.join(" ")),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &subprocess_audit,
                                AuditEvent::denied(
                                    &subprocess_task_id,
                                    step,
                                    "subprocess.exec",
                                    &argv.join(" "),
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "subprocess.exec denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    // Per-argv requires_approval_args gate. Even if
                    // subprocess.exec is broadly allowed, specific argv
                    // patterns (e.g. `git push`) may still need approval.
                    // Returns Some(matched_pattern) if any pattern matches.
                    if let Some(matched) =
                        subprocess_policy.subprocess_argv_requires_approval(&argv)
                    {
                        let decision = subprocess_confirm.confirm(&ConfirmRequest {
                            task_id: subprocess_task_id.clone(),
                            capability: "subprocess.exec".to_string(),
                            summary: format!(
                                "{} (matched requires_approval pattern: {matched})",
                                argv.join(" ")
                            ),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &subprocess_audit,
                                AuditEvent::denied(
                                    &subprocess_task_id,
                                    step,
                                    "subprocess.exec",
                                    &argv.join(" "),
                                    &format!("confirm hook denied (pattern: {matched})"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::ConfirmDenied(format!(
                                    "subprocess.exec denied by confirm hook (pattern: {matched})"
                                )));
                            return Err(wasmtime::Error::msg("confirm denied (per-argv)"));
                        }
                    }

                    // 3. Spawn the process. Env filtering matches the
                    //    in-process Runner: `policy.subprocess_env(argv0)`
                    //    returns the (name, value) pairs the child should
                    //    see, honouring `allow_vars` plus the local-only
                    //    overlay when the command is itself local-only.
                    //    `[subprocess].sandbox = "bwrap"` mirrors the native
                    //    Runner: bubblewrap builds a fresh namespaced jail
                    //    per call (bind mounts derived from the policy,
                    //    network namespace dropped when no HTTP verb is
                    //    allowed), so a legitimately-allowed command can't
                    //    reach paths or network the policy didn't grant it
                    //    via ambient OS access. Without this branch that
                    //    isolation was silently absent on the wasm path.
                    let env_pairs = subprocess_policy.subprocess_env(&argv[0]);
                    let output = match subprocess_policy.sandbox_mode() {
                        denyx_policy::SandboxMode::None => {
                            let mut cmd = std::process::Command::new(&argv[0]);
                            cmd.args(&argv[1..]);
                            cmd.env_clear();
                            for (name, value) in &env_pairs {
                                cmd.env(name, value);
                            }
                            cmd.output()
                        }
                        denyx_policy::SandboxMode::Bwrap => {
                            let bwrap_argv = subprocess_policy.bwrap_argv(&argv, &env_pairs);
                            let mut cmd = std::process::Command::new(&bwrap_argv[0]);
                            cmd.args(&bwrap_argv[1..]);
                            cmd.env_clear();
                            cmd.output()
                        }
                        denyx_policy::SandboxMode::Landlock => {
                            #[cfg(target_os = "linux")]
                            {
                                let (read_paths, write_paths) =
                                    subprocess_policy.sandbox_fs_paths();
                                let deny_network =
                                    !subprocess_policy.any_network_capability_granted();
                                let mut cmd = std::process::Command::new(&argv[0]);
                                cmd.args(&argv[1..]);
                                cmd.env_clear();
                                for (name, value) in &env_pairs {
                                    cmd.env(name, value);
                                }
                                crate::landlock_sandbox::wire_pre_exec(
                                    &mut cmd,
                                    read_paths,
                                    write_paths,
                                    deny_network,
                                );
                                cmd.output()
                            }
                            #[cfg(not(target_os = "linux"))]
                            {
                                Err(std::io::Error::other(
                                    "landlock sandboxing is Linux-only; this should have \
                                     been refused at policy load",
                                ))
                            }
                        }
                    };
                    let output = match output {
                        Ok(o) => o,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &subprocess_audit,
                                AuditEvent::subprocess(
                                    &subprocess_task_id,
                                    step,
                                    &argv,
                                    None,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
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
                        let step = caller
                            .data()
                            .step_counter
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        emit_scrubbed(
                            &caller,
                            &subprocess_audit,
                            AuditEvent::subprocess(
                                &subprocess_task_id,
                                step,
                                &argv,
                                output.status.code(),
                                false,
                                Some(format!("exit {code}: {stderr}")),
                            ),
                        );
                        caller.data_mut().captured_error = Some(DenyxError::Other(format!(
                            "subprocess.exec({:?}) exited {code}: {stderr}",
                            argv
                        )));
                        return Err(wasmtime::Error::msg("subprocess.exec: non-zero exit"));
                    }
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &subprocess_audit,
                        AuditEvent::subprocess(
                            &subprocess_task_id,
                            step,
                            &argv,
                            output.status.code(),
                            true,
                            None,
                        ),
                    );

                    if subprocess_policy.subprocess_is_local_only(&argv[0]) {
                        let stdout_str = String::from_utf8_lossy(&output.stdout);
                        caller.data().taint_registry.add(stdout_str.as_ref());
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
        let http_get_audit = self.audit.clone();
        let http_get_confirm = self.confirm.clone();
        let http_get_task_id = task_id.to_owned();
        linker
            .func_wrap(
                "denyx",
                "host_net_http_get",
                move |mut caller: Caller<'_, WasmState>,
                      url_ptr: u32,
                      url_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    check_wasm_deadline(
                        &mut caller,
                        &http_get_policy,
                        &http_get_audit,
                        &http_get_task_id,
                        "net.http_get",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &http_get_policy,
                        &http_get_audit,
                        &http_get_task_id,
                        "net.http_get",
                    )?;
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &http_get_policy,
                        &http_get_audit,
                        &http_get_task_id,
                        "net.http_get",
                    )?;
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    let parsed = match http_get_policy.check_http_get(&url) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_get_audit,
                                AuditEvent::denied(
                                    &http_get_task_id,
                                    step,
                                    "net.http_get",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_get({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_get denied"));
                        }
                    };
                    // Hostname-based `[network].deny_ips` — a literal-IP URL is
                    // already covered by check_http_get itself; this catches a
                    // hostname that resolves to a denied IP (SSRF / cloud
                    // metadata / RFC1918 targets reached via an allow-listed
                    // hostname).
                    if let Some(host) = parsed.host_str() {
                        if let Err(e) = crate::dns_check(&http_get_policy, "http_get", host) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_get_audit,
                                AuditEvent::denied(
                                    &http_get_task_id,
                                    step,
                                    "net.http_get",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_get({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_get denied"));
                        }
                    }
                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if http_get_policy.requires_approval("net.http_get") {
                        let decision = http_get_confirm.confirm(&ConfirmRequest {
                            task_id: http_get_task_id.clone(),
                            capability: "net.http_get".to_string(),
                            summary: format!("net.http_get: {url}"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_get_audit,
                                AuditEvent::denied(
                                    &http_get_task_id,
                                    step,
                                    "net.http_get",
                                    &url,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "net.http_get denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    // Outbound taint refusal only fires when the destination is NOT
                    // itself local-only — a local-only host receiving a local-only
                    // value isn't a boundary crossing.
                    let parsed_host = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                        .unwrap_or_default();
                    if !http_get_policy.host_is_local_only(&parsed_host) {
                        if let Some(msg) = crate::check_outbound_taint(
                            &caller.data().taint_registry,
                            &http_get_audit,
                            &http_get_task_id,
                            "net.http_get",
                            &format!("GET {parsed}"),
                            &[("url", url.as_str())],
                            || {
                                caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            },
                        ) {
                            caller.data_mut().captured_error = Some(DenyxError::Policy(msg));
                            return Err(wasmtime::Error::msg("outbound taint refused"));
                        }
                    }

                    let body = match crate::no_redirect_agent()
                        .get(&url)
                        .timeout(http_get_policy.network_timeout())
                        .call()
                    {
                        Ok(resp) => match crate::finalize_http_response(resp) {
                            Ok(s) => s,
                            Err(e) => {
                                let step = caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                emit_scrubbed(
                                    &caller,
                                    &http_get_audit,
                                    AuditEvent::http(
                                        &http_get_task_id,
                                        step,
                                        "net.http_get",
                                        &url,
                                        false,
                                        Some(format!("io: {e}")),
                                    ),
                                );
                                caller.data_mut().captured_error =
                                    Some(DenyxError::Other(format!("net.http_get({url:?}): {e}")));
                                return Err(wasmtime::Error::msg("net.http_get: finalize"));
                            }
                        },
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_get_audit,
                                AuditEvent::http(
                                    &http_get_task_id,
                                    step,
                                    "net.http_get",
                                    &url,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_get({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_get: request failed"));
                        }
                    };
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &http_get_audit,
                        AuditEvent::http(&http_get_task_id, step, "net.http_get", &url, true, None),
                    );
                    if let Some(host) = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                    {
                        if http_get_policy.host_is_local_only(&host) {
                            caller.data().taint_registry.add(&body);
                        }
                    }
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_get: {e}")))?;

        // ── host_net_http_post (Phase 4.8) ────────────────────────
        let http_post_policy = self.policy.clone();
        let http_post_audit = self.audit.clone();
        let http_post_confirm = self.confirm.clone();
        let http_post_task_id = task_id.to_owned();
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
                    check_wasm_deadline(
                        &mut caller,
                        &http_post_policy,
                        &http_post_audit,
                        &http_post_task_id,
                        "net.http_post",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &http_post_policy,
                        &http_post_audit,
                        &http_post_task_id,
                        "net.http_post",
                    )?;
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &http_post_policy,
                        &http_post_audit,
                        &http_post_task_id,
                        "net.http_post",
                    )?;
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    let req_body = read_string_from_guest(&mut caller, body_ptr, body_len, "body")?;
                    let parsed = match http_post_policy.check_http_post(&url) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_post_audit,
                                AuditEvent::denied(
                                    &http_post_task_id,
                                    step,
                                    "net.http_post",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_post({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_post denied"));
                        }
                    };
                    if let Some(host) = parsed.host_str() {
                        if let Err(e) = crate::dns_check(&http_post_policy, "http_post", host) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_post_audit,
                                AuditEvent::denied(
                                    &http_post_task_id,
                                    step,
                                    "net.http_post",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_post({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_post denied"));
                        }
                    }
                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if http_post_policy.requires_approval("net.http_post") {
                        let decision = http_post_confirm.confirm(&ConfirmRequest {
                            task_id: http_post_task_id.clone(),
                            capability: "net.http_post".to_string(),
                            summary: format!("net.http_post: {url}"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_post_audit,
                                AuditEvent::denied(
                                    &http_post_task_id,
                                    step,
                                    "net.http_post",
                                    &url,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "net.http_post denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    // Outbound taint refusal only fires when the destination is NOT
                    // itself local-only — a local-only host receiving a local-only
                    // value isn't a boundary crossing.
                    let parsed_host = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                        .unwrap_or_default();
                    if !http_post_policy.host_is_local_only(&parsed_host) {
                        if let Some(msg) = crate::check_outbound_taint(
                            &caller.data().taint_registry,
                            &http_post_audit,
                            &http_post_task_id,
                            "net.http_post",
                            &format!("POST {parsed} ({} bytes)", req_body.len()),
                            &[("url", url.as_str()), ("body", req_body.as_str())],
                            || {
                                caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            },
                        ) {
                            caller.data_mut().captured_error = Some(DenyxError::Policy(msg));
                            return Err(wasmtime::Error::msg("outbound taint refused"));
                        }
                    }

                    let body = match crate::no_redirect_agent()
                        .post(&url)
                        .timeout(http_post_policy.network_timeout())
                        .send_string(&req_body)
                    {
                        Ok(resp) => match crate::finalize_http_response(resp) {
                            Ok(s) => s,
                            Err(e) => {
                                let step = caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                emit_scrubbed(
                                    &caller,
                                    &http_post_audit,
                                    AuditEvent::http(
                                        &http_post_task_id,
                                        step,
                                        "net.http_post",
                                        &url,
                                        false,
                                        Some(format!("io: {e}")),
                                    ),
                                );
                                caller.data_mut().captured_error =
                                    Some(DenyxError::Other(format!("net.http_post({url:?}): {e}")));
                                return Err(wasmtime::Error::msg("net.http_post: finalize"));
                            }
                        },
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_post_audit,
                                AuditEvent::http(
                                    &http_post_task_id,
                                    step,
                                    "net.http_post",
                                    &url,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_post({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_post: request failed"));
                        }
                    };
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &http_post_audit,
                        AuditEvent::http(
                            &http_post_task_id,
                            step,
                            "net.http_post",
                            &url,
                            true,
                            None,
                        ),
                    );
                    if let Some(host) = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                    {
                        if http_post_policy.host_is_local_only(&host) {
                            caller.data().taint_registry.add(&body);
                        }
                    }
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_post: {e}")))?;

        // ── host_net_http_put (Phase 4.8) ─────────────────────────
        let http_put_policy = self.policy.clone();
        let http_put_audit = self.audit.clone();
        let http_put_confirm = self.confirm.clone();
        let http_put_task_id = task_id.to_owned();
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
                    check_wasm_deadline(
                        &mut caller,
                        &http_put_policy,
                        &http_put_audit,
                        &http_put_task_id,
                        "net.http_put",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &http_put_policy,
                        &http_put_audit,
                        &http_put_task_id,
                        "net.http_put",
                    )?;
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &http_put_policy,
                        &http_put_audit,
                        &http_put_task_id,
                        "net.http_put",
                    )?;
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    let req_body = read_string_from_guest(&mut caller, body_ptr, body_len, "body")?;
                    let parsed = match http_put_policy.check_http_put(&url) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_put_audit,
                                AuditEvent::denied(
                                    &http_put_task_id,
                                    step,
                                    "net.http_put",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_put({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_put denied"));
                        }
                    };
                    if let Some(host) = parsed.host_str() {
                        if let Err(e) = crate::dns_check(&http_put_policy, "http_put", host) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_put_audit,
                                AuditEvent::denied(
                                    &http_put_task_id,
                                    step,
                                    "net.http_put",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_put({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_put denied"));
                        }
                    }
                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if http_put_policy.requires_approval("net.http_put") {
                        let decision = http_put_confirm.confirm(&ConfirmRequest {
                            task_id: http_put_task_id.clone(),
                            capability: "net.http_put".to_string(),
                            summary: format!("net.http_put: {url}"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_put_audit,
                                AuditEvent::denied(
                                    &http_put_task_id,
                                    step,
                                    "net.http_put",
                                    &url,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "net.http_put denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    // Outbound taint refusal only fires when the destination is NOT
                    // itself local-only — a local-only host receiving a local-only
                    // value isn't a boundary crossing.
                    let parsed_host = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                        .unwrap_or_default();
                    if !http_put_policy.host_is_local_only(&parsed_host) {
                        if let Some(msg) = crate::check_outbound_taint(
                            &caller.data().taint_registry,
                            &http_put_audit,
                            &http_put_task_id,
                            "net.http_put",
                            &format!("PUT {parsed} ({} bytes)", req_body.len()),
                            &[("url", url.as_str()), ("body", req_body.as_str())],
                            || {
                                caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            },
                        ) {
                            caller.data_mut().captured_error = Some(DenyxError::Policy(msg));
                            return Err(wasmtime::Error::msg("outbound taint refused"));
                        }
                    }

                    let body = match crate::no_redirect_agent()
                        .put(&url)
                        .timeout(http_put_policy.network_timeout())
                        .send_string(&req_body)
                    {
                        Ok(resp) => match crate::finalize_http_response(resp) {
                            Ok(s) => s,
                            Err(e) => {
                                let step = caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                emit_scrubbed(
                                    &caller,
                                    &http_put_audit,
                                    AuditEvent::http(
                                        &http_put_task_id,
                                        step,
                                        "net.http_put",
                                        &url,
                                        false,
                                        Some(format!("io: {e}")),
                                    ),
                                );
                                caller.data_mut().captured_error =
                                    Some(DenyxError::Other(format!("net.http_put({url:?}): {e}")));
                                return Err(wasmtime::Error::msg("net.http_put: finalize"));
                            }
                        },
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_put_audit,
                                AuditEvent::http(
                                    &http_put_task_id,
                                    step,
                                    "net.http_put",
                                    &url,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_put({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_put: request failed"));
                        }
                    };
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &http_put_audit,
                        AuditEvent::http(&http_put_task_id, step, "net.http_put", &url, true, None),
                    );
                    if let Some(host) = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                    {
                        if http_put_policy.host_is_local_only(&host) {
                            caller.data().taint_registry.add(&body);
                        }
                    }
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_put: {e}")))?;

        // ── host_net_http_patch (Phase 4.8) ───────────────────────
        let http_patch_policy = self.policy.clone();
        let http_patch_audit = self.audit.clone();
        let http_patch_confirm = self.confirm.clone();
        let http_patch_task_id = task_id.to_owned();
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
                    check_wasm_deadline(
                        &mut caller,
                        &http_patch_policy,
                        &http_patch_audit,
                        &http_patch_task_id,
                        "net.http_patch",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &http_patch_policy,
                        &http_patch_audit,
                        &http_patch_task_id,
                        "net.http_patch",
                    )?;
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &http_patch_policy,
                        &http_patch_audit,
                        &http_patch_task_id,
                        "net.http_patch",
                    )?;
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    let req_body = read_string_from_guest(&mut caller, body_ptr, body_len, "body")?;
                    let parsed = match http_patch_policy.check_http_patch(&url) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_patch_audit,
                                AuditEvent::denied(
                                    &http_patch_task_id,
                                    step,
                                    "net.http_patch",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_patch({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_patch denied"));
                        }
                    };
                    if let Some(host) = parsed.host_str() {
                        if let Err(e) = crate::dns_check(&http_patch_policy, "http_patch", host) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_patch_audit,
                                AuditEvent::denied(
                                    &http_patch_task_id,
                                    step,
                                    "net.http_patch",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_patch({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_patch denied"));
                        }
                    }
                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if http_patch_policy.requires_approval("net.http_patch") {
                        let decision = http_patch_confirm.confirm(&ConfirmRequest {
                            task_id: http_patch_task_id.clone(),
                            capability: "net.http_patch".to_string(),
                            summary: format!("net.http_patch: {url}"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_patch_audit,
                                AuditEvent::denied(
                                    &http_patch_task_id,
                                    step,
                                    "net.http_patch",
                                    &url,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "net.http_patch denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    // Outbound taint refusal only fires when the destination is NOT
                    // itself local-only — a local-only host receiving a local-only
                    // value isn't a boundary crossing.
                    let parsed_host = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                        .unwrap_or_default();
                    if !http_patch_policy.host_is_local_only(&parsed_host) {
                        if let Some(msg) = crate::check_outbound_taint(
                            &caller.data().taint_registry,
                            &http_patch_audit,
                            &http_patch_task_id,
                            "net.http_patch",
                            &format!("PATCH {parsed} ({} bytes)", req_body.len()),
                            &[("url", url.as_str()), ("body", req_body.as_str())],
                            || {
                                caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            },
                        ) {
                            caller.data_mut().captured_error = Some(DenyxError::Policy(msg));
                            return Err(wasmtime::Error::msg("outbound taint refused"));
                        }
                    }

                    let body = match crate::no_redirect_agent()
                        .request("PATCH", &url)
                        .timeout(http_patch_policy.network_timeout())
                        .send_string(&req_body)
                    {
                        Ok(resp) => match crate::finalize_http_response(resp) {
                            Ok(s) => s,
                            Err(e) => {
                                let step = caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                emit_scrubbed(
                                    &caller,
                                    &http_patch_audit,
                                    AuditEvent::http(
                                        &http_patch_task_id,
                                        step,
                                        "net.http_patch",
                                        &url,
                                        false,
                                        Some(format!("io: {e}")),
                                    ),
                                );
                                caller.data_mut().captured_error = Some(DenyxError::Other(
                                    format!("net.http_patch({url:?}): {e}"),
                                ));
                                return Err(wasmtime::Error::msg("net.http_patch: finalize"));
                            }
                        },
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_patch_audit,
                                AuditEvent::http(
                                    &http_patch_task_id,
                                    step,
                                    "net.http_patch",
                                    &url,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_patch({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_patch: request failed"));
                        }
                    };
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &http_patch_audit,
                        AuditEvent::http(
                            &http_patch_task_id,
                            step,
                            "net.http_patch",
                            &url,
                            true,
                            None,
                        ),
                    );
                    if let Some(host) = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                    {
                        if http_patch_policy.host_is_local_only(&host) {
                            caller.data().taint_registry.add(&body);
                        }
                    }
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_patch: {e}")))?;

        // ── host_net_http_delete (Phase 4.8) ──────────────────────
        let http_delete_policy = self.policy.clone();
        let http_delete_audit = self.audit.clone();
        let http_delete_confirm = self.confirm.clone();
        let http_delete_task_id = task_id.to_owned();
        linker
            .func_wrap(
                "denyx",
                "host_net_http_delete",
                move |mut caller: Caller<'_, WasmState>,
                      url_ptr: u32,
                      url_len: u32|
                      -> Result<u64, wasmtime::Error> {
                    check_wasm_deadline(
                        &mut caller,
                        &http_delete_policy,
                        &http_delete_audit,
                        &http_delete_task_id,
                        "net.http_delete",
                    )?;
                    check_wasm_call_limits(
                        &mut caller,
                        &http_delete_policy,
                        &http_delete_audit,
                        &http_delete_task_id,
                        "net.http_delete",
                    )?;
                    check_wasm_no_output_after_local_only_read(
                        &mut caller,
                        &http_delete_policy,
                        &http_delete_audit,
                        &http_delete_task_id,
                        "net.http_delete",
                    )?;
                    let url = read_string_from_guest(&mut caller, url_ptr, url_len, "url")?;
                    let parsed = match http_delete_policy.check_http_delete(&url) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_delete_audit,
                                AuditEvent::denied(
                                    &http_delete_task_id,
                                    step,
                                    "net.http_delete",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_delete({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_delete denied"));
                        }
                    };
                    if let Some(host) = parsed.host_str() {
                        if let Err(e) = crate::dns_check(&http_delete_policy, "http_delete", host) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_delete_audit,
                                AuditEvent::denied(
                                    &http_delete_task_id,
                                    step,
                                    "net.http_delete",
                                    &url,
                                    &format!("{e}"),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Policy(format!("net.http_delete({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_delete denied"));
                        }
                    }
                    // Capability-level confirm gate. Fires when
                    // policy.requires_approval() lists this capability. An
                    // operator deny surfaces as DenyxError::ConfirmDenied
                    // (exit code 4) — distinct from a policy-Deny.
                    if http_delete_policy.requires_approval("net.http_delete") {
                        let decision = http_delete_confirm.confirm(&ConfirmRequest {
                            task_id: http_delete_task_id.clone(),
                            capability: "net.http_delete".to_string(),
                            summary: format!("net.http_delete: {url}"),
                        });
                        if matches!(decision, ConfirmDecision::Deny) {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_delete_audit,
                                AuditEvent::denied(
                                    &http_delete_task_id,
                                    step,
                                    "net.http_delete",
                                    &url,
                                    "confirm hook denied",
                                ),
                            );
                            caller.data_mut().captured_error = Some(DenyxError::ConfirmDenied(
                                "net.http_delete denied by confirm hook".to_string(),
                            ));
                            return Err(wasmtime::Error::msg("confirm denied"));
                        }
                    }

                    // Outbound taint refusal only fires when the destination is NOT
                    // itself local-only — a local-only host receiving a local-only
                    // value isn't a boundary crossing.
                    let parsed_host = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                        .unwrap_or_default();
                    if !http_delete_policy.host_is_local_only(&parsed_host) {
                        if let Some(msg) = crate::check_outbound_taint(
                            &caller.data().taint_registry,
                            &http_delete_audit,
                            &http_delete_task_id,
                            "net.http_delete",
                            &format!("DELETE {parsed}"),
                            &[("url", url.as_str())],
                            || {
                                caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            },
                        ) {
                            caller.data_mut().captured_error = Some(DenyxError::Policy(msg));
                            return Err(wasmtime::Error::msg("outbound taint refused"));
                        }
                    }

                    let body = match crate::no_redirect_agent()
                        .delete(&url)
                        .timeout(http_delete_policy.network_timeout())
                        .call()
                    {
                        Ok(resp) => match crate::finalize_http_response(resp) {
                            Ok(s) => s,
                            Err(e) => {
                                let step = caller
                                    .data()
                                    .step_counter
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                emit_scrubbed(
                                    &caller,
                                    &http_delete_audit,
                                    AuditEvent::http(
                                        &http_delete_task_id,
                                        step,
                                        "net.http_delete",
                                        &url,
                                        false,
                                        Some(format!("io: {e}")),
                                    ),
                                );
                                caller.data_mut().captured_error = Some(DenyxError::Other(
                                    format!("net.http_delete({url:?}): {e}"),
                                ));
                                return Err(wasmtime::Error::msg("net.http_delete: finalize"));
                            }
                        },
                        Err(e) => {
                            let step = caller
                                .data()
                                .step_counter
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            emit_scrubbed(
                                &caller,
                                &http_delete_audit,
                                AuditEvent::http(
                                    &http_delete_task_id,
                                    step,
                                    "net.http_delete",
                                    &url,
                                    false,
                                    Some(format!("io: {e}")),
                                ),
                            );
                            caller.data_mut().captured_error =
                                Some(DenyxError::Other(format!("net.http_delete({url:?}): {e}")));
                            return Err(wasmtime::Error::msg("net.http_delete: request failed"));
                        }
                    };
                    let step = caller
                        .data()
                        .step_counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    emit_scrubbed(
                        &caller,
                        &http_delete_audit,
                        AuditEvent::http(
                            &http_delete_task_id,
                            step,
                            "net.http_delete",
                            &url,
                            true,
                            None,
                        ),
                    );
                    if let Some(host) = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| u.host_str().map(|s| s.to_owned()))
                    {
                        if http_delete_policy.host_is_local_only(&host) {
                            caller.data().taint_registry.add(&body);
                        }
                    }
                    write_string_to_guest(&mut caller, &body)
                },
            )
            .map_err(|e| DenyxError::Other(format!("link host_net_http_delete: {e}")))?;

        // Instantiate and run `_start`.
        let instance = linker
            .instantiate(&mut store, &self.module)
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
            "ok" => {
                // Scrub printed lines against the taint registry before
                // surfacing to the caller. Matches the in-process
                // Runner's IFC behaviour: secrets sourced from local-
                // only fs/env/hosts/subprocess never reach print's
                // output buffer untouched.
                let state = store.into_data();
                let printed = redact_lines(state.printed, &state.taint_registry);
                Ok(RunOutcome { printed })
            }
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
                // Scrub the error message against tainted values gathered
                // during this run. Without this, `fail(secret)` (or any
                // Starlark error whose message echoes a local-only value)
                // leaks the bytes through the error boundary. The
                // in-process Runner does the same scrubbing.
                let taints = store.data().taint_registry.redaction_snapshot();
                let formatted = crate::taint::redact(&formatted, &taints);
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

/// Validate `(ptr, len)` against the guest's actual linear memory size
/// *before* allocating a host-side buffer of that size. Every guest
/// import takes `len` as a raw, attacker-controlled `u32` — without
/// this check a script could pass a length up to `u32::MAX` and force
/// a large host-heap allocation before the out-of-bounds `Memory::read`
/// that would otherwise catch it ever runs. The guest's own memory is
/// already bounded by wasmtime's configured limit, so capping the
/// allocation to "at most what the guest actually has" closes the gap
/// without adding a new policy knob.
fn checked_guest_len(
    memory: &Memory,
    caller: &Caller<'_, WasmState>,
    ptr: u32,
    len: u32,
    tag: &str,
) -> Result<usize, wasmtime::Error> {
    validate_guest_len(ptr, len, memory.data_size(caller) as u64)
        .map_err(|msg| wasmtime::Error::msg(format!("{tag}: {msg}")))
}

/// Pure arithmetic core of [`checked_guest_len`], split out so the
/// overflow/bounds logic can be unit-tested without spinning up a real
/// wasmtime `Memory`.
fn validate_guest_len(ptr: u32, len: u32, mem_size: u64) -> Result<usize, String> {
    let end = (ptr as u64)
        .checked_add(len as u64)
        .ok_or_else(|| "ptr+len overflow".to_string())?;
    if end > mem_size {
        return Err(format!(
            "(ptr={ptr}, len={len}) out of bounds of guest memory (size={mem_size})"
        ));
    }
    Ok(len as usize)
}

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
    let len = checked_guest_len(&memory, caller, ptr, len, tag)?;
    let mut buf = vec![0u8; len];
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

/// State carried by wasmtime's `Store<T>`. Holds the WASI ctx so WASI
/// imports can find it, plus the print accumulator the `host_print`
/// import writes into, plus a slot for import closures to surface a
/// typed [`DenyxError`] across the trap boundary.
struct WasmState {
    wasi: WasiP1Ctx,
    printed: Vec<String>,
    captured_error: Option<DenyxError>,
    /// Monotonically incrementing step counter stamped into each
    /// `AuditEvent`. The in-process Runner does the same — every
    /// gated call gets a unique sequence number per Run.
    step_counter: std::sync::atomic::AtomicU32,
    /// Tracks values read from local-only fs paths, env vars, hosts,
    /// or subprocess output. Scrubbed at the output boundary (the
    /// printed-lines Vec, in `WasmRunner::run`'s success path) so
    /// secrets sourced from local-only declarations never leave the
    /// runtime untouched.
    ///
    /// `TaintRegistry` uses interior mutability, so import closures
    /// can register through `&caller.data().taint_registry` without
    /// needing `&mut`.
    taint_registry: TaintRegistry,
    /// Monotonic wall-clock instant the script started executing.
    /// Combined with `policy.runtime_max_seconds()` it bounds how long
    /// any effecting capability call is allowed to run before being
    /// rejected with `DenyxError::RuntimeLimit`. Mirrors the
    /// in-process Runner's `HostCtx::start_time` (lib.rs:347).
    start_time: Instant,
    /// Calls made so far this run, by capability name. Mirrors the
    /// in-process Runner's `HostCtx::call_counts` (lib.rs) — backs
    /// both `[runtime].max_calls_per_capability` and
    /// `[runtime].max_total_calls` (summed across every key). See
    /// `check_wasm_call_limits`.
    call_counts: std::collections::HashMap<String, u64>,
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
        let policy_path = write_temp_policy(
            "fs_read_denied",
            "[filesystem]\nread_allow = [\"/dev/null\"]\n",
        );
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
        let policy_path = write_temp_policy(
            "fs_write_denied",
            "[filesystem]\nwrite_allow = [\"/dev/null\"]\n",
        );
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
        let policy_path = write_temp_policy(
            "fs_delete_denied",
            "[filesystem]\ndelete_allow = [\"/dev/null\"]\n",
        );
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
        let policy_path = write_temp_policy(
            "env_read_denied",
            "[environment]\nallow_vars = [\"DENYX_UNRELATED_NEVER_SET\"]\n",
        );
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
            "[subprocess]\nallow_commands = [\"true\"]\n",
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
        let policy_path = write_temp_policy(
            "net_http_get_denied",
            "[network]\nhttp_get_allow = [\"never-allowed.invalid\"]\n",
        );
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
        let policy_path = write_temp_policy(
            "net_http_post_denied",
            "[network]\nhttp_post_allow = [\"never-allowed.invalid\"]\n",
        );
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
        let policy_path = write_temp_policy(
            "net_http_put_denied",
            "[network]\nhttp_put_allow = [\"never-allowed.invalid\"]\n",
        );
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
            "[network]\nhttp_patch_allow = [\"never-allowed.invalid\"]\n",
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
            "[network]\nhttp_delete_allow = [\"never-allowed.invalid\"]\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let err = runner
            .run("t", "net.http_delete(\"https://example.com\")", "x.star")
            .expect_err("denied URL should error");
        let _ = std::fs::remove_file(&policy_path);
        assert!(matches!(err, DenyxError::Policy(_)), "got {err:?}");
    }

    /// Phase 4.9 — local-only fs.read content is scrubbed from the
    /// printed output. The script reads a secret file and prints it;
    /// after the run, the printed line must contain `[REDACTED]` and
    /// NOT contain the raw secret. Mirrors the
    /// `LOCAL_ONLY_fs_redaction` task in the multistep eval.
    #[test]
    fn fs_read_local_only_is_scrubbed_from_print() {
        let file_path = unique_tmp_path("fs_read_local_only");
        let secret = "sk-fixture-secret-XYZ123";
        std::fs::write(&file_path, secret).expect("write fixture");
        let policy_path = write_temp_policy(
            "fs_read_local_only",
            &format!(
                "[filesystem]\nlocal_only_read = [{:?}]\n",
                file_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!(
            "print(\"token=\" + fs.read({:?}))",
            file_path.display().to_string()
        );
        // The verifier (Phase 4.9 wired statically into WasmRunner)
        // rejects `local-only read + print` shapes BEFORE the
        // interpreter runs. The runtime redactor remains as a
        // defence-in-depth for shapes the verifier doesn't catch —
        // see `examples/local_executor/run_exfil.py` for empirical
        // validation of both layers composing on the wasm path.
        let err = runner
            .run("test", &script, "fs_local.star")
            .expect_err("verifier should reject local-only + print");
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::Verifier(msg) => {
                assert!(
                    msg.contains("tainted-output-flow"),
                    "verifier error should name the tainted-output-flow rule, got {msg:?}"
                );
                assert!(
                    !msg.contains(secret),
                    "verifier error message must not contain raw secret, got {msg:?}"
                );
            }
            other => panic!("expected DenyxError::Verifier, got {other:?}"),
        }
    }

    /// Phase 4.9 — local-only env.read value is scrubbed at output.
    /// Mirrors the `LOCAL_ONLY_env_redaction` eval task.
    #[test]
    fn env_read_local_only_is_scrubbed_from_print() {
        let var_name = format!("DENYX_WASM_RUNNER_TEST_LOCAL_ONLY_{}", std::process::id());
        let secret = "sk-fixture-env-secret-ABC456";
        std::env::set_var(&var_name, secret);
        let policy_path = write_temp_policy(
            "env_read_local_only",
            &format!("[environment]\nlocal_only_vars = [{var_name:?}]\n"),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!("print(\"auth=Bearer \" + env.read({var_name:?}))");
        // Same verifier-rejected shape as the fs.read case above —
        // env.read of a local-only var + print is statically refused.
        let err = runner
            .run("test", &script, "env_local.star")
            .expect_err("verifier should reject local-only env + print");
        std::env::remove_var(&var_name);
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::Verifier(msg) => {
                assert!(
                    msg.contains("tainted-output-flow"),
                    "verifier error should name the tainted-output-flow rule, got {msg:?}"
                );
                assert!(
                    !msg.contains(secret),
                    "verifier error message must not contain raw env secret, got {msg:?}"
                );
            }
            other => panic!("expected DenyxError::Verifier, got {other:?}"),
        }
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

    /// `[runtime] max_seconds = 0` should fire `RuntimeLimit` on the
    /// FIRST effecting builtin call. Mirrors the in-process Runner
    /// behaviour (lib.rs:376) — closes the parity gap surfaced by
    /// examples/local_executor/probe_layer_variants.py.
    #[test]
    fn deadline_zero_max_seconds_trips_first_effecting_call_env_read() {
        let policy_path = write_temp_policy(
            "deadline_env_read",
            r#"[runtime]
max_seconds = 0

[environment]
allow_vars = ["USER", "HOME", "PATH"]
"#,
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let script = r#"
print(env.read("USER"))
"#;
        let err = runner
            .run("test", script, "deadline_env_read.star")
            .expect_err("env.read should trip the wall-time deadline before reading");
        match &err {
            DenyxError::RuntimeLimit(msg) => {
                assert!(
                    msg.contains("wall-time deadline"),
                    "expected wall-time deadline message, got: {msg}"
                );
                assert!(
                    msg.contains("env.read"),
                    "deadline message should name the capability, got: {msg}"
                );
            }
            other => panic!("expected DenyxError::RuntimeLimit, got {other:?}"),
        }
    }

    /// Same property on a different capability — confirms the deadline
    /// check is wired into every effecting builtin, not just env.read.
    #[test]
    fn deadline_zero_max_seconds_trips_first_effecting_call_fs_write() {
        // Use a dedicated subdir for write_allow so it doesn't include
        // the policy file's parent (/tmp). Denyx refuses self-writable
        // policies (an agent that can rewrite its own policy disables
        // every other rule).
        let target_dir = unique_tmp_path("deadline_fs_write_subdir");
        std::fs::create_dir_all(&target_dir).expect("mkdir target subdir");
        let target = target_dir.join("file.txt");
        let policy_path = write_temp_policy(
            "deadline_fs_write",
            &format!(
                "[runtime]
max_seconds = 0

[filesystem]
write_allow = [{:?}]
",
                target_dir.display().to_string() + "/**"
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let script = format!(
            r#"
fs.write({:?}, "hello")
"#,
            target.display().to_string()
        );
        let err = runner
            .run("test", &script, "deadline_fs_write.star")
            .expect_err("fs.write should trip the wall-time deadline before writing");
        match &err {
            DenyxError::RuntimeLimit(msg) => {
                assert!(
                    msg.contains("wall-time deadline"),
                    "expected wall-time deadline message, got: {msg}"
                );
                assert!(
                    msg.contains("fs.write"),
                    "deadline message should name the capability, got: {msg}"
                );
            }
            other => panic!("expected DenyxError::RuntimeLimit, got {other:?}"),
        }
        assert!(
            !target.exists(),
            "deadline-tripped fs.write must not create the target file"
        );
    }

    /// AuditSink that captures every emitted event into a Vec, for
    /// assertion in audit-wiring tests. Mutex-guarded so the sink
    /// satisfies the AuditSink: Send + Sync bound.
    #[derive(Default)]
    struct RecordingAuditSink {
        events: std::sync::Mutex<Vec<AuditEvent>>,
    }

    impl AuditSink for RecordingAuditSink {
        fn emit(&self, event: AuditEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    /// Phase 4.10 — successful fs.read emits an `Allowed` audit event
    /// with the right capability and a populated detail.
    #[test]
    fn fs_read_success_emits_audit_event() {
        use crate::audit::AuditStatus;
        let file_path = unique_tmp_path("fs_read_audit_ok");
        std::fs::write(&file_path, "audit-ok").expect("write fixture");
        let policy_path = write_temp_policy(
            "fs_read_audit_ok",
            &format!(
                "[filesystem]\nread_allow = [{:?}]\n",
                file_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let sink = std::sync::Arc::new(RecordingAuditSink::default());
        let runner = WasmRunner::new(policy).with_audit(sink.clone());

        let script = format!("fs.read({:?})", file_path.display().to_string());
        runner.run("t-audit-ok", &script, "x.star").expect("runs");
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        let events = sink.events.lock().unwrap();
        assert!(
            events.iter().any(|e| {
                e.capability == "fs.read"
                    && matches!(e.status, AuditStatus::Allowed)
                    && e.task_id == "t-audit-ok"
            }),
            "expected an Allowed fs.read event, got {events:?}"
        );
    }

    /// Phase 4.10 — policy-denied fs.read emits a `Denied` audit
    /// event capturing the reason.
    #[test]
    fn fs_read_denied_emits_audit_event() {
        use crate::audit::AuditStatus;
        let file_path = unique_tmp_path("fs_read_audit_deny");
        std::fs::write(&file_path, "audit-deny").expect("write fixture");
        let policy_path = write_temp_policy(
            "fs_read_audit_deny",
            "[filesystem]\nread_allow = [\"/dev/null\"]\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let sink = std::sync::Arc::new(RecordingAuditSink::default());
        let runner = WasmRunner::new(policy).with_audit(sink.clone());

        let script = format!("fs.read({:?})", file_path.display().to_string());
        let _ = runner
            .run("t-audit-deny", &script, "x.star")
            .expect_err("denied path errors");
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        let events = sink.events.lock().unwrap();
        assert!(
            events.iter().any(|e| {
                e.capability == "fs.read"
                    && matches!(e.status, AuditStatus::Denied)
                    && e.task_id == "t-audit-deny"
            }),
            "expected a Denied fs.read event, got {events:?}"
        );
    }

    /// Phase 4.10 — step counter increments across calls. Two
    /// allow-path fs.read calls produce two events with distinct
    /// `.step` values.
    #[test]
    fn audit_step_counter_increments_per_call() {
        let file_a = unique_tmp_path("step_a");
        let file_b = unique_tmp_path("step_b");
        std::fs::write(&file_a, "a").expect("a");
        std::fs::write(&file_b, "b").expect("b");
        let policy_path = write_temp_policy(
            "audit_step",
            &format!(
                "[filesystem]\nread_allow = [{:?}, {:?}]\n",
                file_a.display().to_string(),
                file_b.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let sink = std::sync::Arc::new(RecordingAuditSink::default());
        let runner = WasmRunner::new(policy).with_audit(sink.clone());

        let script = format!(
            "fs.read({:?}); fs.read({:?})",
            file_a.display().to_string(),
            file_b.display().to_string()
        );
        runner.run("t-step", &script, "x.star").expect("runs");
        let _ = std::fs::remove_file(&file_a);
        let _ = std::fs::remove_file(&file_b);
        let _ = std::fs::remove_file(&policy_path);

        let events = sink.events.lock().unwrap();
        let fs_steps: Vec<u32> = events
            .iter()
            .filter(|e| e.capability == "fs.read")
            .map(|e| e.step)
            .collect();
        assert!(
            fs_steps.len() >= 2 && fs_steps[0] != fs_steps[1],
            "expected distinct step values for two fs.read events, got {fs_steps:?}"
        );
    }

    /// Recording ConfirmHook for use in Phase 4.11 tests. Captures the
    /// most recent ConfirmRequest the hook was asked about and lets
    /// the test choose Allow / Deny per-call.
    struct RecordingConfirm {
        decision: ConfirmDecision,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl ConfirmHook for RecordingConfirm {
        fn confirm(&self, req: &ConfirmRequest) -> ConfirmDecision {
            self.seen
                .lock()
                .unwrap()
                .push(format!("{}: {}", req.capability, req.summary));
            self.decision
        }
    }

    /// Phase 4.11 — capability listed in requires_approval triggers
    /// the confirm hook; an Allow decision lets the operation proceed.
    #[test]
    fn fs_read_requires_approval_calls_confirm_hook() {
        let file_path = unique_tmp_path("fs_read_confirm_ok");
        std::fs::write(&file_path, "confirmed").expect("write fixture");
        let policy_path = write_temp_policy(
            "fs_read_confirm_ok",
            &format!(
                "requires_approval = [\"fs.read\"]\n\n[filesystem]\nread_allow = [{:?}]\n",
                file_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let confirm = std::sync::Arc::new(RecordingConfirm {
            decision: ConfirmDecision::Allow,
            seen: std::sync::Mutex::new(vec![]),
        });
        let runner = WasmRunner::new(policy).with_confirm_hook(confirm.clone());

        let script = format!("print(fs.read({:?}))", file_path.display().to_string());
        let outcome = runner.run("test", &script, "x.star").expect("runs");
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        let seen = confirm.seen.lock().unwrap();
        assert!(
            seen.iter().any(|s| s.starts_with("fs.read: fs.read:")),
            "confirm hook should have been called with fs.read summary; got {seen:?}"
        );
        assert_eq!(outcome.printed, vec!["confirmed".to_string()]);
    }

    /// Phase 4.11 — confirm Deny surfaces as DenyxError::ConfirmDenied.
    #[test]
    fn fs_write_confirm_deny_surfaces_typed_error() {
        let file_path = unique_tmp_path("fs_write_confirm_deny");
        let _ = std::fs::remove_file(&file_path);
        let policy_path = write_temp_policy(
            "fs_write_confirm_deny",
            &format!(
                "requires_approval = [\"fs.write\"]\n\n[filesystem]\nwrite_allow = [{:?}]\n",
                file_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let confirm = std::sync::Arc::new(RecordingConfirm {
            decision: ConfirmDecision::Deny,
            seen: std::sync::Mutex::new(vec![]),
        });
        let runner = WasmRunner::new(policy).with_confirm_hook(confirm);

        let script = format!(
            "fs.write({:?}, \"should not appear\")",
            file_path.display().to_string()
        );
        let err = runner
            .run("test", &script, "x.star")
            .expect_err("confirm deny should error");
        let exists_after = file_path.exists();
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::ConfirmDenied(_) => {}
            other => panic!("expected DenyxError::ConfirmDenied, got {other:?}"),
        }
        assert!(
            !exists_after,
            "confirm-denied fs.write must not create the target file"
        );
    }

    /// Phase 4.11 — subprocess.exec per-argv requires_approval_args
    /// fires the confirm hook even when subprocess.exec is broadly
    /// allowed. Deny → DenyxError::ConfirmDenied.
    #[test]
    fn subprocess_exec_argv_requires_approval_calls_confirm_hook() {
        let policy_path = write_temp_policy(
            "subprocess_argv_confirm",
            "[subprocess]\nallow_commands = [\"echo\"]\n\n[subprocess.requires_approval_args]\necho = [\"sensitive\"]\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let confirm = std::sync::Arc::new(RecordingConfirm {
            decision: ConfirmDecision::Deny,
            seen: std::sync::Mutex::new(vec![]),
        });
        let runner = WasmRunner::new(policy).with_confirm_hook(confirm.clone());

        let script = r#"subprocess.exec(["echo", "sensitive", "payload"])"#;
        let err = runner
            .run("test", script, "x.star")
            .expect_err("argv-pattern confirm deny should error");
        let _ = std::fs::remove_file(&policy_path);

        match err {
            DenyxError::ConfirmDenied(_) => {}
            other => panic!("expected DenyxError::ConfirmDenied, got {other:?}"),
        }
        let seen = confirm.seen.lock().unwrap();
        assert!(
            !seen.is_empty(),
            "confirm hook should have been called for per-argv pattern"
        );
    }

    /// Final parity gap closer: an outbound fs.write whose content
    /// matches a tainted substring (from a prior local-only fs.read)
    /// must refuse, not redact. Mirrors the in-process Runner's
    /// `enforce_outbound_taint`.
    #[test]
    fn fs_write_outbound_taint_refuses() {
        let secret_path = unique_tmp_path("outbound_taint_secret");
        let secret = "outbound-taint-fixture-XYZ123";
        std::fs::write(&secret_path, secret).expect("write secret fixture");

        let target_path = unique_tmp_path("outbound_taint_target");
        let _ = std::fs::remove_file(&target_path);

        let policy_path = write_temp_policy(
            "outbound_taint",
            &format!(
                "[filesystem]\nlocal_only_read = [{:?}]\nwrite_allow = [{:?}]\n",
                secret_path.display().to_string(),
                target_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!(
            "_s = fs.read({:?})\nfs.write({:?}, _s)",
            secret_path.display().to_string(),
            target_path.display().to_string()
        );
        let err = runner
            .run("test", &script, "x.star")
            .expect_err("outbound taint should refuse");
        let exists_after = target_path.exists();
        let _ = std::fs::remove_file(&secret_path);
        let _ = std::fs::remove_file(&target_path);
        let _ = std::fs::remove_file(&policy_path);

        // Either the static verifier catches the read+write pattern,
        // or the runtime outbound-taint check catches the bytes
        // flowing through the host closure — both are valid
        // denials of the same threat (local-only data flowing
        // outbound). Accept either.
        match err {
            DenyxError::Policy(_) | DenyxError::Verifier(_) => {}
            other => panic!("expected Policy or Verifier denial, got {other:?}"),
        }
        assert!(
            !exists_after,
            "outbound-taint-refused fs.write must not create target"
        );
    }

    /// Same outbound refusal for net.http_post body. Skips the
    /// host_is_local_only gate because the destination is not in
    /// local_only_hosts.
    #[test]
    fn net_http_post_outbound_taint_refuses() {
        let secret_path = unique_tmp_path("http_taint_secret");
        let secret = "http-outbound-fixture-ABC789";
        std::fs::write(&secret_path, secret).expect("write secret fixture");

        let policy_path = write_temp_policy(
            "http_outbound_taint",
            &format!(
                "[filesystem]\nlocal_only_read = [{:?}]\n\n[network]\nhttp_post_allow = [\"example.com\"]\n",
                secret_path.display().to_string()
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = format!(
            "_s = fs.read({:?})\nnet.http_post(\"https://example.com\", _s)",
            secret_path.display().to_string()
        );
        let err = runner
            .run("test", &script, "x.star")
            .expect_err("outbound taint over HTTP should refuse");
        let _ = std::fs::remove_file(&secret_path);
        let _ = std::fs::remove_file(&policy_path);

        // Same as fs.write above — verifier may catch this statically
        // before the runtime outbound-taint check runs. Both are
        // valid denials of local-only-data-flowing-outbound.
        match err {
            DenyxError::Policy(_) | DenyxError::Verifier(_) => {}
            other => panic!("expected Policy or Verifier denial, got {other:?}"),
        }
    }

    /// Phase 4.X env filtering: subprocess.exec should expose only the
    /// vars policy.subprocess_env returns. We set a probe var on the
    /// host, leave it OUT of allow_vars, then have the child print
    /// its env via `env`. The probe must NOT appear.
    #[test]
    fn subprocess_exec_env_filtered_to_policy_allow_vars() {
        let probe_name = format!("DENYX_WASM_ENV_PROBE_{}", std::process::id());
        std::env::set_var(&probe_name, "should-not-leak");

        // Policy allows `env` but NOT our probe var. PATH is auto-
        // injected by the in-process Runner's subprocess_env so the
        // child can find /usr/bin/env.
        let policy_path = write_temp_policy(
            "subprocess_env_filter",
            "[subprocess]\nallow_commands = [\"env\"]\n\n[environment]\nallow_vars = [\"PATH\"]\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);

        let script = r#"print(subprocess.exec(["env"]))"#;
        let outcome = runner
            .run("test", script, "x.star")
            .expect("subprocess.exec runs");
        std::env::remove_var(&probe_name);
        let _ = std::fs::remove_file(&policy_path);

        let printed = outcome.printed.join("\n");
        assert!(
            !printed.contains(&probe_name),
            "probe var leaked into child env: {printed:?}"
        );
    }

    // ---- Round 4 wasm-path regressions (dns_check, bwrap sandbox,
    // HTTP timeout, guest-length bounds) — the wasm sandbox became
    // the default execution path in v0.4.0 without carrying over
    // four properties the in-process Runner already had. See
    // docs/security-pentest-r4-wasm-path-regressions.md.

    /// Mirrors `denyx_host::tests::host::dns_resolves_hostname_through_deny_cidr`
    /// but against `WasmRunner`. `localhost` reliably resolves to
    /// 127.0.0.1 / ::1 on every POSIX system, so this exercises the
    /// full DNS-then-policy path without a real network round-trip.
    #[test]
    fn dns_resolves_hostname_through_deny_cidr() {
        let policy_path = write_temp_policy(
            "dns_deny_cidr",
            "[network]\nhttp_get_allow = [\"localhost\"]\ndeny_ips = [\"127.0.0.0/8\", \"::1/128\"]\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let err = runner
            .run("t1", r#"net.http_get("http://localhost:1/")"#, "test.star")
            .expect_err("hostname resolving to a denied IP must be refused");
        let _ = std::fs::remove_file(&policy_path);
        assert!(
            matches!(err, DenyxError::Policy(_)),
            "expected policy violation from DNS-resolved deny, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("127.") || msg.contains("::1"),
            "expected resolved-IP diagnostic, got: {msg}"
        );
    }

    /// A hung backend must not hang the wasm path indefinitely — the
    /// per-request `.timeout(policy.network_timeout())` that the
    /// in-process Runner always set was missing on every wasm HTTP
    /// verb. Binds an ephemeral port, accepts but never responds,
    /// and asserts the call fails within a few seconds against a
    /// 1-second `[network].timeout_seconds`.
    #[test]
    fn http_get_aborts_within_timeout_against_unresponsive_backend() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let _bg = std::thread::spawn(move || {
            let mut held = Vec::new();
            for conn in listener.incoming().flatten() {
                held.push(conn);
            }
        });

        let policy_path = write_temp_policy(
            "http_timeout",
            "[network]\nhttp_get_allow = [\"127.0.0.1\"]\ntimeout_seconds = 1\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let src = format!(r#"net.http_get("http://127.0.0.1:{port}/never-responds")"#);

        let started = std::time::Instant::now();
        let err = runner
            .run("t1", &src, "test.star")
            .expect_err("unresponsive backend must not hang forever");
        let elapsed = started.elapsed();
        let _ = std::fs::remove_file(&policy_path);

        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "timeout should fire within ~1s; took {elapsed:?}"
        );
        assert!(
            !err.to_string().is_empty(),
            "expected an error message, got empty: {err:?}"
        );
    }

    /// `[subprocess].sandbox = "bwrap"` must be honored on the wasm
    /// path exactly as it is on the native Runner: a policy that
    /// permits a command AND (accidentally or not) allow-lists a
    /// host-only path must still have that path hidden inside the
    /// sandbox, because the jail — not the argv path-gate — is what's
    /// under test here. Skips cleanly where bubblewrap can't run
    /// (e.g. restricted CI runners without user namespaces).
    #[test]
    fn bwrap_sandbox_hides_host_only_path_even_when_argv_gate_allows_it() {
        fn bwrap_works() -> bool {
            std::process::Command::new("bwrap")
                .args([
                    "--ro-bind",
                    "/usr",
                    "/usr",
                    "--ro-bind",
                    "/bin",
                    "/bin",
                    "--unshare-all",
                    "--",
                    "/bin/true",
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        if !bwrap_works() {
            eprintln!(
                "skipping: bwrap is not installed or cannot create a working \
                 sandbox in this environment"
            );
            return;
        }

        let policy_path = write_temp_policy(
            "bwrap_sandbox",
            "[filesystem]\nread_allow = [\"/etc/**\"]\n\n[environment]\nallow_vars = [\"PATH\"]\n\n[subprocess]\nallow_commands = [\"cat\"]\nsandbox = \"bwrap\"\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        // The argv path-gate accepts /etc/<file> because read_allow
        // covers it; the sandbox doesn't bind-mount /etc at all, so
        // the child fails to find a path that's host-real but not
        // jail-real. Without the bwrap branch wired into WasmRunner,
        // this would succeed (real ambient filesystem access).
        let result = runner.run(
            "t1",
            r#"subprocess.exec(["cat", "/etc/denyx_does_not_exist_in_sandbox.txt"])"#,
            "test.star",
        );
        let _ = std::fs::remove_file(&policy_path);
        assert!(
            result.is_err(),
            "subprocess inside the wasm-path bwrap sandbox should fail to find a host-only path"
        );
    }

    /// Pure arithmetic unit tests for `validate_guest_len`, the core
    /// of the guest-length bounds check every `(ptr, len)` guest
    /// import argument goes through before a host-side `vec![0u8; len]`
    /// allocation. Exercises the property directly rather than via a
    /// live wasmtime `Memory`, since a legitimate Starlark script
    /// can't fabricate an out-of-bounds `(ptr, len)` pair itself — the
    /// compiled interpreter always passes the real length of the
    /// string it's marshalling. The defect this closes is a
    /// hypothetical corrupted/malicious raw guest module calling a
    /// host import directly with a length that doesn't match its
    /// actual memory size.
    #[test]
    fn validate_guest_len_accepts_in_bounds_request() {
        assert_eq!(validate_guest_len(0, 100, 65536).unwrap(), 100);
        assert_eq!(validate_guest_len(65436, 100, 65536).unwrap(), 100);
    }

    #[test]
    fn validate_guest_len_rejects_length_past_end_of_memory() {
        assert!(validate_guest_len(0, 65537, 65536).is_err());
        assert!(validate_guest_len(65437, 100, 65536).is_err());
    }

    #[test]
    fn validate_guest_len_rejects_max_u32_length_against_small_memory() {
        // The exact shape of the pre-fix bug: a script-controlled
        // `len` near `u32::MAX` against a guest that only actually has
        // one 64KiB page of linear memory.
        assert!(validate_guest_len(0, u32::MAX, 65536).is_err());
    }

    #[test]
    fn validate_guest_len_rejects_max_ptr_and_len_against_small_memory() {
        // ptr and len are both u32, promoted to u64 before adding, so
        // the sum can never itself overflow u64 — this exercises the
        // realistic failure mode instead (huge ptr+len against a
        // guest that only has a small amount of actual memory).
        assert!(validate_guest_len(u32::MAX, u32::MAX, 65536).is_err());
    }

    // ---- [runtime].no_output_after_local_only_read (wasm path) ----
    //
    // Mirrors crates/host/tests/runtime_no_output_after_local_only_read.rs's
    // native-runner tests against WasmRunner. Uses a variable-arg
    // fs.read (`p = "..."; fs.read(p)`) so the pre-exec verifier's
    // literal-arg-only taint_flow check doesn't short-circuit before
    // the runtime flag gets a chance to fire.

    #[test]
    fn no_output_after_local_only_read_denies_unrelated_print_when_flag_set() {
        let secret_path = unique_tmp_path("no_output_secret_deny");
        std::fs::write(&secret_path, "irrelevant-secret-value").expect("write fixture");
        let path_lit = secret_path.to_string_lossy().replace('\\', "/");

        let policy_path = write_temp_policy(
            "no_output_deny",
            &format!(
                "[filesystem]\nlocal_only_read = [\"{path_lit}\"]\n\n\
                 [runtime]\nno_output_after_local_only_read = true\n"
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let src =
            format!("p = \"{path_lit}\"\nx = fs.read(p)\nprint(\"unrelated to the secret\")\n");
        let err = runner
            .run("t1", &src, "test.star")
            .expect_err("output after a local-only read must be refused when the flag is set");
        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&secret_path);
        assert!(
            matches!(err, DenyxError::Policy(_)),
            "expected DenyxError::Policy, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("no_output_after_local_only_read") || msg.contains("local-only read"),
            "expected a message naming the flag/property, got: {msg}"
        );
    }

    #[test]
    fn no_output_after_local_only_read_allows_output_with_no_local_only_read() {
        let policy_path = write_temp_policy(
            "no_output_clean",
            "[runtime]\nno_output_after_local_only_read = true\n",
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let outcome = runner
            .run(
                "t1",
                r#"print("no local-only read ever happened in this script")"#,
                "test.star",
            )
            .expect("no local-only read occurred, so output must be unaffected by the flag");
        let _ = std::fs::remove_file(&policy_path);
        assert_eq!(
            outcome.printed,
            vec!["no local-only read ever happened in this script".to_string()]
        );
    }

    #[test]
    fn no_output_after_local_only_read_allows_output_when_flag_unset_default() {
        let secret_path = unique_tmp_path("no_output_secret_default_off");
        std::fs::write(&secret_path, "irrelevant-secret-value").expect("write fixture");
        let path_lit = secret_path.to_string_lossy().replace('\\', "/");

        // No [runtime] section at all — flag defaults to false.
        let policy_path = write_temp_policy(
            "no_output_default_off",
            &format!("[filesystem]\nlocal_only_read = [\"{path_lit}\"]\n"),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let src =
            format!("p = \"{path_lit}\"\nx = fs.read(p)\nprint(\"unrelated to the secret\")\n");
        let outcome = runner
            .run("t1", &src, "test.star")
            .expect("flag defaults to off; unrelated output after a local-only read is unaffected");
        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&secret_path);
        assert_eq!(outcome.printed, vec!["unrelated to the secret".to_string()]);
    }

    // ---- [runtime].max_calls_per_capability / max_total_calls (wasm) ----
    //
    // Mirrors crates/host/tests/runtime_call_limits.rs's native-runner
    // tests against WasmRunner.

    #[test]
    fn max_calls_per_capability_allows_up_to_the_cap_and_denies_the_next() {
        let fixture = unique_tmp_path("call_limit_fixture");
        std::fs::write(&fixture, "hello").expect("write fixture");
        let path_lit = fixture.to_string_lossy().replace('\\', "/");

        let policy_path = write_temp_policy(
            "call_limit_deny",
            &format!(
                "[filesystem]\nread_allow = [\"{path_lit}\"]\n\n\
                 [runtime.max_calls_per_capability]\n\"fs.read\" = 2\n"
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let src = format!("p = \"{path_lit}\"\nfs.read(p)\nfs.read(p)\nfs.read(p)\n");
        let err = runner
            .run("t1", &src, "test.star")
            .expect_err("the 3rd fs.read call must be refused once the cap of 2 is reached");
        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&fixture);
        assert!(
            matches!(err, DenyxError::RuntimeLimit(_)),
            "expected DenyxError::RuntimeLimit, got: {err:?}"
        );
        assert!(
            err.to_string().contains("max_calls_per_capability"),
            "expected a message naming the cap, got: {err}"
        );
    }

    #[test]
    fn max_calls_per_capability_two_calls_at_the_cap_succeed() {
        let fixture = unique_tmp_path("call_limit_fixture_ok");
        std::fs::write(&fixture, "hello").expect("write fixture");
        let path_lit = fixture.to_string_lossy().replace('\\', "/");

        let policy_path = write_temp_policy(
            "call_limit_ok",
            &format!(
                "[filesystem]\nread_allow = [\"{path_lit}\"]\n\n\
                 [runtime.max_calls_per_capability]\n\"fs.read\" = 2\n"
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let src = format!(
            "p = \"{path_lit}\"\nfs.read(p)\nfs.read(p)\nprint(\"both calls succeeded\")\n"
        );
        let outcome = runner
            .run("t1", &src, "test.star")
            .expect("exactly 2 calls against a cap of 2 must succeed");
        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(outcome.printed, vec!["both calls succeeded".to_string()]);
    }

    #[test]
    fn max_total_calls_counts_across_different_capabilities() {
        let fixture = unique_tmp_path("total_call_limit_fixture");
        std::fs::write(&fixture, "hello").expect("write fixture");
        let path_lit = fixture.to_string_lossy().replace('\\', "/");

        let policy_path = write_temp_policy(
            "total_call_limit",
            &format!(
                "[filesystem]\nread_allow = [\"{path_lit}\"]\n\n\
                 [environment]\nallow_vars = [\"PATH\"]\n\n\
                 [runtime]\nmax_total_calls = 2\n"
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let src = format!("p = \"{path_lit}\"\nfs.read(p)\nenv.read(\"PATH\")\nfs.read(p)\n");
        let err = runner
            .run("t1", &src, "test.star")
            .expect_err("the 3rd call must be refused once max_total_calls=2 is reached");
        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&fixture);
        assert!(
            matches!(err, DenyxError::RuntimeLimit(_)),
            "expected DenyxError::RuntimeLimit, got: {err:?}"
        );
        assert!(
            err.to_string().contains("max_total_calls"),
            "expected a message naming the cap, got: {err}"
        );
    }

    #[test]
    fn no_caps_configured_allows_unlimited_calls() {
        let fixture = unique_tmp_path("no_call_limit_fixture");
        std::fs::write(&fixture, "hello").expect("write fixture");
        let path_lit = fixture.to_string_lossy().replace('\\', "/");

        let policy_path = write_temp_policy(
            "no_call_limit",
            &format!("[filesystem]\nread_allow = [\"{path_lit}\"]\n"),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let src = format!(
            "p = \"{path_lit}\"\ndef go():\n    for _ in range(50):\n        fs.read(p)\n    print(\"done\")\ngo()\n"
        );
        let outcome = runner
            .run("t1", &src, "test.star")
            .expect("with no caps configured, repeated calls are unaffected");
        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(outcome.printed, vec!["done".to_string()]);
    }

    // ---- Phase 3 (wasm/native parity review) regressions ----

    /// Before the Phase 3 `check_outbound_taint` extraction, wasm's
    /// subprocess.exec applied the outbound-taint refusal
    /// unconditionally — unlike the native Runner, which skips it when
    /// the command itself is `local_only_commands`-marked (that
    /// command's own stdout/stderr is also tainted, so a secret passed
    /// to it can't escape via that channel). This denied legitimate
    /// local-only-command use on wasm that native allowed.
    #[test]
    fn subprocess_local_only_command_may_receive_tainted_argv() {
        let secret_path = unique_tmp_path("local_only_cmd_secret");
        std::fs::write(&secret_path, "secret-value-for-local-sink").expect("write fixture");
        let path_lit = secret_path.to_string_lossy().replace('\\', "/");

        let policy_path = write_temp_policy(
            "local_only_cmd",
            &format!(
                "[filesystem]\nlocal_only_read = [\"{path_lit}\"]\n\n\
                 [subprocess]\nallow_commands = [\"echo\"]\nlocal_only_commands = [\"echo\"]\n"
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let runner = WasmRunner::new(policy);
        let src = format!(
            "p = \"{path_lit}\"\nsecret = fs.read(p)\nsubprocess.exec([\"echo\", secret])\nprint(\"subprocess succeeded\")\n"
        );
        let outcome = runner.run("t1", &src, "test.star").expect(
            "a local-only command must be allowed to receive a tainted argv, matching native",
        );
        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&secret_path);
        assert_eq!(outcome.printed, vec!["subprocess succeeded".to_string()]);
    }

    /// Before the `emit_scrubbed`/`emit_with_taint_scrub` fix, wasm's
    /// audit emission bypassed taint scrubbing entirely — an
    /// outbound-taint-refusal denial's `target` field (built from the
    /// RAW argument value) was written to the audit log unredacted.
    /// See crates/host/tests/audit_scrub_wasm_native_parity.rs for the
    /// full integration-level reproducer against both runners; this is
    /// a fast unit-level pin of the same property.
    #[test]
    fn denied_outbound_taint_audit_event_is_scrubbed() {
        use crate::confirm::DenyAllConfirm;
        use std::sync::Mutex;

        #[derive(Default)]
        struct Capture(Mutex<Vec<crate::AuditEvent>>);
        impl crate::AuditSink for Capture {
            fn emit(&self, event: crate::AuditEvent) {
                self.0.lock().unwrap().push(event);
            }
        }

        let secret_path = unique_tmp_path("audit_scrub_secret");
        std::fs::write(&secret_path, "TOPSECRET-must-not-leak").expect("write fixture");
        let path_lit = secret_path.to_string_lossy().replace('\\', "/");
        let out_path = unique_tmp_path("audit_scrub_out");
        let out_path_lit = out_path.to_string_lossy().replace('\\', "/");

        let policy_path = write_temp_policy(
            "audit_scrub",
            &format!(
                "[filesystem]\nlocal_only_read = [\"{path_lit}\"]\nwrite_allow = [\"{out_path_lit}\"]\n"
            ),
        );
        let policy = Policy::load(&policy_path).expect("policy loads");
        let cap = std::sync::Arc::new(Capture::default());
        let runner = WasmRunner::new(policy)
            .with_audit(cap.clone())
            .with_confirm_hook(std::sync::Arc::new(DenyAllConfirm));
        let src = format!(
            "p = \"{path_lit}\"\nsecret = fs.read(p)\nfs.write(\"{out_path_lit}\", secret)\n"
        );
        let result = runner.run("t1", &src, "test.star");
        let _ = std::fs::remove_file(&policy_path);
        let _ = std::fs::remove_file(&secret_path);
        let _ = std::fs::remove_file(&out_path);

        assert!(
            result.is_err(),
            "outbound taint refusal must deny the write"
        );
        let events = cap.0.lock().unwrap();
        assert!(!events.is_empty(), "expected at least one audit event");
        for event in events.iter() {
            let serialized = serde_json::to_string(&event.detail).unwrap();
            assert!(
                !serialized.contains("TOPSECRET-must-not-leak"),
                "raw secret leaked into an audit event: {serialized}"
            );
        }
    }
}
