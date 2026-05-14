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
//! - imports under module `"denyx"`: `host_print` (Phase 4.1); the rest
//!   wired one capability at a time in subsequent Phase 4 commits.
//! - exports: `denyx_alloc(len)` / `denyx_dealloc(ptr, len)` — the host
//!   calls these to return byte-buffer payloads (string results from
//!   gated builtins) back into the interpreter's linear memory.
//!
//! ## What this commit does (and does NOT do)
//!
//! Phase 4.1 — scaffolding. The WasmRunner instantiates the .wasm,
//! wires WASI preview1 plus a `host_print` stub that forwards into the
//! returned [`RunOutcome`], and decodes the JSON response. No host
//! builtin (`fs.read`, `net.http_*`, …) is reshaped yet; scripts that
//! call those will trap with an unsatisfied-import error at
//! instantiation. Gate-through-Policy wiring lands in subsequent
//! Phase 4 sub-commits.

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
    ///
    /// `task_id` is stamped into audit events. `source` is the
    /// Starlark source. `script_name` is the filename used in error
    /// messages.
    pub fn run(
        &self,
        task_id: &str,
        source: &str,
        script_name: &str,
    ) -> Result<RunOutcome, DenyxError> {
        // Build the JSON request the interpreter expects on stdin.
        let request = serde_json::json!({
            "task_id": task_id,
            "source_path": script_name,
            "source": source,
        });
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| DenyxError::Other(format!("serialize wasm request: {e}")))?;

        // Engine + module. The module bytes are the pre-built
        // wasm32-wasip1 interpreter, embedded in denyx-runtime-starlark.
        let mut config = Config::new();
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        let engine =
            Engine::new(&config).map_err(|e| DenyxError::Other(format!("wasmtime engine: {e}")))?;
        let module = Module::new(&engine, STARLARK_INTERPRETER_WASM)
            .map_err(|e| DenyxError::Other(format!("wasmtime module load: {e}")))?;

        // WASI preview1 ctx, with the request piped on stdin and stdout
        // captured into an in-memory buffer for the JSON response.
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
        };
        let mut store = Store::new(&engine, state);

        let mut linker: Linker<WasmState> = Linker::new(&engine);
        add_to_linker_sync(&mut linker, |s: &mut WasmState| &mut s.wasi)
            .map_err(|e| DenyxError::Other(format!("wasi linker: {e}")))?;

        // host_print: read a UTF-8 slice from guest linear memory and
        // append it to the run's printed lines. Phase 4.1 has no gate
        // here — print is observable but not policy-gated. The other
        // capabilities (Phase 4.2+) will gate through Policy.
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

        // Instantiate and run `_start`. `_start` is the WASI entry point;
        // the interpreter reads stdin, evaluates, writes stdout, returns.
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| DenyxError::Other(format!("wasm instantiate: {e}")))?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| DenyxError::Other(format!("missing _start: {e}")))?;
        start
            .call(&mut store, ())
            .map_err(|e| DenyxError::Other(format!("wasm trap: {e}")))?;

        // Collect the interpreter's response from the stdout pipe and
        // the printed lines from host_print. The interpreter's response
        // is a single JSON line terminated by newline.
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
                // Destructure once to avoid borrow-after-move on response.error.
                let (kind, message) = match response.error {
                    Some(e) => (e.kind, e.message),
                    None => (String::new(), "(no error info)".to_string()),
                };
                let formatted = if kind.is_empty() {
                    message
                } else {
                    format!("{kind}: {message}")
                };
                // Map kind back to the right DenyxError variant. Phase
                // 4.1 only sees starlark-parse / starlark-eval / io /
                // protocol; Policy denials don't fire here yet because
                // no builtin gates are wired.
                let mapped = match kind.as_str() {
                    "starlark-parse" | "starlark-eval" | "io" | "protocol" => {
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
/// import writes into.
struct WasmState {
    wasi: WasiP1Ctx,
    printed: Vec<String>,
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

    /// The Phase 4.1 smoke parity test: a script that calls `print()`
    /// round-trips through the WasmRunner and the call gets observed
    /// via the `host_print` import. Eval result is discarded (same as
    /// the in-process Runner — `RunOutcome` only carries `printed`).
    #[test]
    fn smoke_print_through_wasm() {
        let policy = Policy::secure_defaults_at(std::env::current_dir().unwrap())
            .expect("secure-defaults loads");
        let runner = WasmRunner::new(policy);
        let outcome = runner
            .run("test", "print('hello'); 1 + 2", "smoke.star")
            .expect("WasmRunner runs");
        assert_eq!(outcome.printed, vec!["hello".to_string()]);
    }

    /// Negative path: a parse error should surface as DenyxError::Starlark.
    #[test]
    fn smoke_parse_error_surfaces() {
        let policy = Policy::secure_defaults_at(std::env::current_dir().unwrap())
            .expect("secure-defaults loads");
        let runner = WasmRunner::new(policy);
        let err = runner
            .run("test", "this is not valid starlark $", "smoke.star")
            .expect_err("parse should fail");
        match err {
            DenyxError::Starlark(_) => {}
            other => panic!("expected DenyxError::Starlark, got {other:?}"),
        }
    }

    /// Phase 4.2 structural check: the interpreter exposes the
    /// `denyx_alloc` / `denyx_dealloc` export pair that Phase 4.3+
    /// will use to return string payloads from gated builtins. This
    /// test just asserts the exports are present; their callers come
    /// online in subsequent Phase 4 sub-commits.
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
}
