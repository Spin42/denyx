# Denyx Wasm Sandbox

> ← [Back to docs README](README.md) · [Threat model](04-security-threat-model.md) · [Policy file](06-policy-file.md)

This doc covers the wasmtime-sandboxed Starlark runner that ships
alongside the original in-process runner. It is **opt-in** in the
current release — pass `--use-wasm` on `denyx run` or `denyx-mcp`.
Promotion to default is pending the items in the [Open work](#open-work)
section below.

If you're an operator wondering whether to flip the switch: read
[Operator-facing differences](#operator-facing-differences) and the
[Open work](#open-work) section. If you're a security reviewer: skip
to [Threat model](#threat-model-differences-from-the-in-process-runner).

## What changed

denyx historically evaluated Starlark scripts in-process via
`starlark-rust`, with policy enforcement in Rust at every effecting
builtin. The wasm-sandbox migration adds a second evaluation path:
the same `starlark-rust` interpreter, but compiled to `wasm32-wasip1`
and executed inside `wasmtime`. The policy gate **stays in Rust on
the host side**; only the Starlark interpreter moves.

The motivation is operational, not security-first: the in-process
runner has no cheap preemption mechanism for runaway pure-computation
scripts (`for _ in range(10**9): pass` runs forever within
`max_seconds`). wasmtime's fuel mechanism solves that cleanly, and
the sandbox additionally contains any future starlark-rust interpreter
bugs to the wasm boundary instead of the whole host process.

## Architecture

Two new crates land alongside the existing ones:

| Crate | Role |
|-------|------|
| `denyx-interpreter` (NOT published) | Thin Rust binary that compiles to `wasm32-wasip1`. Embeds `starlark-rust`, reads a JSON request on stdin, writes a JSON response on stdout, and calls `denyx::host_*` Wasm imports for every effecting builtin. |
| `denyx-runtime-starlark` (published) | Library crate that ships the pre-built `.wasm` artefact as a `&[u8]` byte slice (`STARLARK_INTERPRETER_WASM`). End users never compile `wasm32-wasip1` themselves — the artefact is bundled. |

The original crates gain new members:

| Crate | What changed |
|-------|--------------|
| `denyx-host` | New `WasmRunner` type alongside the in-process `Runner`. Same `.run()` / `.policy()` / `.with_audit()` / `.with_confirm_hook()` surface; internally instantiates wasmtime, wires every `host_*` import to a Rust closure that gates through `Policy`, and runs the embedded interpreter. The cached `Engine` + `Module` mean per-call wasmtime cost is ~5ms after the first call. |
| `denyx-cli` | New `--use-wasm` flag on `denyx run`. When set, dispatches to `WasmRunner`; when not, dispatches to the legacy `Runner`. Output format unchanged. |
| `denyx-mcp` | Same `--use-wasm` flag on the server entry point. The `denyx_*` MCP tool surface is unchanged — synth'd Starlark routes through whichever runner is active. |

```
                       ┌─ in-process Runner (default) ─────┐
denyx run [--use-wasm]─┤                                    │── policy gate
                       └─ WasmRunner ─ wasmtime ─ .wasm ────┘   (same in both)
```

A new MCP tool surfaces during the same migration cycle for purely
ergonomic reasons (large-file efficiency, not security):

- `denyx_fs_read_range(path, offset, limit)` — bounded read at the
  IO layer via `File::seek` + `Read::take(limit)`. Same `read_allow`
  gate as `fs.read`; goes through `fs.read_range` on either runner.
- `denyx_fs_replace(path, old, new)` — read-modify-write with an
  exactly-one-match guard. Refuses if `old` occurs 0 or 2+ times.
  Goes through `fs.read` + `fs.write` gates.

## Threat model differences from the in-process runner

The wasm path is built to be **functionally equivalent** to the
in-process runner at the security boundary. Every defence in
[04-security-threat-model.md](04-security-threat-model.md) carries
across; the only additions are wasmtime's own properties.

| Layer | In-process Runner | WasmRunner | Notes |
|-------|-------------------|------------|-------|
| Policy gate (fs / env / net / subprocess) | ✓ | ✓ | Same `Policy::check_*` calls in the same order |
| Audit emission (`AuditEvent::*`) | ✓ | ✓ | `Allowed` / `Denied` / `Errored` shapes match |
| Taint scrubbing at print boundary | ✓ | ✓ | Same `TaintRegistry` + `redact_lines` |
| Outbound taint refusal (`fs.write`, HTTP body, subprocess argv) | ✓ | ✓ | Same `arg_taint_reason` check per arg |
| Confirm hook (capability + per-argv `requires_approval_args`) | ✓ | ✓ | Same `ConfirmHook` trait, same elicit machinery |
| Subprocess env filtering (`policy.subprocess_env`) | ✓ | ✓ | Same allow_vars filtering |
| Bounded IO read (`fs.read_range`) | ✓ | ✓ | New builtin, same `read_allow` gate |
| **Fuel-based preemption** | ✗ | ✓ | Wasm-only — see below |
| **Interpreter-bug containment** | ✗ | ✓ | Wasm-only — see below |

### Fuel-based preemption (new)

wasmtime fuel is a per-instruction budget. Each Wasm instruction the
guest executes consumes one unit; running out produces `Trap::OutOfFuel`,
which the host catches and surfaces as `DenyxError::RuntimeLimit`
(CLI exit code 6 — same code the in-process runner uses for
`max_seconds` deadline overruns).

`DEFAULT_WASM_FUEL = 200_000_000` is hardcoded today (see
`crates/host/src/wasm_runner.rs`). The Starlark interpreter emits
many Wasm instructions per Starlark operation, so this is an upper
bound on legitimate-script cost, not a tight fit. A runaway loop
like `for _ in range(10**9): pass` trips within ~1 second of CPU on
contemporary hardware.

This is the **gap-closer** the in-process runner cannot offer
without rewriting the interpreter — wall-time deadlines catch
effects, not pure CPU.

### Interpreter-bug containment (new)

A miscompilation or memory-safety bug in `starlark-rust` compromises
the in-process runner directly (the interpreter is in the host
address space). In the wasm path, the same bug stays inside the
wasmtime sandbox: it might crash the guest or trap, but it cannot
read host memory it wasn't explicitly given access to via the
`host_*` imports. This is defence-in-depth, not a primary control.

### What it does NOT change

- The Policy gate is the same code on both paths. A policy that's
  too permissive on the in-process runner is exactly as permissive
  on the wasm path.
- The pre-execution verifier (`crates/host/src/verifier.rs`) runs
  in Rust before any evaluation. It applies to both runners.
- The MCP tool surface is the same. The wasm path doesn't change
  what the cloud orchestrator can see.
- The taint registry's transform set is finite — the same caveat
  in the threat model applies. Wasm doesn't add value-level taint
  propagation through Starlark.

## Operator-facing differences

### Activation

```sh
denyx run --policy <toml> --use-wasm <script.star>
denyx-mcp --policy <toml> --use-wasm
```

Both CLIs print a one-line warning on stderr when `--use-wasm`
fires, naming the current deferral list. The flag is opt-in until
the items in [Open work](#open-work) are closed.

### Exit codes and errors

All `DenyxError` variants the in-process runner emits, the wasm
path emits too:

| Variant | CLI exit | Where it comes from |
|---------|----------|---------------------|
| `Policy(_)` | 2 | Capability gate, outbound taint refusal |
| `Verifier(_)` | 3 | Pre-execution verifier (runs in Rust on both paths) |
| `ConfirmDenied(_)` | 4 | Confirm hook returned Deny |
| `Starlark(_)` | 1 | Parse / eval errors inside the interpreter |
| `RuntimeLimit(_)` | 6 | Wasm fuel exhaustion (or `max_seconds` on in-process) |
| `Io(_)` | 5 | Underlying file / network / spawn failure |
| `Other(_)` | 5 | Wasmtime traps with no captured error, miscellaneous |

The error message body for `RuntimeLimit` differs: in-process says
`"wall-time deadline exceeded after Ns"`, wasm says
`"wasm fuel exhausted after N units"`. Both map to exit 6.

### Performance characteristics

Measured via `scripts/bench-wasm-runner.py` on Linux 6.19 / x86_64 /
opt-level=3, 15 samples per measurement after 3 warm-up runs
discarded. Numbers vary with CPU and disk-cache state; the
qualitative shape is reproducible.

Two costs matter and they are very different:

| Cost | In-process Runner | WasmRunner | Why |
|------|-------------------|------------|-----|
| **Cold call** (process startup + 1 `print`) | 3.8 ms median | **16.5 ms median** | The wasm path loads the AOT-precompiled `.cwasm` shipped by `denyx-runtime-starlark` via `Module::deserialize`. The cwasm is produced at `denyx-runtime-starlark`'s build time on the host architecture (see its `build.rs`). If deserialize fails (different wasmtime version, different Config flags, different target arch), the WasmRunner falls back to JIT-compiling the raw `.wasm` — ~480 ms — same as before AOT existed. |
| **Amortized per-call** (T(1000 prints) − T(1 print)) / 999 | 0.003 ms | 0.004 ms | Marginal cost of one more script-level operation inside an already-instantiated runner. Statistically indistinguishable between the two runners. |

What this means in practice:

- **`denyx run --use-wasm <script>` from a fresh shell** pays
  ~13 ms more than the in-process runner per invocation — wasmtime
  instantiation, store setup, linker wiring. Imperceptible for
  interactive use; matched closely enough by the in-process runner
  that the cost is no longer a blocker for promoting `--use-wasm`
  to default.

- **`denyx-mcp --use-wasm` (long-lived server)** pays the cold-call
  cost once at startup. Every subsequent tool call costs ~4 µs of
  wasm overhead, invisible next to the underlying IO.

- **The runner choice does not change the IO bottleneck.** A
  `fs.read` of a 10 KB file is ~10× more expensive than the runner
  overhead on either path. A `net.http_post` is ~100× more
  expensive.

If the `.cwasm` deserialize fails at runtime (uncommon but possible
on a host with a different wasmtime patch version than the build,
or a different microarchitecture), the WasmRunner transparently
falls back to JIT-compiling the raw `.wasm` — ~480 ms slower but
always correct. No user action is needed.

Memory: wasmtime instances reserve a 4 GB linear memory address
range per `Store`. On 64-bit Linux this is virtual, not resident;
the resident set follows actual interpreter use (typically a few
MB for the Starlark interpreter's working set).

### Audit log shape

Identical to the in-process runner. Every gated call emits one
`AuditEvent` with the same `task_id`, `step`, `capability`,
`status`, and capability-specific `detail`. The SHA-256 chain
(`denyx_seq` + `denyx_prev_hash`) is wrapped by the `AuditSink`
implementation, not by the runner, so chain semantics are
unchanged.

## Open work

The wasm path is not yet promoted to default. Items still
outstanding:

1. ~~No end-to-end multistep eval since the final parity commit.~~
   **Closed 2026-05-14.** Re-ran
   `examples/local_executor/run_multistep.py --use-wasm` against
   `qwen2.5-coder:7b` after all parity work landed: **36/36 PASS**
   (cross 5/5, deny 8/8, file 6/6, http 6/6, local_only 2/2,
   report 4/4, subprocess 5/5). 4 tasks needed a retry (model-
   quality variance, not gate behaviour); all 4 were rescued.
   Both `LOCAL_ONLY_*_redaction` tasks now pass: `auth=Bearer
   [REDACTED]` and `token=[REDACTED]` are the output the harness
   verifies against.

2. **No pentest re-run against the wasm path.** Round 1 and Round
   2 v3 pentest reports cover the in-process runner only. The
   adversarial probes in `examples/local_executor/run_exfil.py`
   and `examples/local_executor/run_pentest.py` have not been
   re-run with `--use-wasm`.

3. **Phase 6 CI integration is not done.** `denyx-runtime-starlark`
   isn't published to crates.io yet. Flipping `--use-wasm` to
   default before this would mean `cargo install denyx-cli` fails
   because the runtime-starlark dependency doesn't resolve.

4. **Bench coverage is process-level only.** The cold-call /
   amortized-per-call numbers in [Performance
   characteristics](#performance-characteristics) come from
   `scripts/bench-wasm-runner.py`. There is no `criterion` bench
   covering the in-process steady-state per-call path on the
   `denyx-mcp` side, and no measurement of fuel-budget headroom on
   realistic scripts.

5. **Fuel budget is hardcoded.** `DEFAULT_WASM_FUEL = 200_000_000`
   is in `crates/host/src/wasm_runner.rs`. Operators have no way
   to tune it via policy. A future `[runtime].max_wasm_fuel`
   policy field would close this.

## Where to look in the code

| File | Role |
|------|------|
| `crates/interpreter/src/main.rs` | The wasm guest. JSON request handling, Starlark eval, `denyx::host_*` extern declarations, `denyx_alloc` / `denyx_dealloc` exports. |
| `crates/host/src/wasm_runner.rs` | `WasmRunner` struct, every `host_*` import closure, the per-closure policy gate + taint check + confirm hook + audit emission. ~3,200 lines of which ~50 lines per closure × 10 closures. |
| `crates/runtime-starlark/src/lib.rs` | The `STARLARK_INTERPRETER_WASM: &[u8]` re-export and the `STARLARK_VERSION` / `INTERPRETER_BUILT_AT` build-provenance constants. |
| `crates/runtime-starlark/build.rs` | Validates the `.wasm` is present at compile time; falls back to a helpful error pointing at `scripts/build-runtime-starlark.sh`. |
| `scripts/build-runtime-starlark.sh` | Local-dev convenience: builds the interpreter for `wasm32-wasip1` and copies the artefact into `crates/runtime-starlark/`. CI runs the equivalent before `cargo publish`. |
| `examples/wasm-smoke/smoke.py` | Hand-written wasmtime-py harness from Phase 2. Validates the wire model end-to-end with stub imports; useful as a structural sanity check after interpreter changes. |

The Phase 4 sub-commit messages on the `wasm-sandbox` branch are the
narrative source-of-truth for each layer — `git log
--oneline main..HEAD` reads as a complete migration timeline.

## Where this doc fits

| Doc | Purpose |
|-----|---------|
| [04-security-threat-model.md](04-security-threat-model.md) | What Denyx claims to defend; what it doesn't. **Read first.** |
| [05-owasp-agentic-coverage.md](05-owasp-agentic-coverage.md) | OWASP Agentic mapping. |
| [06-policy-file.md](06-policy-file.md) | Policy file reference. |
| **This doc** (`wasm-sandbox.md`) | What the wasm sandbox adds, what it doesn't change, what's still open. |
| [security-pentest-r2-tool-poisoning.md](security-pentest-r2-tool-poisoning.md) | Round 2 pentest — in-process runner only at time of writing. |
