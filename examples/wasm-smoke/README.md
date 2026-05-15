# wasm-smoke

Hand-written wasmtime harness for `crates/interpreter`. Validates that
the `denyx-interpreter.wasm` artefact:

1. Instantiates under wasmtime.
2. Round-trips the stdin/stdout JSON wire protocol.
3. Fires the `denyx::host_print` Wasm import when the script calls
   `print()`.

This is the Phase 2 acceptance test from the wasmtime-sandbox migration
plan — "Phases 1-3 have produced a working .wasm that runs under
Wasmtime with hand-written test imports."

## What this does **not** test

- Anything about policy enforcement. The `host_print` stub here does
  no gating. Real gating arrives in Phase 4 when the host wires its
  builtins through the Wasm import boundary and routes each call
  through the existing `denyx-policy` gate.
- The full builtin surface. Only `host_print` is exercised — that's
  also the only import the Phase 2 interpreter declares.
- Wasmtime fuel / preemption. That's a Phase 5 acceptance criterion.

The Phase 5 host-side wiring will use wasmtime's Rust API, not
wasmtime-py. The wire protocol is language-agnostic, so this Python
harness is a structural smoke test, not a Rust API rehearsal.

## Run it

```sh
# Build the interpreter .wasm (once per change to crates/interpreter):
cargo build -p denyx-interpreter --target wasm32-wasip1 --release

# Create a venv with wasmtime-py (once per machine):
python3 -m venv /tmp/wasm_smoke_venv
/tmp/wasm_smoke_venv/bin/pip install wasmtime

# Run the smoke test:
/tmp/wasm_smoke_venv/bin/python examples/wasm-smoke/smoke.py
```

A successful run prints the interpreter's JSON response, the
`host_print` lines the harness captured, and exits 0. Non-zero exit
means the .wasm or the wire protocol regressed.

## Custom invocations

```sh
# Different Starlark source:
/tmp/wasm_smoke_venv/bin/python examples/wasm-smoke/smoke.py \
    target/wasm32-wasip1/release/denyx-interpreter.wasm \
    "x = [1, 2, 3]; print(x); sum(x)"

# Force an error path (unparseable source):
/tmp/wasm_smoke_venv/bin/python examples/wasm-smoke/smoke.py \
    target/wasm32-wasip1/release/denyx-interpreter.wasm \
    "this is not valid starlark $"
```
