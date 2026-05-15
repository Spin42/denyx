"""
Smoke test for crates/interpreter's wasm32-wasip1 build.

Loads the .wasm under wasmtime (via wasmtime-py), wires `host_print`
as a hand-written import that accumulates printed lines, pipes a JSON
request to stdin and captures stdout, then asserts the JSON response.

What this proves (and doesn't):
  ✓ The .wasm instantiates under wasmtime with stub imports.
  ✓ The stdin/stdout JSON wire protocol round-trips.
  ✓ The Wasm import boundary fires (host_print receives the line).
  ✗ Nothing about gating — this harness has no policy; the host_print
    stub does no checks. That's Phase 4's job.

The Rust-side host (Phase 4 / Phase 5) will provide the same import
surface via wasmtime's Rust API instead of wasmtime-py. The wire
protocol is language-agnostic.

Usage:
  /tmp/wasm_smoke_venv/bin/python examples/wasm-smoke/smoke.py \\
      [<wasm-path>] [<starlark-source>]

Defaults:
  wasm-path       = target/wasm32-wasip1/release/denyx-interpreter.wasm
  starlark-source = "print('hello from inside wasm'); 1 + 2"
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import wasmtime

REPO = Path(__file__).resolve().parents[2]
DEFAULT_WASM = REPO / "target/wasm32-wasip1/release/denyx-interpreter.wasm"
DEFAULT_SOURCE = "print('hello from inside wasm'); 1 + 2"


def main() -> int:
    wasm_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WASM
    source = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_SOURCE

    if not wasm_path.exists():
        print(
            f"wasm not found at {wasm_path}\n"
            "build it first:\n"
            "  cargo build -p denyx-interpreter --target wasm32-wasip1 --release",
            file=sys.stderr,
        )
        return 2

    request = json.dumps(
        {
            "task_id": "smoke",
            "source_path": "smoke.star",
            "source": source,
        }
    )

    # WasiConfig wants paths for stdin/stdout; use temp files and clean
    # up afterwards. /tmp is the natural scratch tree here.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, prefix="wasm_smoke_stdin_"
    ) as f:
        f.write(request)
        stdin_path = f.name
    stdout_path = tempfile.NamedTemporaryFile(
        suffix=".json", delete=False, prefix="wasm_smoke_stdout_"
    ).name

    try:
        engine = wasmtime.Engine()
        module = wasmtime.Module.from_file(engine, str(wasm_path))
        store = wasmtime.Store(engine)

        wasi = wasmtime.WasiConfig()
        wasi.stdin_file = stdin_path
        wasi.stdout_file = stdout_path
        wasi.inherit_stderr()
        store.set_wasi(wasi)

        linker = wasmtime.Linker(engine)
        linker.define_wasi()

        printed_lines: list[str] = []

        host_print_ty = wasmtime.FuncType(
            [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
            [],
        )

        def host_print(caller, ptr, length):
            # The interpreter's print() handler calls this via the
            # `denyx::host_print` Wasm import. ptr+length describe a
            # UTF-8 slice of the module's linear memory. `access_caller`
            # below gives us the Caller so we can reach the memory.
            memory = caller["memory"]
            raw = memory.read(caller, ptr, ptr + length)
            text = bytes(raw).decode("utf-8")
            printed_lines.append(text)

        linker.define_func(
            "denyx", "host_print", host_print_ty, host_print, access_caller=True
        )

        instance = linker.instantiate(store, module)
        start = instance.exports(store)["_start"]
        start(store)

        response_raw = Path(stdout_path).read_text().strip()
    finally:
        for p in (stdin_path, stdout_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    print("── wasm-smoke result " + "─" * 39)
    print(f"interpreter stdout (raw): {response_raw}")
    try:
        response = json.loads(response_raw)
    except json.JSONDecodeError as e:
        print(f"!! failed to parse interpreter response as JSON: {e}", file=sys.stderr)
        return 3
    print("interpreter response (parsed):")
    print(json.dumps(response, indent=2))
    print(f"host_print received {len(printed_lines)} line(s):")
    for line in printed_lines:
        print(f"  {line!r}")
    print("─" * 60)

    if response.get("status") != "ok":
        err = response.get("error", {}) or {}
        print(
            f"!! interpreter returned non-ok status: "
            f"{err.get('kind', '?')}: {err.get('message', '(no message)')}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
