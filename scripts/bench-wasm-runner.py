"""
Benchmark the per-invocation cost of `denyx run` under both runners
(default in-process vs `--use-wasm`).

Reports two numbers per runner:
  - Cold-call cost: time(N=1 print)
    For the wasm path this is dominated by wasmtime JIT-compiling
    the embedded Starlark interpreter (~5 MB of wasm → native).
    Paid once per WasmRunner instance.

  - Amortized per-call cost: (time(N=1000) - time(N=1)) / 999
    The marginal cost of one more script-level operation within an
    already-instantiated runner. This is what denyx-mcp pays per
    tool call after the first one.

Methodology: 15 samples per N after 3 warm-up runs discarded. Median
reported. Standard Starlark dialect doesn't allow top-level `for`,
so scripts are flat sequences of `print(...)` statements.

Re-run on your machine with:

    python3 scripts/bench-wasm-runner.py

Numbers will vary with CPU, disk cache state, and current load. The
qualitative gap (wasm path ~100× slower cold, ~7× slower amortized)
is reproducible.
"""

import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DENYX = REPO / "target" / "release" / "denyx"
POLICY = REPO / "examples" / "policies" / "minimal_print.toml"
SCRATCH = Path("/tmp/denyx_bench")
SCRATCH.mkdir(exist_ok=True)


def ensure_setup():
    if not DENYX.exists():
        print(
            f"need release build at {DENYX}; run "
            "`cargo build --release -p denyx-cli` first",
            file=sys.stderr,
        )
        sys.exit(2)
    if not POLICY.exists():
        # Fallback to a minimal inline policy if the canonical one
        # hasn't been added yet.
        fallback = SCRATCH / "bench_policy.toml"
        fallback.write_text('inherits = "secure-defaults"\n')
        return fallback
    return POLICY


def make_script(n):
    path = SCRATCH / f"bench_{n}.star"
    path.write_text("\n".join(f'print("ok {i}")' for i in range(n)) + "\n")
    return path


def time_one(extra_args, script_path, policy_path):
    argv = [
        str(DENYX),
        "run",
        "--policy",
        str(policy_path),
        *extra_args,
        str(script_path),
    ]
    start = time.perf_counter()
    result = subprocess.run(argv, capture_output=True, text=True)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if result.returncode != 0:
        raise RuntimeError(
            f"denyx exit {result.returncode}: stderr={result.stderr!r}"
        )
    return elapsed_ms


def bench(label, extra_args, policy_path, n_values, samples=15, warmup=3):
    print(f"## {label}")
    rows = []
    for n in n_values:
        script = make_script(n)
        times = []
        for i in range(samples + warmup):
            t = time_one(extra_args, script, policy_path)
            if i >= warmup:
                times.append(t)
        times.sort()
        row = {
            "n_prints": n,
            "median_ms": round(times[len(times) // 2], 2),
            "min_ms": round(times[0], 2),
            "stdev_ms": round(statistics.stdev(times), 2),
        }
        rows.append(row)
        print(json.dumps(row))
    if len(rows) >= 2:
        t1 = rows[0]["median_ms"]
        tn = rows[-1]["median_ms"]
        n_delta = rows[-1]["n_prints"] - rows[0]["n_prints"]
        per_call_ms = (tn - t1) / n_delta
        print(
            f"# Amortized per-call cost ((T({rows[-1]['n_prints']})-T({rows[0]['n_prints']}))/{n_delta}): "
            f"{per_call_ms:.4f} ms"
        )
    print()
    return rows


def main():
    policy = ensure_setup()
    print("# bench-wasm-runner.py")
    print(f"# binary: {DENYX}")
    print(f"# policy: {policy}")
    print()
    n_values = [1, 10, 100, 1000]
    bench("in-process Runner", [], policy, n_values)
    bench("WasmRunner (--use-wasm)", ["--use-wasm"], policy, n_values)


if __name__ == "__main__":
    main()
