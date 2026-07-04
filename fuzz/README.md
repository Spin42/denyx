# Denyx fuzz harnesses

Three coverage-guided fuzz targets for the load-bearing parsers /
matchers in the Denyx runtime:

| Target          | What it fuzzes                                          |
|-----------------|---------------------------------------------------------|
| `verifier`      | The pre-execution verifier's string/comment stripper + capability scanner (`crates/host/src/verifier.rs`). |
| `policy_toml`   | TOML deserialization + resolution into a runtime [`Policy`] (`crates/policy/src/lib.rs`). |
| `policy_globs`  | Glob-pattern compilation and `check_fs_{read,write,delete}` path matching. |

## Run with nightly + libFuzzer (canonical)

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run verifier
cargo +nightly fuzz run policy_toml
cargo +nightly fuzz run policy_globs
```

`cargo-fuzz` keeps a corpus in `fuzz/corpus/<target>/` and crashes in
`fuzz/artifacts/<target>/`. Both directories are gitignored.

## Run on stable (regression sweep)

`cargo test -p denyx-host --test fuzz_stable` and
`cargo test -p denyx-policy --test fuzz_stable` drive the same three
surfaces with a deterministic 100 000-iteration random sweep using a
hand-rolled xorshift PRNG. This runs in CI on stable — it doesn't
have libFuzzer's coverage feedback, but it catches the same class of
parser-panic / glob-explosion bugs and pins the runtime against
regressions.

## CI

`.github/workflows/fuzz.yml` runs the three real libFuzzer targets on
a weekly schedule (Thursday 06:00 UTC, offset from
`.github/workflows/mutants.yml`'s Monday slot) plus `workflow_dispatch`
for on-demand runs. Each target gets a bounded time budget
(`-max_total_time`, currently 600s) rather than running to
exhaustion — this is a periodic audit signal, not a merge gate, same
reasoning as the mutation-testing schedule (see
[mutation-testing.md](../docs/mutation-testing.md#schedule-not-gate)).
The corpus is cached across runs so coverage accumulates week over
week instead of restarting cold. Unlike the mutation-testing
workflow, a fuzz crash is a real, reproducible bug — the job fails
loudly and uploads the crashing input as an artifact; it doesn't
soft-fail.

The stable pseudo-fuzz sweep (`fuzz_stable` tests, above) is separate
and runs on every `cargo test --workspace` in `ci.yml` — it's the
fast, deterministic, always-on layer; the scheduled libFuzzer job is
the slow, coverage-guided, periodic layer.

## Triage

- A panic / abort produces a reproducer in
  `fuzz/artifacts/<target>/`. `cargo +nightly fuzz fmt <target>
  <artifact>` pretty-prints the input.
- A timeout (default 1 s per input) is also a finding — usually a
  pathological glob or a TOML deserialization edge case.
- Fix the underlying defect in the crate, then re-add the artifact
  bytes as a regression test in the corresponding `tests/` file.
