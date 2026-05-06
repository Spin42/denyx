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

## Triage

- A panic / abort produces a reproducer in
  `fuzz/artifacts/<target>/`. `cargo +nightly fuzz fmt <target>
  <artifact>` pretty-prints the input.
- A timeout (default 1 s per input) is also a finding — usually a
  pathological glob or a TOML deserialization edge case.
- Fix the underlying defect in the crate, then re-add the artifact
  bytes as a regression test in the corresponding `tests/` file.
