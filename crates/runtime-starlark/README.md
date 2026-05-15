# denyx-runtime-starlark

The pre-built `wasm32-wasip1` Starlark interpreter that the denyx
runtime loads into wasmtime. Ships as a byte slice; consumers don't
need the `wasm32-wasip1` Rust target installed.

```rust
use denyx_runtime_starlark::{STARLARK_INTERPRETER_WASM, STARLARK_VERSION};

let module = wasmtime::Module::new(&engine, STARLARK_INTERPRETER_WASM)?;
```

## How the `.wasm` is built

The artefact is compiled from `crates/interpreter/` (a non-published
workspace member) at the **same git tag** as this crate's `version`.
Build recipe:

```sh
cargo build -p denyx-interpreter --target wasm32-wasip1 --release
# → target/wasm32-wasip1/release/denyx-interpreter.wasm
```

For local development, use the convenience script — it builds the
interpreter and copies the artefact into the runtime-starlark crate
under the expected name:

```sh
./scripts/build-runtime-starlark.sh
```

CI runs an equivalent step before `cargo publish -p denyx-runtime-starlark`.

## Reproducibility

A given git checkout should produce a **byte-identical** `.wasm` on any
host. To verify:

```sh
# build a fresh artefact:
cargo build -p denyx-interpreter --target wasm32-wasip1 --release

# compare against the staged copy:
sha256sum target/wasm32-wasip1/release/denyx-interpreter.wasm
sha256sum crates/runtime-starlark/starlark_interpreter.wasm
# the two hashes must match
```

If the hashes diverge, something in the build environment is
non-reproducible (different Rust toolchain version, different
`Cargo.lock` resolution, host architecture mismatch, etc.). File an
issue — the security argument for shipping a pre-built `.wasm` rests
on byte-identical reproduction from public source at the tagged
commit.

## Why this is its own crate

The `denyx-interpreter` source crate targets `wasm32-wasip1`. End users
who just `cargo install denyx-cli` should not need to install that
Rust target on their machine. Splitting:

- **`denyx-interpreter`** — non-published, source of the `.wasm`.
- **`denyx-runtime-starlark`** (this crate) — published, ships the
  pre-built `.wasm` as a `&[u8]`.

…means `cargo install denyx-cli` is a single command. The interpreter
toolchain only matters to denyx maintainers and CI.

## Build metadata

Two `env!()` constants record build provenance:

| Constant                | Source env var          | Default at local dev |
|-------------------------|-------------------------|----------------------|
| `STARLARK_VERSION`      | `STARLARK_VERSION`      | `"dev"`              |
| `INTERPRETER_BUILT_AT`  | `INTERPRETER_BUILT_AT`  | `"dev"`              |

CI exports both before running `scripts/build-runtime-starlark.sh`,
so the published crate's constants reflect the upstream `starlark`
version pinned in the workspace `Cargo.toml` and the release
timestamp.

## Stability

The interpreter's stdin/stdout JSON wire protocol and Wasm import
surface (`denyx::host_*`) are denyx-internal. Both may change between
denyx minor versions. Consumers outside denyx should treat this crate
as an internal implementation detail.
