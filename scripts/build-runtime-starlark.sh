#!/usr/bin/env bash
# Build the denyx-interpreter for wasm32-wasip1 and stage the .wasm
# into denyx-runtime-starlark. CI runs an equivalent step before
# `cargo publish -p denyx-runtime-starlark`.
#
# Use locally before any `cargo build` that touches denyx-runtime-starlark
# (or any crate downstream of it). The artefact is gitignored, so a
# fresh clone has no .wasm until this script runs.
#
# Reproducibility: the same git checkout should produce a byte-identical
# .wasm on any host. See crates/runtime-starlark/README.md for the
# verification recipe.

set -euo pipefail

cd "$(dirname "$0")/.."

target_dir="${CARGO_TARGET_DIR:-target}"

echo "==> cargo build -p denyx-interpreter --target wasm32-wasip1 --release"
cargo build -p denyx-interpreter --target wasm32-wasip1 --release

src="$target_dir/wasm32-wasip1/release/denyx-interpreter.wasm"
dst="crates/runtime-starlark/starlark_interpreter.wasm"

if [[ ! -f "$src" ]]; then
    echo "expected wasm artefact missing at: $src" >&2
    exit 1
fi

cp "$src" "$dst"

# CI sets STARLARK_VERSION and INTERPRETER_BUILT_AT before running this
# script; build.rs in denyx-runtime-starlark forwards them into
# compile-time env!() constants. Locally they default to "dev".

size=$(stat -c%s "$dst")
sha=$(sha256sum "$dst" | cut -d' ' -f1)
echo "==> staged $dst"
echo "    size   : $size bytes"
echo "    sha256 : $sha"
