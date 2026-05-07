#!/usr/bin/env bash
#
# Publish all four Denyx crates to crates.io in dependency order.
#
# Crates and their dep graph:
#
#   denyx-policy   (no internal deps)
#   denyx-host     (depends on denyx-policy)
#   denyx-cli      (depends on denyx-policy + denyx-host)
#   denyx-mcp      (depends on denyx-policy + denyx-host)
#
# Cargo can't publish all four in one shot — workspace deps with
# version specs require the upstream crate to already be visible
# in the crates.io index before the downstream's `cargo publish`
# starts. Between each step we wait for index propagation
# (typically 15–60 seconds).
#
# `cargo publish --dry-run` has the same limitation: it only fully
# works on the leaf crate (`denyx-policy`). For downstream crates,
# cargo strips the `path = "..."` part of the workspace dep at
# packaging time and tries to resolve `denyx-policy = "0.1.0"`
# against the crates.io index — which fails because nothing is
# published yet. This is a known cargo design choice, not a bug in
# our manifests.
#
# To dry-run the downstream crates without that false-positive
# failure, this script uses `cargo package --list` for them, which
# validates the manifest and tarball contents (LICENSE, README,
# sources, tests) without any registry resolution. The leaf crate
# still gets the full `cargo publish --dry-run` (compile-from-tarball
# verification included).
#
# A more polished alternative is `cargo install cargo-release` and
# `cargo release <version> --workspace --execute`, which handles
# the index polling automatically. This script is the
# zero-extra-deps fallback.
#
# Usage:
#
#   # Dry-run first (always do this — verifies metadata and package
#   # contents; full compile-the-tarball verification happens for the
#   # leaf crate, see note above):
#   ./scripts/publish.sh --dry-run
#
#   # Real publish (requires CARGO_REGISTRY_TOKEN set, or
#   # `cargo login` already done):
#   ./scripts/publish.sh
#
# Pre-flight checklist before running for real:
#
#   1. CHANGELOG.md has an entry for the version being released
#      (matches `version` in workspace Cargo.toml).
#   2. `git status` is clean — nothing uncommitted.
#   3. `cargo test --workspace --locked` is green.
#   4. `cargo fmt --all --check` and `cargo clippy --workspace
#      --all-targets --locked -- -D warnings` are green.
#   5. You've tagged the release: `git tag v$VERSION && git push
#      --tags`.
#   6. The crates.io account that holds the token is the owner of
#      all four crates (or first publish — owner is set on first
#      upload).

set -euo pipefail

CRATES=(
    denyx-policy
    denyx-host
    denyx-cli
    denyx-mcp
)

# How long to wait between publishes for the crates.io index to
# update. crates.io's sparse index is usually quick (~15s) but
# slow paths exist; 30s is the conservative default.
SLEEP_SECONDS="${DENYX_PUBLISH_SLEEP:-30}"

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    echo "==> DRY RUN: no uploads will happen."
fi

cd "$(dirname "$0")/.."

# Sanity: the workspace must build clean before we publish
# anything. cargo publish runs build internally for each crate's
# packaged tarball, so this is partly redundant — but catching a
# build failure at the workspace level gives a clearer error
# message than catching it inside a per-crate `cargo publish`.
echo "==> Workspace build sanity check..."
cargo build --workspace --locked

LEAF_CRATE="${CRATES[0]}"

for crate in "${CRATES[@]}"; do
    echo
    if [[ -n "${DRY_RUN}" && "${crate}" != "${LEAF_CRATE}" ]]; then
        # Downstream crate in dry-run mode: cargo publish --dry-run
        # would fail trying to resolve the not-yet-published upstream
        # against the crates.io index. Use cargo package --list
        # instead — it validates the manifest and tarball contents
        # without registry resolution. See header comment.
        echo "==> Validating ${crate} (cargo package --list — registry-free)..."
        n_files=$(cargo package --list -p "${crate}" --locked 2>/dev/null | wc -l)
        echo "    OK: ${n_files} files would be packaged."
    else
        echo "==> Publishing ${crate}..."
        cargo publish -p "${crate}" ${DRY_RUN} --locked
    fi

    if [[ -z "${DRY_RUN}" && "${crate}" != "${CRATES[-1]}" ]]; then
        echo "==> Sleeping ${SLEEP_SECONDS}s for crates.io index propagation..."
        sleep "${SLEEP_SECONDS}"
    fi
done

if [[ -n "${DRY_RUN}" ]]; then
    echo
    echo "==> DRY RUN complete. Re-run without --dry-run to actually publish."
else
    echo
    echo "==> All crates published."
    echo "    Verify on:"
    for crate in "${CRATES[@]}"; do
        echo "      https://crates.io/crates/${crate}"
    done
fi
