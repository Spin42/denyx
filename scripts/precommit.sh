#!/usr/bin/env bash
# Run the same fmt + clippy gates as .github/workflows/ci.yml's
# `fmt` and `clippy` jobs, locally, before a commit lands or before
# a push. Keep this in sync with the workflow — if CI tightens a
# flag, mirror it here so contributors see the same failure
# locally instead of catching it after the push.
#
# Usage:
#
#   ./scripts/precommit.sh
#
# Or wired automatically through git's hooks system:
#
#   git config core.hooksPath .githooks
#
# After that one-time `core.hooksPath` setup, `git commit` runs
# .githooks/pre-commit which calls this script.
#
# The hook deliberately does NOT run `cargo test --workspace`. The
# full test suite is ~30s and would make `git commit` annoying.
# Run tests manually before pushing, or wire a separate pre-push
# hook if you want them automatic too.

set -euo pipefail

cd "$(dirname "$0")/.."

# Color helpers — degrade gracefully if not a TTY.
if [[ -t 1 ]]; then
    bold=$'\033[1m'
    green=$'\033[32m'
    red=$'\033[31m'
    reset=$'\033[0m'
else
    bold="" green="" red="" reset=""
fi

step() {
    echo "${bold}==> $*${reset}"
}

fail() {
    echo "${red}✗ precommit failed at: $*${reset}" >&2
    echo "    fix locally with: cargo fmt --all && cargo clippy --workspace --all-targets --locked --fix" >&2
    exit 1
}

# Matches .github/workflows/ci.yml's `fmt` job exactly.
step "cargo fmt --all -- --check"
cargo fmt --all -- --check || fail "cargo fmt"

# Matches the `clippy` job exactly. -D warnings keeps it strict.
step "cargo clippy --workspace --all-targets --locked -- -D warnings"
cargo clippy --workspace --all-targets --locked -- -D warnings || fail "cargo clippy"

echo "${green}✓ precommit gates: PASS${reset}"
