#!/usr/bin/env bash
set -euo pipefail

echo "==> fmt"
cargo fmt --check

echo "==> clippy"
cargo clippy --all-targets -- -D warnings

echo "==> test"
cargo test

echo "==> test (integration)"
cargo test --test integration_test -- --ignored

echo "==> doc"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

if command -v cargo-deny >/dev/null 2>&1; then
    echo "==> deny"
    cargo deny check
else
    echo "warn: cargo-deny not found, skipping"
fi

if command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "==> coverage"
    cargo llvm-cov --lcov --output-path lcov.info --fail-under-lines 70
else
    echo "warn: cargo-llvm-cov not found, skipping"
fi

echo "==> done"
