#!/usr/bin/env bash
# Hardware validation CI wrapper — runs workspace gates + hardware_validation_runner.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

PROFILE="${ANTECH_HARDWARE_VALIDATION_PROFILE:-ci}"
BUILD_PROFILE="${ANTECH_BUILD_PROFILE:-release}"

echo "=== hardware validation profile=${PROFILE} build=${BUILD_PROFILE} ==="

cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings

if [[ "${BUILD_PROFILE}" == "debug" ]]; then
  ANTECH_HARDWARE_VALIDATION_PROFILE="${PROFILE}" \
    cargo run --manifest-path research/code/Cargo.toml \
      -p antech-kdf-research --example hardware_validation_runner
else
  ANTECH_HARDWARE_VALIDATION_PROFILE="${PROFILE}" \
    cargo run --manifest-path research/code/Cargo.toml --release \
      -p antech-kdf-research --example hardware_validation_runner
fi

echo "=== hardware validation complete ==="
test -f research/results/hardware-validation/report.md
