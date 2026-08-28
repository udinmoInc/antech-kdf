# Hardware validation CI wrapper (Windows)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$Profile = if ($env:ANTECH_HARDWARE_VALIDATION_PROFILE) { $env:ANTECH_HARDWARE_VALIDATION_PROFILE } else { "ci" }
$BuildProfile = if ($env:ANTECH_BUILD_PROFILE) { $env:ANTECH_BUILD_PROFILE } else { "release" }

Write-Host "=== hardware validation profile=$Profile build=$BuildProfile ==="

cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings

$env:ANTECH_HARDWARE_VALIDATION_PROFILE = $Profile
if ($BuildProfile -eq "debug") {
    cargo run --manifest-path research/code/Cargo.toml `
        -p antech-kdf-research --example hardware_validation_runner
} else {
    cargo run --manifest-path research/code/Cargo.toml --release `
        -p antech-kdf-research --example hardware_validation_runner
}

if (-not (Test-Path "research/results/hardware-validation/report.md")) {
    throw "missing report.md"
}
Write-Host "=== hardware validation complete ==="
