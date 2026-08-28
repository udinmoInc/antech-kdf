//! Cross-platform hardware validation → research/results/hardware-validation/
//!
//!   ANTECH_HARDWARE_VALIDATION_PROFILE=ci|full \
//!   cargo run --manifest-path research/code/Cargo.toml --release \
//!     -p antech-kdf-research --example hardware_validation_runner

use antech_kdf_research::engineering::hardware_validation::{default_out_dir, run_campaign};
use std::process::ExitCode;

fn main() -> ExitCode {
    let out = default_out_dir();
    let summary = run_campaign(&out);
    println!("\n=== Hardware validation ===");
    println!("platform_id={}", summary.platform_id);
    println!("verdict={}", summary.verdict);
    println!(
        "correctness={} stress={} sdk={} gpu={} regressions={}",
        summary.correctness_verdict,
        summary.stress_verdict,
        summary.sdk_verdict,
        summary.gpu_verdict,
        summary.regressions,
    );
    println!("report={}", out.join("report.md").display());
    if summary.verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
