//! Final engineering validation → research/results/final-validation/
//!
//!   ANTECH_FINAL_VALIDATION_PROFILE=ci|full \
//!   cargo run --manifest-path research/code/Cargo.toml --release \
//!     -p antech-kdf-research --example final_validation_runner

use antech_kdf_research::engineering::final_validation::{default_out_dir, run};
use std::process::ExitCode;

fn main() -> ExitCode {
    let out = default_out_dir();
    let summary = run(&out);
    println!("\n=== Final validation ===");
    println!("verdict={}", summary.verdict);
    println!(
        "checks={} pass={} fail={} blocked={} not_run={}",
        summary.checks.len(),
        summary
            .checks
            .iter()
            .filter(|c| matches!(
                c.status,
                antech_kdf_research::engineering::final_validation::CheckStatus::Pass
            ))
            .count(),
        summary
            .checks
            .iter()
            .filter(|c| matches!(
                c.status,
                antech_kdf_research::engineering::final_validation::CheckStatus::Fail
            ))
            .count(),
        summary
            .checks
            .iter()
            .filter(|c| matches!(
                c.status,
                antech_kdf_research::engineering::final_validation::CheckStatus::Blocked
            ))
            .count(),
        summary
            .checks
            .iter()
            .filter(|c| matches!(
                c.status,
                antech_kdf_research::engineering::final_validation::CheckStatus::NotRun
            ))
            .count(),
    );
    println!("report={}", out.join("final-report.md").display());
    if summary.verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
