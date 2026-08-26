//! Production-path stress campaign → research/results/stress/
//!
//! Run from repository root:
//!   cargo run --manifest-path research/code/Cargo.toml --release \
//!     -p antech-kdf-research --example production_stress_runner
//!
//! Optional env:
//!   ANTECH_PROD_STRESS_SECS=10,30,60
//!   ANTECH_PROD_STRESS_CONC=1,10,32,100,250,500,1000

use antech_kdf_research::engineering::production_stress::{
    default_out_dir, run_full_campaign, write_campaign_outputs,
};
use std::process::ExitCode;

fn main() -> ExitCode {
    let out = default_out_dir();
    println!("Writing results to {}", out.display());
    let summary = run_full_campaign();
    if let Err(e) = write_campaign_outputs(&out, &summary) {
        eprintln!("failed to write outputs: {e}");
        return ExitCode::FAILURE;
    }
    println!("\n=== Campaign complete ===");
    println!("verdict={}", summary.verdict);
    println!(
        "all_idle={} unexpected_errors={} panics={} budget_violations={} queue_limit_violations={}",
        summary.all_idle,
        summary.unexplained_errors,
        summary.unexplained_panics,
        summary.budget_violations,
        summary.queue_limit_violations
    );
    println!("report={}", out.join("stress-report.md").display());

    if summary.verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
