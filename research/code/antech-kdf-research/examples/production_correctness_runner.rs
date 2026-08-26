//! Exhaustive correctness campaign → research/results/correctness/
//!
//!   cargo run --manifest-path research/code/Cargo.toml --release \
//!     -p antech-kdf-research --example production_correctness_runner

use antech_kdf_research::engineering::production_correctness::{default_out_dir, run_campaign};
use std::process::ExitCode;

fn main() -> ExitCode {
    let out = default_out_dir();
    let summary = run_campaign(&out);
    println!("\n=== Correctness campaign complete ===");
    println!("verdict={}", summary.verdict);
    println!(
        "cases={} pass={} fail={} blocked={} n/a={} panics={}",
        summary.totals.cases,
        summary.totals.pass,
        summary.totals.fail,
        summary.totals.blocked,
        summary.totals.not_applicable,
        summary.totals.panics_caught
    );
    println!("report={}", out.join("report.md").display());
    if summary.verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
