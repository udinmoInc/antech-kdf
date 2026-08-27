//! Adversarial reliability validation campaign entrypoint.

use antech_kdf_research::engineering::adversarial_validation::{default_out_dir, run_campaign};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = default_out_dir();
    println!("adversarial validation → {}", out.display());
    let summary = run_campaign(&out)?;
    println!(
        "executions={} fails={} crashes={} hangs={} panics={} races={} leaks={} bugs_found={} bugs_fixed={} blocked={} not_run={} verdict={}",
        summary.total_executions,
        summary.total_failures,
        summary.total_crashes,
        summary.total_hangs,
        summary.total_panics,
        summary.total_races,
        summary.total_leaks,
        summary.total_bugs_found,
        summary.total_bugs_fixed,
        summary.total_blocked,
        summary.total_not_run,
        summary.verdict
    );
    if summary.total_failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}
