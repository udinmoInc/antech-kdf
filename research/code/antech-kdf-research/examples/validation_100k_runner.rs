//! 100,000-case adversarial validation campaign entrypoint.

use antech_kdf_research::engineering::validation_100k::{default_out_dir, run_campaign};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = default_out_dir();
    println!("100k validation → {}", out.display());
    let summary = run_campaign(&out)?;
    println!(
        "executed={} pass={} fail={} blocked={} not_run={} reached_100k={} verdict={}",
        summary.executed_cases,
        summary.pass,
        summary.fail,
        summary.blocked,
        summary.not_run,
        summary.reached_100k_executed,
        summary.verdict
    );
    if summary.fail > 0 || !summary.reached_100k_executed {
        std::process::exit(1);
    }
    Ok(())
}
