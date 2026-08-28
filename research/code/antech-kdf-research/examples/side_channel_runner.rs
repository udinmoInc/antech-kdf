//! Deep side-channel validation campaign entrypoint.

use antech_kdf_research::engineering::side_channel_campaign::{default_out_dir, run_campaign};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = default_out_dir();
    println!("side-channel campaign → {}", out.display());
    let summary = run_campaign(&out)?;
    println!(
        "verdict={} timing_rows={} derive_leaks={} fast_oracles={} cache_blocked={}",
        summary.verdict,
        summary.timing_rows,
        summary.significant_derive_leaks,
        summary.fast_path_oracles,
        summary.blocked_cache
    );
    if summary.verdict == "FAIL" {
        std::process::exit(1);
    }
    Ok(())
}
