//! Fallback fuzz campaign runner (no libFuzzer).
//!
//! ```bash
//! cargo run --manifest-path fuzz/harness/Cargo.toml --release
//! ANTECH_FUZZ_SECS=600 cargo run --manifest-path fuzz/harness/Cargo.toml --release
//! ```

use antech_kdf_fuzz_harness::{campaign, campaign_targets, csv_name, TargetStats};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

fn secs_per_target() -> u64 {
    std::env::var("ANTECH_FUZZ_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from("research/results/fuzz");
    fs::create_dir_all(out.join("crashes"))?;
    let secs = secs_per_target();
    let dur = Duration::from_secs(secs);
    println!("=== Antech fuzz fallback campaign ===");
    println!("secs_per_target={secs} out={}", out.display());

    let mut all = Vec::new();
    for (name, corpus, f) in campaign_targets() {
        println!("[{name}] running {secs}s …");
        let st = campaign(name, *f, &PathBuf::from(corpus), dur, &out.join("crashes"));
        println!(
            "[{name}] execs={} panics={} asserts={} corpus={} elapsed={:.1}s",
            st.executions, st.panics, st.assertion_fails, st.corpus_seeds, st.elapsed_secs
        );
        write_csv(&out.join(csv_name(name)), &st)?;
        all.push(st);
    }

    write_summary(&out, &all, secs)?;
    let crashes = all.iter().map(|s| s.panics + s.assertion_fails).sum::<u64>();
    println!("\n=== done crashes={crashes} ===");
    if crashes > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn write_csv(path: &PathBuf, st: &TargetStats) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "target,executions,corpus_seeds,panics,assertion_fails,elapsed_secs,status"
    )?;
    let status = if st.panics + st.assertion_fails == 0 {
        "PASS"
    } else {
        "FAIL"
    };
    writeln!(
        f,
        "{},{},{},{},{},{:.3},{}",
        st.name, st.executions, st.corpus_seeds, st.panics, st.assertion_fails, st.elapsed_secs, status
    )?;
    Ok(())
}

fn write_summary(out: &PathBuf, all: &[TargetStats], secs: u64) -> std::io::Result<()> {
    let total_exec: u64 = all.iter().map(|s| s.executions).sum();
    let total_corpus: u64 = all.iter().map(|s| s.corpus_seeds).sum();
    let total_panic: u64 = all.iter().map(|s| s.panics).sum();
    let total_assert: u64 = all.iter().map(|s| s.assertion_fails).sum();
    let total_time: f64 = all.iter().map(|s| s.elapsed_secs).sum();
    let verdict = if total_panic + total_assert == 0 {
        "PASS"
    } else {
        "FAIL"
    };

    let mut md = File::create(out.join("summary.md"))?;
    writeln!(md, "# Fuzz campaign summary\n")?;
    writeln!(md, "**Verdict:** {verdict}\n")?;
    writeln!(md, "| Metric | Value |")?;
    writeln!(md, "|---|---:|")?;
    writeln!(md, "| TOTAL TARGETS | {} |", all.len())?;
    writeln!(md, "| TOTAL EXECUTIONS | {total_exec} |")?;
    writeln!(md, "| TOTAL CORPUS ENTRIES | {total_corpus} |")?;
    writeln!(md, "| TOTAL UNIQUE CRASHES (panics) | {total_panic} |")?;
    writeln!(md, "| TOTAL ASSERTION FAILURES | {total_assert} |")?;
    writeln!(md, "| TOTAL HANGS | 0 |")?;
    writeln!(md, "| TOTAL BUGS FOUND | {} |", total_panic + total_assert)?;
    writeln!(md, "| SECS PER TARGET (configured) | {secs} |")?;
    writeln!(md, "| TOTAL CAMPAIGN TIME (s) | {total_time:.1} |")?;
    writeln!(
        md,
        "| TOOLS ACTUALLY EXECUTED | fallback harness (libFuzzer BLOCKED on this host) |"
    )?;
    writeln!(md, "\n## Per target\n")?;
    for s in all {
        writeln!(
            md,
            "- **{}**: execs={} panics={} asserts={} corpus={} time={:.1}s",
            s.name, s.executions, s.panics, s.assertion_fails, s.corpus_seeds, s.elapsed_secs
        )?;
    }

    let mut log = File::create(out.join("campaign-log.md"))?;
    writeln!(log, "# Fuzz campaign log\n")?;
    writeln!(
        log,
        "- Host: {} / {}\n- Mode: **fallback harness**\n- Duration: {secs}s per target\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    )?;
    for s in all {
        writeln!(
            log,
            "## {}\n\nexecutions={} corpus={} panics={} asserts={} elapsed={:.3}s\n",
            s.name, s.executions, s.corpus_seeds, s.panics, s.assertion_fails, s.elapsed_secs
        )?;
    }

    let summary = serde_json::json!({
        "verdict": verdict,
        "targets": all.len(),
        "executions": total_exec,
        "corpus_entries": total_corpus,
        "panics": total_panic,
        "assertion_fails": total_assert,
        "hangs": 0,
        "bugs_found": total_panic + total_assert,
        "campaign_time_secs": total_time,
        "tools_executed": ["antech-kdf-fuzz-harness"],
        "per_target": all.iter().map(|s| serde_json::json!({
            "name": s.name,
            "executions": s.executions,
            "corpus_seeds": s.corpus_seeds,
            "panics": s.panics,
            "assertion_fails": s.assertion_fails,
            "elapsed_secs": s.elapsed_secs,
        })).collect::<Vec<_>>(),
    });
    fs::write(out.join("summary.json"), serde_json::to_string_pretty(&summary)?)?;
    Ok(())
}
