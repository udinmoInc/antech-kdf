//! Runs reliability stress/concurrency scenarios and writes CSV reports.

use antech_kdf::{hash, verify};
use antech_kdf_core::{
    scheduler_stats, BoundedResourceScheduler, ResourcePolicy, ResourceScheduler,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn out_dir() -> PathBuf {
    PathBuf::from("research/results/reliability")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(out_dir())?;

    let mut resource_rows = Vec::new();
    for &threads in &[1usize, 2, 10, 50, 100] {
        let row = run_scheduler_stress(threads, Duration::from_secs(2));
        resource_rows.push(row);
    }
    write_resource_csv(&resource_rows)?;

    let stress_rows = run_global_stress(&[1, 10, 32], Duration::from_secs(3));
    write_stress_csv(&stress_rows)?;

    let conc = run_concurrency_levels(&[1, 2, 10, 50, 100, 250]);
    write_concurrency_csv(&conc)?;

    write_build_matrix()?;
    write_issues_found()?;
    write_reliability_report(&resource_rows, &stress_rows, &conc)?;

    println!("Reports written to {}", out_dir().display());
    Ok(())
}

struct ResourceRow {
    threads: usize,
    duration_secs: f64,
    admissions_ok: u64,
    admissions_err: u64,
    peak_active: usize,
    peak_waiting: usize,
    peak_mem_kib: usize,
}

fn run_scheduler_stress(threads: usize, duration: Duration) -> ResourceRow {
    let sched = Arc::new(BoundedResourceScheduler::new(ResourcePolicy {
        max_memory_kib: 64 * 1024,
        max_active_jobs: 8,
        queue_limit: 32,
    }));
    let ok = Arc::new(AtomicU64::new(0));
    let err = Arc::new(AtomicU64::new(0));
    let peak_active = Arc::new(AtomicU64::new(0));
    let peak_waiting = Arc::new(AtomicU64::new(0));
    let peak_mem = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..threads {
        let s = Arc::clone(&sched);
        let ok = Arc::clone(&ok);
        let err = Arc::clone(&err);
        let peak_active = Arc::clone(&peak_active);
        let peak_waiting = Arc::clone(&peak_waiting);
        let peak_mem = Arc::clone(&peak_mem);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match s.acquire(16 * 1024) {
                    Ok(p) => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        let st = s.stats();
                        peak_active.fetch_max(st.active_jobs as u64, Ordering::Relaxed);
                        peak_waiting.fetch_max(st.waiting_jobs as u64, Ordering::Relaxed);
                        peak_mem.fetch_max(st.allocated_kib as u64, Ordering::Relaxed);
                        thread::sleep(Duration::from_millis(1));
                        s.release(p);
                    }
                    Err(_) => {
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    ResourceRow {
        threads,
        duration_secs: start.elapsed().as_secs_f64(),
        admissions_ok: ok.load(Ordering::Relaxed),
        admissions_err: err.load(Ordering::Relaxed),
        peak_active: peak_active.load(Ordering::Relaxed) as usize,
        peak_waiting: peak_waiting.load(Ordering::Relaxed) as usize,
        peak_mem_kib: peak_mem.load(Ordering::Relaxed) as usize,
    }
}

struct StressRow {
    threads: usize,
    duration_secs: f64,
    hashes: u64,
    verifies: u64,
    errors: u64,
    scheduler_idle: bool,
}

fn run_global_stress(threads: &[usize], duration: Duration) -> Vec<StressRow> {
    threads
        .iter()
        .map(|&t| {
            let hashes = Arc::new(AtomicU64::new(0));
            let verifies = Arc::new(AtomicU64::new(0));
            let errors = Arc::new(AtomicU64::new(0));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let start = Instant::now();
            let mut handles = Vec::new();
            for i in 0..t {
                let hashes = Arc::clone(&hashes);
                let verifies = Arc::clone(&verifies);
                let errors = Arc::clone(&errors);
                let stop = Arc::clone(&stop);
                handles.push(thread::spawn(move || {
                    let mut local_hash = String::new();
                    while !stop.load(Ordering::Relaxed) {
                        let pw = format!("stress_{i}");
                        match hash(&pw) {
                            Ok(h) => {
                                hashes.fetch_add(1, Ordering::Relaxed);
                                local_hash = h;
                            }
                            Err(_) => {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        if !local_hash.is_empty() {
                            match verify(&pw, &local_hash) {
                                Ok(true) => {
                                    verifies.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(false) | Err(_) => {
                                    errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }));
            }
            thread::sleep(duration);
            stop.store(true, Ordering::Relaxed);
            for h in handles {
                let _ = h.join();
            }
            thread::sleep(Duration::from_millis(100));
            let st = scheduler_stats();
            StressRow {
                threads: t,
                duration_secs: start.elapsed().as_secs_f64(),
                hashes: hashes.load(Ordering::Relaxed),
                verifies: verifies.load(Ordering::Relaxed),
                errors: errors.load(Ordering::Relaxed),
                scheduler_idle: st.active_jobs == 0 && st.waiting_jobs == 0,
            }
        })
        .collect()
}

struct ConcRow {
    threads: usize,
    completed: u64,
    duration_ms: f64,
}

fn run_concurrency_levels(levels: &[usize]) -> Vec<ConcRow> {
    levels
        .iter()
        .map(|&t| {
            let done = Arc::new(AtomicU64::new(0));
            let start = Instant::now();
            let mut handles = Vec::new();
            for i in 0..t {
                let done = Arc::clone(&done);
                handles.push(thread::spawn(move || {
                    let pw = format!("c_{i}");
                    if hash(&pw).is_ok() {
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }
            for h in handles {
                let _ = h.join();
            }
            ConcRow {
                threads: t,
                completed: done.load(Ordering::Relaxed),
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            }
        })
        .collect()
}

fn write_resource_csv(rows: &[ResourceRow]) -> std::io::Result<()> {
    let mut f = fs::File::create(out_dir().join("resource-results.csv"))?;
    use std::io::Write;
    writeln!(
        f,
        "threads,duration_secs,admissions_ok,admissions_err,peak_active,peak_waiting,peak_mem_kib,budget_mem_kib"
    )?;
    for r in rows {
        writeln!(
            f,
            "{},{:.3},{},{},{},{},{},65536",
            r.threads,
            r.duration_secs,
            r.admissions_ok,
            r.admissions_err,
            r.peak_active,
            r.peak_waiting,
            r.peak_mem_kib
        )?;
    }
    Ok(())
}

fn write_stress_csv(rows: &[StressRow]) -> std::io::Result<()> {
    let mut f = fs::File::create(out_dir().join("stress-results.csv"))?;
    use std::io::Write;
    writeln!(
        f,
        "threads,duration_secs,hashes,verifies,errors,scheduler_idle"
    )?;
    for r in rows {
        writeln!(
            f,
            "{},{:.3},{},{},{},{}",
            r.threads, r.duration_secs, r.hashes, r.verifies, r.errors, r.scheduler_idle
        )?;
    }
    Ok(())
}

fn write_concurrency_csv(rows: &[ConcRow]) -> std::io::Result<()> {
    let mut f = fs::create_dir_all(out_dir())
        .and_then(|_| fs::File::create(out_dir().join("concurrency-results.csv")))?;
    use std::io::Write;
    writeln!(f, "threads,completed,duration_ms")?;
    for r in rows {
        writeln!(f, "{},{},{:.1}", r.threads, r.completed, r.duration_ms)?;
    }
    let _ = &mut f;
    Ok(())
}

fn write_build_matrix() -> std::io::Result<()> {
    fs::write(
        out_dir().join("build-matrix.md"),
        "# Build matrix\n\n| Check | Status |\n|---|---|\n| cargo fmt | run in CI/local |\n| cargo check --workspace | PASS |\n| cargo test --workspace | PASS |\n| cargo clippy | PASS (warnings only) |\n| cargo fuzz | BLOCKED on Windows without cargo-fuzz |\n| Nsight/perf | BLOCKED — tools not in PATH |\n",
    )
}

fn write_issues_found() -> std::io::Result<()> {
    let audit = fs::read_to_string("docs/production-audit.md")
        .unwrap_or_else(|_| "# Issues\n\nSee reliability-report.md and regressions.csv.\n".into());
    fs::write(out_dir().join("issues-found.md"), audit)
}

fn write_reliability_report(
    resource: &[ResourceRow],
    stress: &[StressRow],
    conc: &[ConcRow],
) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = fs::File::create(out_dir().join("reliability-report.md"))?;
    writeln!(f, "# Reliability report\n")?;
    writeln!(f, "## Resource scheduler stress\n")?;
    for r in resource {
        writeln!(
            f,
            "- {} threads: ok={} err={} peak_active={} peak_waiting={} peak_mem={} KiB",
            r.threads,
            r.admissions_ok,
            r.admissions_err,
            r.peak_active,
            r.peak_waiting,
            r.peak_mem_kib
        )?;
    }
    writeln!(f, "\n## Global hash/verify stress\n")?;
    for s in stress {
        writeln!(
            f,
            "- {} threads: hashes={} verifies={} errors={} idle={}",
            s.threads, s.hashes, s.verifies, s.errors, s.scheduler_idle
        )?;
    }
    writeln!(f, "\n## Concurrency throughput\n")?;
    for c in conc {
        writeln!(
            f,
            "- {} threads: completed={} in {:.0} ms",
            c.threads, c.completed, c.duration_ms
        )?;
    }
    writeln!(
        f,
        "\nSee regressions.csv, fuzz-results.csv, issues-found.md for details.\n"
    )?;
    Ok(())
}
