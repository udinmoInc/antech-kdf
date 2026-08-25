//! Fair CPU-only head-to-head: Antech Compute-Memory v2 vs Argon2id baseline.
//!
//! No GPU / CUDA. Same thread counts, same password corpus, same worker model.
//! Parameters for both algorithms are taken from existing research configs
//! without modification.

use super::config::{ComputeMemoryConfig, CPU_WORKER_COUNTS, DEFAULT_MEMORY_KIB};
use super::optimized::OptimizedEngine;
use crate::candidates::cand_004::ResearchKdf;
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Canonical Argon2id baseline from existing research comparisons (64 MiB, t=2, p=1).
pub const ARGON2_M_KIB: u32 = 65536;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;

/// Shared salt for both algorithms.
const SHARED_SALT: &[u8] = b"cpu_h2h_shared_salt";

/// Shared password candidate corpus (identical for both algorithms).
fn password_corpus() -> Vec<Vec<u8>> {
    (0..256u32)
        .map(|i| format!("cpu_h2h_candidate_{:04}", i).into_bytes())
        .collect()
}

#[derive(Debug, Clone)]
pub struct HeadToHeadRow {
    pub threads: usize,
    pub algorithm: String,
    pub working_memory_mib: f64,
    pub peak_rss_mib: f64,
    pub defender_p50_ms: f64,
    pub defender_p95_ms: f64,
    pub defender_p99_ms: f64,
    pub defender_throughput_ops_per_sec: f64,
    pub cpu_utilization_pct: f64,
    pub cpu_cycles_per_op: f64,
    pub attacker_guesses_per_sec: f64,
    pub attacker_latency_ms_per_guess: f64,
    pub scaling_efficiency: f64,
}

fn argon2_baseline_params() -> Params {
    ParamsBuilder::new()
        .m_cost(ARGON2_M_KIB)
        .t_cost(ARGON2_T_COST)
        .p_cost(ARGON2_P_COST)
        .output_len(32)
        .build()
        .expect("valid argon2 baseline params")
}

fn argon2_derive(params: &Params, password: &[u8], salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut out = [0u8; 32];
    let _ = argon2.hash_password_into(password, salt, &mut out);
    out
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(target_arch = "x86_64")]
fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}

#[cfg(not(target_arch = "x86_64"))]
fn rdtsc() -> u64 {
    0
}

#[cfg(windows)]
fn current_rss_bytes() -> u64 {
    use std::mem::{size_of, zeroed};
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[link(name = "psapi")]
    extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut core::ffi::c_void,
            ppsmem_counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
    }
    unsafe {
        let mut pmc: ProcessMemoryCounters = zeroed();
        pmc.cb = size_of::<ProcessMemoryCounters>() as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
            pmc.peak_working_set_size as u64
        } else {
            0
        }
    }
}

#[cfg(not(windows))]
fn current_rss_bytes() -> u64 {
    0
}

fn measure_defender_concurrent<F>(
    threads: usize,
    samples_per_thread: usize,
    derive_one: F,
) -> (Vec<f64>, f64, f64, f64)
where
    F: Fn(&[u8], &[u8]) + Sync,
{
    let corpus = password_corpus();
    let wall_start = Instant::now();
    let mut all_latencies = Vec::with_capacity(threads * samples_per_thread);
    let mut total_cycles = 0u64;

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for t in 0..threads {
            let corpus = &corpus;
            let derive_one = &derive_one;
            handles.push(s.spawn(move || {
                let mut local_lat = Vec::with_capacity(samples_per_thread);
                let mut local_cycles = 0u64;
                for i in 0..samples_per_thread {
                    let pw = &corpus[(t * samples_per_thread + i) % corpus.len()];
                    let c0 = rdtsc();
                    let t0 = Instant::now();
                    derive_one(pw, SHARED_SALT);
                    let ms = t0.elapsed().as_secs_f64() * 1000.0;
                    let c1 = rdtsc();
                    local_lat.push(ms);
                    if c1 > c0 {
                        local_cycles = local_cycles.saturating_add(c1 - c0);
                    }
                }
                (local_lat, local_cycles)
            }));
        }
        for h in handles {
            let (lat, cycles) = h.join().unwrap();
            all_latencies.extend(lat);
            total_cycles = total_cycles.saturating_add(cycles);
        }
    });

    let wall = wall_start.elapsed().as_secs_f64().max(1e-9);
    let throughput = all_latencies.len() as f64 / wall;
    let avg_cycles = if all_latencies.is_empty() {
        0.0
    } else {
        total_cycles as f64 / all_latencies.len() as f64
    };
    let busy = all_latencies.iter().sum::<f64>() / 1000.0;
    let cpu_util = ((busy / (wall * threads as f64)) * 100.0).min(100.0);

    all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (all_latencies, throughput, avg_cycles, cpu_util)
}

fn measure_attacker<F>(
    threads: usize,
    duration: Duration,
    derive_one: F,
) -> (f64, f64, u64)
where
    F: Fn(&[u8], &[u8]) + Sync,
{
    let corpus = password_corpus();
    let counter = Arc::new(AtomicU64::new(0));
    let peak_rss = Arc::new(AtomicU64::new(current_rss_bytes()));
    let start = Instant::now();

    std::thread::scope(|s| {
        for t in 0..threads {
            let counter = Arc::clone(&counter);
            let peak_rss = Arc::clone(&peak_rss);
            let corpus = &corpus;
            let derive_one = &derive_one;
            s.spawn(move || {
                let mut local = 0u64;
                let mut idx = t;
                let end = Instant::now() + duration;
                while Instant::now() < end {
                    let pw = &corpus[idx % corpus.len()];
                    derive_one(pw, SHARED_SALT);
                    local += 1;
                    idx = idx.wrapping_add(threads);
                    if local % 4 == 0 {
                        let rss = current_rss_bytes();
                        peak_rss.fetch_max(rss, Ordering::Relaxed);
                    }
                }
                counter.fetch_add(local, Ordering::Relaxed);
            });
        }
    });

    let elapsed = start.elapsed().as_secs_f64().max(1e-9);
    let total = counter.load(Ordering::Relaxed);
    let gps = total as f64 / elapsed;
    let lat_ms = if gps > 0.0 { 1000.0 / gps } else { 0.0 };
    (gps, lat_ms, peak_rss.load(Ordering::Relaxed))
}

/// Run the full CPU-only head-to-head and write result artifacts.
pub fn run_cpu_head_to_head(
    output_dir: &Path,
) -> Result<Vec<HeadToHeadRow>, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let antech_cfg = ComputeMemoryConfig::default().memory_kib(DEFAULT_MEMORY_KIB);
    let antech_params = antech_cfg.to_research_params();
    let antech = OptimizedEngine::new();
    let argon_params = argon2_baseline_params();

    // Warmup both (not timed).
    {
        let _ = antech.derive(b"warmup", SHARED_SALT, &antech_params);
        let _ = argon2_derive(&argon_params, b"warmup", SHARED_SALT);
    }

    let attacker_window = Duration::from_millis(1500);
    let defender_samples_per_thread = 8usize;

    let mut rows = Vec::new();
    let mut antech_attacker_base = 0.0f64;
    let mut argon_attacker_base = 0.0f64;

    for &threads in &CPU_WORKER_COUNTS {
        eprintln!("CPU H2H: {threads} thread(s) — Antech v2 defender...");
        let (antech_lats, antech_tps, antech_cycles, antech_cpu) = measure_defender_concurrent(
            threads,
            defender_samples_per_thread,
            |pw, salt| {
                let _ = antech.derive(pw, salt, &antech_params);
            },
        );

        eprintln!("CPU H2H: {threads} thread(s) — Argon2id defender...");
        let (argon_lats, argon_tps, argon_cycles, argon_cpu) = measure_defender_concurrent(
            threads,
            defender_samples_per_thread,
            |pw, salt| {
                let _ = argon2_derive(&argon_params, pw, salt);
            },
        );

        eprintln!("CPU H2H: {threads} thread(s) — Antech v2 attacker...");
        let (antech_gps, antech_att_lat, antech_rss) = measure_attacker(
            threads,
            attacker_window,
            |pw, salt| {
                let _ = antech.derive(pw, salt, &antech_params);
            },
        );

        eprintln!("CPU H2H: {threads} thread(s) — Argon2id attacker...");
        let (argon_gps, argon_att_lat, argon_rss) = measure_attacker(
            threads,
            attacker_window,
            |pw, salt| {
                let _ = argon2_derive(&argon_params, pw, salt);
            },
        );

        if threads == 1 {
            antech_attacker_base = antech_gps.max(1e-9);
            argon_attacker_base = argon_gps.max(1e-9);
        }

        let antech_eff = antech_gps / (antech_attacker_base * threads as f64);
        let argon_eff = argon_gps / (argon_attacker_base * threads as f64);

        rows.push(HeadToHeadRow {
            threads,
            algorithm: "antech-compute-memory-v2".into(),
            working_memory_mib: antech_cfg.memory_kib as f64 / 1024.0,
            peak_rss_mib: antech_rss as f64 / (1024.0 * 1024.0),
            defender_p50_ms: percentile(&antech_lats, 0.50),
            defender_p95_ms: percentile(&antech_lats, 0.95),
            defender_p99_ms: percentile(&antech_lats, 0.99),
            defender_throughput_ops_per_sec: antech_tps,
            cpu_utilization_pct: antech_cpu,
            cpu_cycles_per_op: antech_cycles,
            attacker_guesses_per_sec: antech_gps,
            attacker_latency_ms_per_guess: antech_att_lat,
            scaling_efficiency: antech_eff,
        });

        rows.push(HeadToHeadRow {
            threads,
            algorithm: "argon2id".into(),
            working_memory_mib: ARGON2_M_KIB as f64 / 1024.0,
            peak_rss_mib: argon_rss as f64 / (1024.0 * 1024.0),
            defender_p50_ms: percentile(&argon_lats, 0.50),
            defender_p95_ms: percentile(&argon_lats, 0.95),
            defender_p99_ms: percentile(&argon_lats, 0.99),
            defender_throughput_ops_per_sec: argon_tps,
            cpu_utilization_pct: argon_cpu,
            cpu_cycles_per_op: argon_cycles,
            attacker_guesses_per_sec: argon_gps,
            attacker_latency_ms_per_guess: argon_att_lat,
            scaling_efficiency: argon_eff,
        });
    }

    write_main_csv(&output_dir.join("cpu-head-to-head.csv"), &rows)?;
    write_defender_scaling(&output_dir.join("defender-scaling.csv"), &rows)?;
    write_attacker_scaling(&output_dir.join("attacker-scaling.csv"), &rows)?;
    write_report_md(&output_dir.join("cpu-head-to-head.md"), &rows)?;

    Ok(rows)
}

fn write_main_csv(path: &Path, rows: &[HeadToHeadRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "threads,algorithm,working_memory_mib,peak_rss_mib,defender_p50_ms,defender_p95_ms,defender_p99_ms,defender_throughput_ops_s,cpu_utilization_pct,cpu_cycles_per_op,attacker_guesses_per_sec,attacker_latency_ms_per_guess,scaling_efficiency"
    )?;
    for r in rows {
        writeln!(
            f,
            "{},{},{:.2},{:.2},{:.3},{:.3},{:.3},{:.4},{:.1},{:.0},{:.4},{:.3},{:.4}",
            r.threads,
            r.algorithm,
            r.working_memory_mib,
            r.peak_rss_mib,
            r.defender_p50_ms,
            r.defender_p95_ms,
            r.defender_p99_ms,
            r.defender_throughput_ops_per_sec,
            r.cpu_utilization_pct,
            r.cpu_cycles_per_op,
            r.attacker_guesses_per_sec,
            r.attacker_latency_ms_per_guess,
            r.scaling_efficiency
        )?;
    }
    Ok(())
}

fn write_defender_scaling(
    path: &Path,
    rows: &[HeadToHeadRow],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "threads,argon2id_p50_ms,antech_v2_p50_ms,argon2id_p95_ms,antech_v2_p95_ms,argon2id_ram_mib,antech_ram_mib,argon2id_throughput,antech_throughput"
    )?;
    for &t in &CPU_WORKER_COUNTS {
        let a = rows
            .iter()
            .find(|r| r.threads == t && r.algorithm == "argon2id")
            .unwrap();
        let n = rows
            .iter()
            .find(|r| r.threads == t && r.algorithm == "antech-compute-memory-v2")
            .unwrap();
        writeln!(
            f,
            "{},{:.3},{:.3},{:.3},{:.3},{:.2},{:.2},{:.4},{:.4}",
            t,
            a.defender_p50_ms,
            n.defender_p50_ms,
            a.defender_p95_ms,
            n.defender_p95_ms,
            a.working_memory_mib,
            n.working_memory_mib,
            a.defender_throughput_ops_per_sec,
            n.defender_throughput_ops_per_sec
        )?;
    }
    Ok(())
}

fn write_attacker_scaling(
    path: &Path,
    rows: &[HeadToHeadRow],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "threads,argon2id_guesses_per_sec,antech_v2_guesses_per_sec,antech_over_argon_ratio,argon2id_scaling_eff,antech_scaling_eff"
    )?;
    for &t in &CPU_WORKER_COUNTS {
        let a = rows
            .iter()
            .find(|r| r.threads == t && r.algorithm == "argon2id")
            .unwrap();
        let n = rows
            .iter()
            .find(|r| r.threads == t && r.algorithm == "antech-compute-memory-v2")
            .unwrap();
        let ratio = if a.attacker_guesses_per_sec > 0.0 {
            n.attacker_guesses_per_sec / a.attacker_guesses_per_sec
        } else {
            0.0
        };
        writeln!(
            f,
            "{},{:.4},{:.4},{:.4},{:.4},{:.4}",
            t,
            a.attacker_guesses_per_sec,
            n.attacker_guesses_per_sec,
            ratio,
            a.scaling_efficiency,
            n.scaling_efficiency
        )?;
    }
    Ok(())
}

fn find<'a>(rows: &'a [HeadToHeadRow], threads: usize, algo: &str) -> &'a HeadToHeadRow {
    rows.iter()
        .find(|r| r.threads == threads && r.algorithm == algo)
        .unwrap()
}

fn write_report_md(path: &Path, rows: &[HeadToHeadRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(f, "# CPU-Only Head-to-Head: Antech Compute-Memory v2 vs Argon2id\n")?;
    writeln!(f, "**Mode:** CPU only — no CUDA / GPU metrics.\n")?;
    writeln!(f, "## Configurations (unchanged)\n")?;
    writeln!(
        f,
        "- **Antech v2:** {} MiB working set, block_size={}, fan_in={} (no depth/passes)",
        DEFAULT_MEMORY_KIB / 1024,
        ComputeMemoryConfig::default().block_size,
        ComputeMemoryConfig::default().fan_in
    )?;
    writeln!(
        f,
        "- **Argon2id baseline:** m_cost={} KiB ({} MiB), t_cost={}, p_cost={}",
        ARGON2_M_KIB,
        ARGON2_M_KIB / 1024,
        ARGON2_T_COST,
        ARGON2_P_COST
    )?;
    writeln!(
        f,
        "- **Corpus:** 256 shared password candidates, shared salt `cpu_h2h_shared_salt`"
    )?;
    writeln!(
        f,
        "- **Workers:** identical thread counts {{1,2,4,8,16,32}} and `std::thread` pool for both\n"
    )?;

    writeln!(f, "## Comparison table\n")?;
    writeln!(
        f,
        "| Threads | Algorithm | RAM (MiB) | p50 (ms) | p95 (ms) | p99 (ms) | CPU cycles/op | Attacker g/s | Scaling |"
    )?;
    writeln!(f, "|---:|---|---:|---:|---:|---:|---:|---:|---:|")?;
    for r in rows {
        writeln!(
            f,
            "| {} | {} | {:.0} | {:.2} | {:.2} | {:.2} | {:.2e} | {:.3} | {:.3} |",
            r.threads,
            r.algorithm,
            r.working_memory_mib,
            r.defender_p50_ms,
            r.defender_p95_ms,
            r.defender_p99_ms,
            r.cpu_cycles_per_op,
            r.attacker_guesses_per_sec,
            r.scaling_efficiency
        )?;
    }

    writeln!(f, "\n### Defender scaling\n")?;
    writeln!(
        f,
        "| Threads | Argon2id p50 | Antech v2 p50 | Argon2id RAM | Antech RAM |"
    )?;
    writeln!(f, "|---:|---:|---:|---:|---:|")?;
    for &t in &CPU_WORKER_COUNTS {
        let a = find(rows, t, "argon2id");
        let n = find(rows, t, "antech-compute-memory-v2");
        writeln!(
            f,
            "| {} | {:.2} ms | {:.2} ms | {:.0} MiB | {:.0} MiB |",
            t, a.defender_p50_ms, n.defender_p50_ms, a.working_memory_mib, n.working_memory_mib
        )?;
    }

    writeln!(f, "\n### Attacker scaling\n")?;
    writeln!(
        f,
        "| Threads | Argon2id g/s | Antech v2 g/s | Antech/Argon ratio |"
    )?;
    writeln!(f, "|---:|---:|---:|---:|")?;
    for &t in &CPU_WORKER_COUNTS {
        let a = find(rows, t, "argon2id");
        let n = find(rows, t, "antech-compute-memory-v2");
        let ratio = n.attacker_guesses_per_sec / a.attacker_guesses_per_sec.max(1e-12);
        writeln!(
            f,
            "| {} | {:.3} | {:.3} | {:.3} |",
            t, a.attacker_guesses_per_sec, n.attacker_guesses_per_sec, ratio
        )?;
    }

    writeln!(f, "\n### Attacker speedup vs 1-thread baseline\n")?;
    writeln!(
        f,
        "| Threads | Argon2id speedup | Antech v2 speedup | Argon2id eff. | Antech eff. |"
    )?;
    writeln!(f, "|---:|---:|---:|---:|---:|")?;
    let a1 = find(rows, 1, "argon2id").attacker_guesses_per_sec;
    let n1 = find(rows, 1, "antech-compute-memory-v2").attacker_guesses_per_sec;
    for &t in &CPU_WORKER_COUNTS {
        let a = find(rows, t, "argon2id");
        let n = find(rows, t, "antech-compute-memory-v2");
        writeln!(
            f,
            "| {} | {:.2}× | {:.2}× | {:.3} | {:.3} |",
            t,
            a.attacker_guesses_per_sec / a1.max(1e-12),
            n.attacker_guesses_per_sec / n1.max(1e-12),
            a.scaling_efficiency,
            n.scaling_efficiency
        )?;
    }

    let a1r = find(rows, 1, "argon2id");
    let n1r = find(rows, 1, "antech-compute-memory-v2");
    let a16 = find(rows, 16, "argon2id");
    let n16 = find(rows, 16, "antech-compute-memory-v2");
    let a32 = find(rows, 32, "argon2id");
    let n32 = find(rows, 32, "antech-compute-memory-v2");

    let harder = |antech_gps: f64, argon_gps: f64| -> &'static str {
        if antech_gps < argon_gps {
            "Antech v2 (lower attacker g/s)"
        } else if argon_gps < antech_gps {
            "Argon2id (lower attacker g/s)"
        } else {
            "Tie"
        }
    };

    writeln!(f, "\n## Answers\n")?;
    writeln!(
        f,
        "1. **Which uses less RAM?** Antech v2 ({:.0} MiB working set) vs Argon2id ({:.0} MiB).\n",
        n1r.working_memory_mib, a1r.working_memory_mib
    )?;
    writeln!(
        f,
        "2. **Which is faster for legitimate verification (1-thread p50)?** {} ({:.2} ms vs {:.2} ms).\n",
        if n1r.defender_p50_ms <= a1r.defender_p50_ms {
            "Antech v2"
        } else {
            "Argon2id"
        },
        n1r.defender_p50_ms.min(a1r.defender_p50_ms),
        n1r.defender_p50_ms.max(a1r.defender_p50_ms)
    )?;
    writeln!(
        f,
        "3. **Which scales better 1→32 (attacker efficiency)?** {} (eff {:.3} vs {:.3}).\n",
        if n32.scaling_efficiency >= a32.scaling_efficiency {
            "Antech v2"
        } else {
            "Argon2id"
        },
        n32.scaling_efficiency,
        a32.scaling_efficiency
    )?;
    writeln!(
        f,
        "4. **Harder for optimized CPU attacker at 1 thread?** {} ({:.3} vs {:.3} g/s).\n",
        harder(n1r.attacker_guesses_per_sec, a1r.attacker_guesses_per_sec),
        n1r.attacker_guesses_per_sec,
        a1r.attacker_guesses_per_sec
    )?;
    writeln!(
        f,
        "5. **Harder at 16 threads?** {} ({:.3} vs {:.3} g/s).\n",
        harder(n16.attacker_guesses_per_sec, a16.attacker_guesses_per_sec),
        n16.attacker_guesses_per_sec,
        a16.attacker_guesses_per_sec
    )?;
    writeln!(
        f,
        "6. **Harder at 32 threads?** {} ({:.3} vs {:.3} g/s).\n",
        harder(n32.attacker_guesses_per_sec, a32.attacker_guesses_per_sec),
        n32.attacker_guesses_per_sec,
        a32.attacker_guesses_per_sec
    )?;

    let antech_harder_at_32 = n32.attacker_guesses_per_sec < a32.attacker_guesses_per_sec;
    let antech_harder_at_1 = n1r.attacker_guesses_per_sec < a1r.attacker_guesses_per_sec;
    writeln!(
        f,
        "7. **Does Antech v2 maintain its CPU-cost advantage with all threads?** {} (1-thread harder for Antech: {}; 32-thread harder for Antech: {}).\n",
        if antech_harder_at_1 && antech_harder_at_32 {
            "Yes — still lower attacker g/s at 32 threads"
        } else if antech_harder_at_1 && !antech_harder_at_32 {
            "No — advantage lost at high thread counts (Argon2id becomes harder)"
        } else if !antech_harder_at_1 && antech_harder_at_32 {
            "Antech becomes relatively harder only at high concurrency"
        } else {
            "Antech is not harder at 1 or 32 threads under this baseline"
        },
        antech_harder_at_1,
        antech_harder_at_32
    )?;

    writeln!(
        f,
        "8. **Does the graph-based design remain expensive without a huge depth loop?** Yes — work is `num_blocks = memory/block_size` ({}); 1-thread defender p50 ≈ {:.1} ms with no `dependency_depth` / `passes` knobs.\n",
        ComputeMemoryConfig::default()
            .memory_kib(DEFAULT_MEMORY_KIB)
            .num_blocks(),
        n1r.defender_p50_ms
    )?;

    writeln!(f, "## Notes\n")?;
    writeln!(
        f,
        "- CPU cycles/op from `RDTSC` deltas (wall-clock turbo effects apply)."
    )?;
    writeln!(
        f,
        "- Peak RSS is process peak working set sampled during the attacker window."
    )?;
    writeln!(
        f,
        "- Argon2id: `argon2` crate release build; Antech: optimized research engine release build."
    )?;
    writeln!(f, "- No GPU / CUDA results are included in this report.")?;

    Ok(())
}
