//! Fair CPU-only head-to-head: canonical Antech (core) vs Argon2id baseline.
//!
//! No GPU / CUDA. Same thread counts, same password corpus, same worker model.

use super::config::{ComputeMemoryConfig, CPU_WORKER_COUNTS, DEFAULT_MEMORY_KIB};
use antech_kdf_core::AntechEngine;
use antech_kdf_types::AntechConfig;
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
    let mut b = ParamsBuilder::new();
    b.m_cost(ARGON2_M_KIB)
        .t_cost(ARGON2_T_COST)
        .p_cost(ARGON2_P_COST);
    let _ = b.output_len(32);
    b.build().unwrap()
}

fn argon2_derive(params: &Params, password: &[u8], salt: &[u8]) -> [u8; 32] {
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let mut out = [0u8; 32];
    a2.hash_password_into(password, salt, &mut out).unwrap();
    out
}

fn antech_derive(eng: &AntechEngine, cfg: &AntechConfig, password: &[u8], salt: &[u8]) -> Vec<u8> {
    eng.derive(password, salt, cfg).unwrap()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn measure_defender_concurrent(
    threads: usize,
    samples_per_thread: usize,
    f: &(dyn Fn(&[u8], &[u8]) + Sync),
) -> (Vec<f64>, f64, f64, f64) {
    let mut all = Vec::new();
    let start = Instant::now();
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for t in 0..threads {
            handles.push(s.spawn(move || {
                let mut local = Vec::with_capacity(samples_per_thread);
                for i in 0..samples_per_thread {
                    let pw = format!("def_{t}_{i}");
                    let t0 = Instant::now();
                    f(pw.as_bytes(), SHARED_SALT);
                    local.push(t0.elapsed().as_secs_f64() * 1000.0);
                }
                local
            }));
        }
        for h in handles {
            all.extend(h.join().unwrap());
        }
    });
    let elapsed = start.elapsed().as_secs_f64().max(1e-9);
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let tps = all.len() as f64 / elapsed;
    (all, tps, 0.0, 0.0)
}

fn measure_attacker(
    threads: usize,
    window: Duration,
    f: &(dyn Fn(&[u8], &[u8]) + Sync),
) -> (f64, f64, u64) {
    let corpus = password_corpus();
    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicU64::new(0));
    let peak_rss = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    std::thread::scope(|s| {
        for t in 0..threads {
            let counter = Arc::clone(&counter);
            let stop = Arc::clone(&stop);
            let corpus = &corpus;
            s.spawn(move || {
                let mut i = t;
                while stop.load(Ordering::Relaxed) == 0 {
                    let pw = &corpus[i % corpus.len()];
                    f(pw, SHARED_SALT);
                    counter.fetch_add(1, Ordering::Relaxed);
                    i += threads;
                }
            });
        }
        std::thread::sleep(window);
        stop.store(1, Ordering::Relaxed);
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

    let antech_cfg = ComputeMemoryConfig::default()
        .memory_kib(DEFAULT_MEMORY_KIB)
        .to_antech_config();
    let antech = AntechEngine::new();
    let argon_params = argon2_baseline_params();

    {
        let _ = antech_derive(&antech, &antech_cfg, b"warmup", SHARED_SALT);
        let _ = argon2_derive(&argon_params, b"warmup", SHARED_SALT);
    }

    let attacker_window = Duration::from_millis(1500);
    let defender_samples_per_thread = 8usize;

    let mut rows = Vec::new();
    let mut antech_attacker_base = 0.0f64;
    let mut argon_attacker_base = 0.0f64;

    for &threads in &CPU_WORKER_COUNTS {
        eprintln!("CPU H2H: {threads} thread(s) — Antech (core) defender...");
        let (antech_lats, antech_tps, antech_cycles, antech_cpu) =
            measure_defender_concurrent(threads, defender_samples_per_thread, &|pw, salt| {
                let _ = antech_derive(&antech, &antech_cfg, pw, salt);
            });

        eprintln!("CPU H2H: {threads} thread(s) — Argon2id defender...");
        let (argon_lats, argon_tps, argon_cycles, argon_cpu) =
            measure_defender_concurrent(threads, defender_samples_per_thread, &|pw, salt| {
                let _ = argon2_derive(&argon_params, pw, salt);
            });

        eprintln!("CPU H2H: {threads} thread(s) — Antech (core) attacker...");
        let (antech_gps, antech_att_lat, antech_rss) =
            measure_attacker(threads, attacker_window, &|pw, salt| {
                let _ = antech_derive(&antech, &antech_cfg, pw, salt);
            });

        eprintln!("CPU H2H: {threads} thread(s) — Argon2id attacker...");
        let (argon_gps, argon_att_lat, argon_rss) =
            measure_attacker(threads, attacker_window, &|pw, salt| {
                let _ = argon2_derive(&argon_params, pw, salt);
            });

        if threads == 1 {
            antech_attacker_base = antech_gps.max(1e-9);
            argon_attacker_base = argon_gps.max(1e-9);
        }

        let antech_eff = antech_gps / (antech_attacker_base * threads as f64);
        let argon_eff = argon_gps / (argon_attacker_base * threads as f64);

        rows.push(HeadToHeadRow {
            threads,
            algorithm: "antech-core-combined-frontier".into(),
            working_memory_mib: antech_cfg.memory.as_kib() as f64 / 1024.0,
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

    let csv_path = output_dir.join("cpu-head-to-head.csv");
    let mut csv = File::create(&csv_path)?;
    writeln!(
        csv,
        "threads,algorithm,working_memory_mib,peak_rss_mib,defender_p50_ms,defender_p95_ms,defender_p99_ms,defender_throughput_ops_per_sec,cpu_utilization_pct,cpu_cycles_per_op,attacker_guesses_per_sec,attacker_latency_ms_per_guess,scaling_efficiency"
    )?;
    for r in &rows {
        writeln!(
            csv,
            "{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.0},{:.3},{:.3},{:.3}",
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

    Ok(rows)
}
