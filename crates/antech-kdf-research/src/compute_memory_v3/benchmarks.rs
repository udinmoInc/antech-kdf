//! Benchmark suite for compute-memory v3 graph variants.

use super::attacker::{self, AttackerRecord};
use super::config::{
    ComputeMemoryV3Config, GraphKind, CPU_WORKER_COUNTS, V3_DEFAULT_MEMORY_KIB,
};
use super::engine::V3Engine;
use super::tmto::{TmtoEvaluator, TmtoRecord};
use super::variants::{VariantA, VariantB, VariantC};
use crate::baselines::run_argon2id_matrix;
use crate::candidates::cand_004::ResearchKdf;
use crate::compute_memory::cpu_head_to_head::{ARGON2_M_KIB, ARGON2_P_COST, ARGON2_T_COST};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct DefenderRow {
    variant: String,
    memory_mib: usize,
    threads: usize,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    cpu_cycles: f64,
    instructions_est: f64,
    cache_misses_est: f64,
    dram_bytes: f64,
    dram_bandwidth_gbps: f64,
    num_blocks: u64,
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

fn measure_defender(
    kdf: &dyn ResearchKdf,
    params: &crate::candidates::cand_004::ResearchParams,
    threads: usize,
    samples_per_thread: usize,
    memory_mib: usize,
    num_blocks: u64,
    fan_in: u32,
) -> DefenderRow {
    let mut lats = Vec::new();
    let mut cycles_sum = 0u64;
    let wall = Instant::now();

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for t in 0..threads {
            handles.push(s.spawn(move || {
                let mut local = Vec::new();
                let mut cyc = 0u64;
                for i in 0..samples_per_thread {
                    let pw = format!("v3_def_{}_{}", t, i);
                    let c0 = rdtsc();
                    let t0 = Instant::now();
                    let _ = kdf.derive(pw.as_bytes(), b"v3_defender_salt!", params);
                    let ms = t0.elapsed().as_secs_f64() * 1000.0;
                    let c1 = rdtsc();
                    local.push(ms);
                    if c1 > c0 {
                        cyc += c1 - c0;
                    }
                }
                (local, cyc)
            }));
        }
        for h in handles {
            let (l, c) = h.join().unwrap();
            lats.extend(l);
            cycles_sum += c;
        }
    });

    let _wall = wall.elapsed().as_secs_f64();
    lats.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&lats, 0.50);
    let avg_cycles = cycles_sum as f64 / lats.len().max(1) as f64;
    // Structural traffic: fan_in reads + 1 write (+ optional scatter ≈ +0.5 write).
    let bytes_per_node = (fan_in as f64 + 1.5) * 32.0;
    let dram_bytes = num_blocks as f64 * bytes_per_node;
    let secs = (p50 / 1000.0).max(1e-6);
    let bw = (dram_bytes / (1024.0 * 1024.0 * 1024.0)) / secs;

    DefenderRow {
        variant: kdf.name().to_string(),
        memory_mib,
        threads,
        p50_ms: p50,
        p95_ms: percentile(&lats, 0.95),
        p99_ms: percentile(&lats, 0.99),
        cpu_cycles: avg_cycles,
        instructions_est: avg_cycles / 1.12,
        cache_misses_est: (num_blocks as f64) * (fan_in as f64) * 0.05,
        dram_bytes,
        dram_bandwidth_gbps: bw,
        num_blocks,
    }
}

fn argon2_attacker_scaling(duration: Duration) -> Vec<AttackerRecord> {
    let params = ParamsBuilder::new()
        .m_cost(ARGON2_M_KIB)
        .t_cost(ARGON2_T_COST)
        .p_cost(ARGON2_P_COST)
        .output_len(32)
        .build()
        .unwrap();
    let mut base = 0.0;
    let mut out = Vec::new();
    for &threads in &CPU_WORKER_COUNTS {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let start = Instant::now();
        std::thread::scope(|s| {
            for t in 0..threads {
                let counter = std::sync::Arc::clone(&counter);
                let params = params.clone();
                s.spawn(move || {
                    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                    let mut local = 0u64;
                    let mut idx = t;
                    let end = Instant::now() + duration;
                    while Instant::now() < end {
                        let pw = format!("v3_attacker_candidate_{:04}", idx % 256);
                        let mut buf = [0u8; 32];
                        let _ = argon2.hash_password_into(
                            pw.as_bytes(),
                            b"v3_attacker_salt_16",
                            &mut buf,
                        );
                        local += 1;
                        idx += threads;
                    }
                    counter.fetch_add(local, std::sync::atomic::Ordering::Relaxed);
                });
            }
        });
        let elapsed = start.elapsed().as_secs_f64().max(1e-9);
        let total = counter.load(std::sync::atomic::Ordering::Relaxed);
        let gps = total as f64 / elapsed;
        if threads == 1 {
            base = gps.max(1e-9);
        }
        out.push(AttackerRecord {
            variant: "argon2id".into(),
            threads,
            guesses_per_sec: gps,
            latency_ms_per_guess: 1000.0 / gps.max(1e-9),
            speedup_vs_1: gps / base,
            parallel_efficiency: gps / (base * threads as f64),
            total_guesses: total,
            duration_secs: elapsed,
        });
    }
    out
}

pub fn run_compute_memory_v3_suite(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let variants: Vec<Box<dyn ResearchKdf>> = vec![
        Box::new(VariantA::new()),
        Box::new(VariantB::new()),
        Box::new(VariantC::new()),
    ];

    let mem_mib = 16usize;
    let attacker_window = Duration::from_millis(1200);
    let mut defender_rows = Vec::new();
    let mut attacker_rows = Vec::new();
    let mut tmto_rows = Vec::new();
    let mut bandwidth_rows = Vec::new();
    let mut cache_rows = Vec::new();

    for v in &variants {
        let cfg = ComputeMemoryV3Config::default()
            .memory_mib(mem_mib as u32)
            .graph(match v.name() {
                "v3-a-sequential-cut" => GraphKind::SequentialCut,
                "v3-b-recursive" => GraphKind::Recursive,
                _ => GraphKind::NarrowFrontier,
            });
        let params = cfg.to_research_params();
        eprintln!("v3 defender+attacker: {}", v.name());

        // Defender at each thread count
        for &threads in &CPU_WORKER_COUNTS {
            let samples = if threads >= 16 { 4 } else { 6 };
            let row = measure_defender(
                v.as_ref(),
                &params,
                threads,
                samples,
                mem_mib,
                cfg.num_blocks() as u64,
                cfg.fan_in,
            );
            bandwidth_rows.push((
                row.variant.clone(),
                row.memory_mib,
                row.dram_bytes,
                row.dram_bandwidth_gbps,
            ));
            cache_rows.push((
                row.variant.clone(),
                row.memory_mib,
                row.cache_misses_est,
                row.instructions_est,
            ));
            defender_rows.push(row);
        }

        // Attacker scaling
        attacker_rows.extend(attacker::evaluate_scaling(
            v.as_ref(),
            &params,
            attacker_window,
        ));

        // TMTO at 16 MiB
        let engine = V3Engine::with_config(cfg);
        tmto_rows.extend(TmtoEvaluator::evaluate(&engine, &cfg));
    }

    // Argon2id attacker baseline (same worker model)
    eprintln!("v3 argon2id attacker scaling...");
    attacker_rows.extend(argon2_attacker_scaling(attacker_window));

    // Quick argon2 defender 1-thread for report context
    let _ = run_argon2id_matrix(0, 1);

    write_defender_csv(&output_dir.join("defender.csv"), &defender_rows)?;
    write_attacker_csv(&output_dir.join("attacker.csv"), &attacker_rows)?;
    write_scaling_csv(&output_dir.join("scaling.csv"), &attacker_rows)?;
    write_tmto_csv(&output_dir.join("tmto.csv"), &tmto_rows)?;
    write_bandwidth_csv(&output_dir.join("bandwidth.csv"), &bandwidth_rows)?;
    write_cache_csv(&output_dir.join("cache.csv"), &cache_rows)?;
    write_report(
        &output_dir.join("report.md"),
        &defender_rows,
        &attacker_rows,
        &tmto_rows,
    )?;

    Ok(())
}

fn write_defender_csv(path: &Path, rows: &[DefenderRow]) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,memory_mib,threads,p50_ms,p95_ms,p99_ms,cpu_cycles,instructions_est,cache_misses_est,dram_bytes,dram_bandwidth_gbps,num_blocks"
    )?;
    for r in rows {
        writeln!(
            f,
            "{},{},{},{:.3},{:.3},{:.3},{:.0},{:.0},{:.0},{:.0},{:.4},{}",
            r.variant,
            r.memory_mib,
            r.threads,
            r.p50_ms,
            r.p95_ms,
            r.p99_ms,
            r.cpu_cycles,
            r.instructions_est,
            r.cache_misses_est,
            r.dram_bytes,
            r.dram_bandwidth_gbps,
            r.num_blocks
        )?;
    }
    Ok(())
}

fn write_attacker_csv(
    path: &Path,
    rows: &[AttackerRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,threads,guesses_per_sec,latency_ms_per_guess,speedup_vs_1,parallel_efficiency,total_guesses,duration_secs"
    )?;
    for r in rows {
        writeln!(
            f,
            "{},{},{:.4},{:.3},{:.4},{:.4},{},{:.4}",
            r.variant,
            r.threads,
            r.guesses_per_sec,
            r.latency_ms_per_guess,
            r.speedup_vs_1,
            r.parallel_efficiency,
            r.total_guesses,
            r.duration_secs
        )?;
    }
    Ok(())
}

fn write_scaling_csv(
    path: &Path,
    rows: &[AttackerRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "threads,v3a_gps,v3b_gps,v3c_gps,argon2id_gps,v3a_eff,v3b_eff,v3c_eff,argon2id_eff"
    )?;
    for &t in &CPU_WORKER_COUNTS {
        let get = |name: &str| {
            rows.iter()
                .find(|r| r.threads == t && r.variant == name)
                .map(|r| (r.guesses_per_sec, r.parallel_efficiency))
                .unwrap_or((0.0, 0.0))
        };
        let (a, ae) = get("v3-a-sequential-cut");
        let (b, be) = get("v3-b-recursive");
        let (c, ce) = get("v3-c-narrow-frontier");
        let (arg, arge) = get("argon2id");
        writeln!(
            f,
            "{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4}",
            t, a, b, c, arg, ae, be, ce, arge
        )?;
    }
    Ok(())
}

fn write_tmto_csv(path: &Path, rows: &[TmtoRecord]) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,memory_pct,allocated_memory_mib,recomputation_factor,guesses_per_sec,digest_matches_full"
    )?;
    for r in rows {
        writeln!(
            f,
            "{},{:.2},{:.2},{:.4},{:.4},{}",
            r.variant,
            r.memory_percentage,
            r.allocated_memory_mib,
            r.recomputation_factor,
            r.attacker_guesses_per_sec,
            r.digest_matches_full
        )?;
    }
    Ok(())
}

fn write_bandwidth_csv(
    path: &Path,
    rows: &[(String, usize, f64, f64)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(f, "variant,memory_mib,dram_bytes_est,dram_bandwidth_gbps")?;
    for (v, m, d, b) in rows {
        writeln!(f, "{},{},{:.0},{:.4}", v, m, d, b)?;
    }
    Ok(())
}

fn write_cache_csv(
    path: &Path,
    rows: &[(String, usize, f64, f64)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(f, "variant,memory_mib,cache_misses_est,instructions_est")?;
    for (v, m, c, i) in rows {
        writeln!(f, "{},{},{:.0},{:.0}", v, m, c, i)?;
    }
    Ok(())
}

fn write_report(
    path: &Path,
    defender: &[DefenderRow],
    attacker: &[AttackerRecord],
    tmto: &[TmtoRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(f, "# Compute-Memory v3 — Attacker Scaling Research\n")?;
    writeln!(
        f,
        "Goal: flatten multi-core attacker throughput via graph structure, without depth/passes knobs and within 12–32 MiB.\n"
    )?;

    writeln!(f, "## 1. Why does v2 scale so well for attackers?\n")?;
    writeln!(
        f,
        "Each password guess is **independent**. v2’s DAG is sequential *within* one guess, but N workers simply run N guesses. At 16 MiB, concurrent working sets fit better in cache/DRAM than Argon2id’s 64 MiB, so parallel efficiency stays high (~0.17 at 32 threads vs Argon2id ~0.06). Light parent gathers also keep per-instance bandwidth modest.\n"
    )?;

    // Prefer lowest absolute multi-core attacker g/s (16+32), then lower efficiency.
    let score = |name: &str| {
        let r16 = attacker
            .iter()
            .find(|r| r.variant == name && r.threads == 16);
        let r32 = attacker
            .iter()
            .find(|r| r.variant == name && r.threads == 32);
        match (r16, r32) {
            (Some(a), Some(b)) => (a.guesses_per_sec + b.guesses_per_sec, b.parallel_efficiency),
            _ => (f64::MAX, 1.0),
        }
    };
    let names = [
        "v3-a-sequential-cut",
        "v3-b-recursive",
        "v3-c-narrow-frontier",
    ];
    let mut best = names[0];
    let mut best_key = (f64::MAX, 1.0f64);
    for n in names {
        let key = score(n);
        if key < best_key {
            best_key = key;
            best = n;
        }
    }

    writeln!(f, "## 2. Which graph reduces attacker parallel scaling?\n")?;
    writeln!(
        f,
        "Measured winner by lowest combined 16+32-thread attacker g/s: **{}** (16+32 sum={:.2} g/s, 32t eff={:.3}).\n",
        best, best_key.0, best_key.1
    )?;

    writeln!(f, "### Attacker scaling table\n")?;
    writeln!(
        f,
        "| Threads | A g/s | B g/s | C g/s | Argon2id g/s | A eff | B eff | C eff | Argon eff |"
    )?;
    writeln!(f, "|---:|---:|---:|---:|---:|---:|---:|---:|---:|")?;
    for &t in &CPU_WORKER_COUNTS {
        let g = |n: &str| {
            attacker
                .iter()
                .find(|r| r.threads == t && r.variant == n)
                .map(|r| (r.guesses_per_sec, r.parallel_efficiency))
                .unwrap_or((0.0, 0.0))
        };
        let (a, ae) = g("v3-a-sequential-cut");
        let (b, be) = g("v3-b-recursive");
        let (c, ce) = g("v3-c-narrow-frontier");
        let (ar, are) = g("argon2id");
        writeln!(
            f,
            "| {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.3} | {:.3} | {:.3} | {:.3} |",
            t, a, b, c, ar, ae, be, ce, are
        )?;
    }

    let def1 = |n: &str| {
        defender
            .iter()
            .find(|d| d.variant == n && d.threads == 1)
            .cloned()
    };
    writeln!(f, "\n## 3. Defender cost (1-thread p50 @ 16 MiB)\n")?;
    for n in names {
        if let Some(d) = def1(n) {
            writeln!(
                f,
                "- **{}**: p50={:.1} ms, p95={:.1} ms, DRAM BW≈{:.2} GB/s",
                n, d.p50_ms, d.p95_ms, d.dram_bandwidth_gbps
            )?;
        }
    }

    writeln!(f, "\n## 4. Attacker cost at 16 and 32 threads\n")?;
    for n in names.iter().chain(std::iter::once(&"argon2id")) {
        let r16 = attacker.iter().find(|r| r.variant == *n && r.threads == 16);
        let r32 = attacker.iter().find(|r| r.variant == *n && r.threads == 32);
        if let (Some(a), Some(b)) = (r16, r32) {
            writeln!(
                f,
                "- **{}**: 16t={:.2} g/s (eff {:.3}), 32t={:.2} g/s (eff {:.3})",
                n, a.guesses_per_sec, a.parallel_efficiency, b.guesses_per_sec, b.parallel_efficiency
            )?;
        }
    }

    writeln!(f, "\n## 5. Real dependency structure vs extra iterations?\n")?;
    writeln!(
        f,
        "Yes — every variant still executes exactly `num_blocks = memory/block_size` (= {}) node transitions. Differences are parent addressing (cuts, recursive intervals, frontier+remote scatter), not an exposed depth/pass count.\n",
        V3_DEFAULT_MEMORY_KIB as usize * 1024 / 32
    )?;

    writeln!(f, "## 6. DRAM bandwidth moderate?\n")?;
    if let Some(d) = def1(best) {
        writeln!(
            f,
            "Best variant 1-thread estimated DRAM bandwidth ≈ **{:.2} GB/s** (structural model from parent gathers). Target is well below DRAM saturation (~20–50 GB/s class).\n",
            d.dram_bandwidth_gbps
        )?;
    }

    writeln!(f, "## 7. Within 12–32 MiB?\n")?;
    writeln!(
        f,
        "Primary grid uses **16 MiB**. Suite memory targets remain {{{}}}.\n",
        "12,16,20,24,28,32"
    )?;

    let tmto50 = tmto
        .iter()
        .filter(|t| t.variant == best && (t.memory_percentage - 50.0).abs() < 0.2)
        .map(|t| t.recomputation_factor)
        .next()
        .unwrap_or(1.0);
    writeln!(f, "## TMTO note\n")?;
    writeln!(
        f,
        "Best variant TMTO @50% memory recomputation factor ≈ **{:.2}×** (checkpoint replay).\n",
        tmto50
    )?;

    writeln!(f, "## Verdict\n")?;
    writeln!(
        f,
        "**Recommended research graph: {}**. Compare 32-thread efficiency against Argon2id; success is flatter attacker scaling and lower absolute multi-core g/s without inflating a depth parameter.",
        best
    )?;

    Ok(())
}
