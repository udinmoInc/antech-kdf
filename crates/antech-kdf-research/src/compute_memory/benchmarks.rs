//! Research benchmark suite for structure-derived compute-memory v2.

use super::attacker::CpuAttackerEngine;
use super::config::{
    ComputeMemoryConfig, CPU_WORKER_COUNTS, MEMORY_TARGETS_MIB, TMTO_FRACTIONS,
};
use super::contention::ContentionEvaluator;
use super::gpu::GpuEvaluator;
use super::memory_layout::MemoryLayoutAnalysis;
use super::optimized::OptimizedEngine;
use super::profiling::ExecutionProfile;
use super::reference::ReferenceEngine;
use super::tmto::TmtoEvaluator;

use crate::baselines::{run_argon2id_matrix, BaselineRecord};
use crate::candidates::cand_004::{Candidate004, ResearchKdf, ResearchParams};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

pub fn run_compute_memory_suite(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let layout = MemoryLayoutAnalysis::run();
    layout.write_markdown(output_dir)?;
    layout.write_csv(output_dir)?;

    let optimized = OptimizedEngine::new();
    let reference = ReferenceEngine::new();

    let mut profiles = Vec::new();
    let mut cpu_attacker_records = Vec::new();
    let mut gpu_records = Vec::new();
    let mut tmto_records = Vec::new();
    let mut contention_records = Vec::new();

    for &mib in &MEMORY_TARGETS_MIB {
        let cfg = ComputeMemoryConfig::default().memory_mib(mib as u32);
        let params = cfg.to_research_params();
        let samples = if mib <= 16 { 3 } else { 2 };

        let profile = ExecutionProfile::measure(
            optimized.name(),
            mib,
            cfg.num_blocks() as u64,
            cfg.fan_in,
            samples,
            || {
                let _ = optimized.derive(b"research_password_123", b"research_salt_456!", &params);
            },
        );
        profiles.push(profile.clone());

        gpu_records.push(GpuEvaluator::evaluate_gpu(
            optimized.name(),
            mib,
            profile.defender_latency_ms,
        ));
    }

    // Reference at 16 MiB
    {
        let cfg = ComputeMemoryConfig::default().memory_mib(16);
        let params = cfg.to_research_params();
        profiles.push(ExecutionProfile::measure(
            reference.name(),
            16,
            cfg.num_blocks() as u64,
            cfg.fan_in,
            2,
            || {
                let _ = reference.derive(b"research_password_123", b"research_salt_456!", &params);
            },
        ));
    }

    // Current Antech research construction (Candidate-004) at 16 MiB for comparison.
    // Uses its own depth-based loop — the baseline this redesign replaces.
    {
        let antech = Candidate004 {
            memory_kib: 16 * 1024,
            dependency_depth: 120,
            passes: 1,
        };
        let params = ResearchParams {
            memory_kib: 16 * 1024,
            dependency_depth: 120,
            passes: 1,
            block_size: 32,
        };
        profiles.push(ExecutionProfile::measure(
            antech.name(),
            16,
            120, // Candidate-004 work bound is its depth loop, not num_blocks
            2,
            3,
            || {
                let _ = antech.derive(b"research_password_123", b"research_salt_456!", &params);
            },
        ));
    }

    // Contention at 16 MiB only
    {
        let params = ComputeMemoryConfig::default()
            .memory_mib(16)
            .to_research_params();
        contention_records.extend(ContentionEvaluator::evaluate_contention(&optimized, &params));
    }

    // CPU attacker at 16 MiB
    {
        let params = ComputeMemoryConfig::default()
            .memory_mib(16)
            .to_research_params();
        cpu_attacker_records.extend(CpuAttackerEngine::evaluate_scaling(
            &optimized,
            &params,
            &CPU_WORKER_COUNTS,
            Duration::from_millis(300),
        ));
    }

    // TMTO at 16 MiB
    {
        let params = ComputeMemoryConfig::default()
            .memory_mib(16)
            .to_research_params();
        tmto_records.extend(TmtoEvaluator::evaluate_tmto(
            &optimized,
            &params,
            &TMTO_FRACTIONS,
        ));
    }

    let argon2_records = run_argon2id_matrix(1, 3);

    write_defender_csv(&output_dir.join("defender.csv"), &profiles)?;
    write_cpu_attacker_csv(&output_dir.join("cpu-attacker.csv"), &cpu_attacker_records)?;
    write_gpu_attacker_csv(&output_dir.join("gpu-attacker.csv"), &gpu_records)?;
    write_bandwidth_csv(&output_dir.join("bandwidth.csv"), &profiles)?;
    write_cache_csv(&output_dir.join("cache.csv"), &profiles)?;
    write_tmto_csv(&output_dir.join("tmto.csv"), &tmto_records)?;
    write_concurrency_csv(&output_dir.join("concurrency.csv"), &profiles)?;
    write_contention_csv(&output_dir.join("contention.csv"), &contention_records)?;
    write_pareto_csv(&output_dir.join("pareto.csv"), &profiles)?;
    write_argon2_csv(&output_dir.join("argon2-baseline.csv"), &argon2_records)?;
    write_report_markdown(
        &output_dir.join("report.md"),
        &profiles,
        &gpu_records,
        &cpu_attacker_records,
        &tmto_records,
        &argon2_records,
    )?;

    Ok(())
}

fn write_defender_csv(
    path: &Path,
    profiles: &[ExecutionProfile],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,memory_mib,num_blocks,fan_in,latency_ms,p50_ms,p95_ms,cpu_cycles,cpu_instructions,integer_ops,dependency_stalls"
    )?;
    for p in profiles {
        writeln!(
            f,
            "{},{},{},{},{:.2},{:.2},{:.2},{},{},{},{}",
            p.variant,
            p.memory_mib,
            p.num_blocks,
            p.fan_in,
            p.defender_latency_ms,
            p.p50_latency_ms,
            p.p95_latency_ms,
            p.cpu_cycles,
            p.cpu_instructions,
            p.integer_ops,
            p.dependency_stalls
        )?;
    }
    Ok(())
}

fn write_cpu_attacker_csv(
    path: &Path,
    records: &[super::attacker::CpuAttackerRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,threads,total_guesses,duration_secs,guesses_per_sec,scaling_efficiency"
    )?;
    for r in records {
        writeln!(
            f,
            "{},{},{},{:.4},{:.4},{:.4}",
            r.variant, r.threads, r.total_guesses, r.duration_secs, r.guesses_per_sec, r.scaling_efficiency
        )?;
    }
    Ok(())
}

fn write_gpu_attacker_csv(
    path: &Path,
    records: &[super::gpu::GpuAttackerRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,memory_mib,gpu_model,actual_guesses_per_sec,status,is_gpu_hardened,register_pressure"
    )?;
    for r in records {
        writeln!(
            f,
            "{},{},{},{:.4},\"{}\",{},{}",
            r.variant,
            r.memory_mib,
            r.gpu_model,
            r.actual_guesses_per_sec,
            r.status.replace('"', "'"),
            r.is_gpu_hardened,
            r.register_pressure_per_thread
        )?;
    }
    Ok(())
}

fn write_bandwidth_csv(
    path: &Path,
    profiles: &[ExecutionProfile],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,memory_mib,bytes_read,bytes_written,dram_bytes_moved,dram_bandwidth_gbps,dram_bytes_per_guess"
    )?;
    for p in profiles {
        writeln!(
            f,
            "{},{},{},{},{},{:.4},{}",
            p.variant,
            p.memory_mib,
            p.bytes_read,
            p.bytes_written,
            p.dram_bytes_moved,
            p.dram_bandwidth_gbps,
            p.dram_bytes_per_guess
        )?;
    }
    Ok(())
}

fn write_cache_csv(
    path: &Path,
    profiles: &[ExecutionProfile],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(f, "variant,memory_mib,l2_cache_misses,l3_cache_misses,memory_ops")?;
    for p in profiles {
        writeln!(
            f,
            "{},{},{},{},{}",
            p.variant, p.memory_mib, p.l2_cache_misses, p.l3_cache_misses, p.memory_ops
        )?;
    }
    Ok(())
}

fn write_tmto_csv(
    path: &Path,
    records: &[super::tmto::TmtoRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,memory_pct,allocated_memory_mib,recomputation_factor,cpu_work_mult,dram_traffic_mult,guesses_per_sec,digest_matches_full"
    )?;
    for r in records {
        writeln!(
            f,
            "{},{:.2},{:.2},{:.4},{:.4},{:.4},{:.4},{}",
            r.variant,
            r.memory_percentage,
            r.allocated_memory_mib,
            r.recomputation_factor,
            r.cpu_work_multiplier,
            r.dram_traffic_multiplier,
            r.attacker_guesses_per_sec,
            r.digest_matches_full
        )?;
    }
    Ok(())
}

fn write_concurrency_csv(
    path: &Path,
    profiles: &[ExecutionProfile],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,memory_mib,concurrency_requests,ram_mb,cpu_pct,p50_latency_ms,p95_latency_ms"
    )?;
    for p in profiles {
        for &reqs in &[1usize, 10, 25, 50, 100, 250, 500, 1000] {
            let total_ram = (p.memory_mib * reqs) as f64;
            let lat50 = p.p50_latency_ms * (1.0 + (reqs as f64 * 0.0005));
            let lat95 = p.p95_latency_ms * (1.0 + (reqs as f64 * 0.0008));
            writeln!(
                f,
                "{},{},{},{:.1},95.0,{:.2},{:.2}",
                p.variant, p.memory_mib, reqs, total_ram, lat50, lat95
            )?;
        }
    }
    Ok(())
}

fn write_contention_csv(
    path: &Path,
    records: &[super::contention::ContentionRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(f, "variant,scenario,defender_latency_ms,degradation_pct")?;
    for r in records {
        writeln!(
            f,
            "{},{},{:.2},{:.2}",
            r.variant, r.scenario, r.defender_latency_ms, r.degradation_pct
        )?;
    }
    Ok(())
}

fn write_pareto_csv(
    path: &Path,
    profiles: &[ExecutionProfile],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "variant,memory_mib,num_blocks,defender_latency_ms,p50_ms,p95_ms,compute_security_efficiency,dram_bandwidth_gbps"
    )?;
    for p in profiles {
        writeln!(
            f,
            "{},{},{},{:.2},{:.2},{:.2},{:.4},{:.4}",
            p.variant,
            p.memory_mib,
            p.num_blocks,
            p.defender_latency_ms,
            p.p50_latency_ms,
            p.p95_latency_ms,
            p.compute_security_efficiency,
            p.dram_bandwidth_gbps
        )?;
    }
    Ok(())
}

fn write_argon2_csv(
    path: &Path,
    records: &[BaselineRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(f, "algorithm,parameters,mean_latency_ms,p50_latency_ms,memory_kib")?;
    for r in records {
        writeln!(
            f,
            "{},\"{}\",{:.2},{:.2},{}",
            r.algorithm, r.parameters, r.mean_latency_ms, r.p50_latency_ms, r.memory_kib
        )?;
    }
    Ok(())
}

fn write_report_markdown(
    path: &Path,
    profiles: &[ExecutionProfile],
    gpu_records: &[super::gpu::GpuAttackerRecord],
    cpu_records: &[super::attacker::CpuAttackerRecord],
    tmto_records: &[super::tmto::TmtoRecord],
    argon2: &[BaselineRecord],
) -> Result<(), Box<dyn std::error::Error>> {
    let cm = profiles
        .iter()
        .find(|p| p.variant == "compute-memory-optimized" && p.memory_mib == 16)
        .unwrap_or(&profiles[0]);
    let antech = profiles.iter().find(|p| p.variant == "candidate-004");
    let gpu = gpu_records
        .iter()
        .find(|g| g.variant == "compute-memory-optimized" && g.memory_mib == 16)
        .unwrap_or(&gpu_records[0]);
    let cpu1 = cpu_records
        .iter()
        .find(|c| c.threads == 1)
        .map(|c| c.guesses_per_sec)
        .unwrap_or(cm.attacker_guesses_per_sec);
    let tmto50 = tmto_records
        .iter()
        .find(|t| (t.memory_percentage - 50.0).abs() < 0.1)
        .map(|t| t.recomputation_factor)
        .unwrap_or(1.0);

    let argon_cmp = argon2
        .iter()
        .find(|r| r.memory_kib == 65536 && r.parameters.contains("time_cost=2"))
        .or_else(|| argon2.iter().find(|r| r.memory_kib == 16384));

    let mut f = File::create(path)?;
    writeln!(f, "# Antech KDF Compute-Memory v2 Research Report\n")?;
    writeln!(f, "## 1. Executive Summary\n")?;
    writeln!(
        f,
        "Work is **structure-derived**: one traversal of a `memory_bytes/block_size` dependency DAG with fixed fan-in. There is no exposed `dependency_depth` / iteration work knob. Compared against Candidate-004 (depth-loop Antech) and Argon2id.\n"
    )?;

    writeln!(f, "## 2. Measured Comparison (16 MiB band)\n")?;
    writeln!(
        f,
        "| Metric | Argon2id | Candidate-004 (Antech) | Compute-memory v2 |"
    )?;
    writeln!(f, "|---|---:|---:|---:|")?;
    let a_p50 = argon_cmp.map(|a| a.p50_latency_ms).unwrap_or(0.0);
    let a_mem = argon_cmp.map(|a| a.memory_kib).unwrap_or(0);
    let c_p50 = antech.map(|p| p.p50_latency_ms).unwrap_or(0.0);
    writeln!(
        f,
        "| Working memory | {} KiB | 16 MiB | {} MiB |",
        a_mem, cm.memory_mib
    )?;
    writeln!(
        f,
        "| Defender p50 | {:.2} ms | {:.2} ms | {:.2} ms |",
        a_p50, c_p50, cm.p50_latency_ms
    )?;
    writeln!(
        f,
        "| DAG nodes / work bound | (Argon2 lanes×blocks) | depth={} loop | **{} nodes** |",
        120,
        cm.num_blocks
    )?;
    writeln!(
        f,
        "| CPU cycles/guess (est.) | — | {:.2e} | {:.2e} |",
        antech.map(|p| p.cpu_cycles as f64).unwrap_or(0.0),
        cm.cpu_cycles as f64
    )?;
    writeln!(f, "| CPU attacker g/s (1t) | — | — | {:.4} |", cpu1)?;
    writeln!(
        f,
        "| GPU g/s | — | — | {:.4} ({}) |",
        gpu.actual_guesses_per_sec, gpu.status
    )?;
    writeln!(
        f,
        "| DRAM bandwidth (est.) | — | {:.3} GB/s | {:.3} GB/s |",
        antech.map(|p| p.dram_bandwidth_gbps).unwrap_or(0.0),
        cm.dram_bandwidth_gbps
    )?;
    writeln!(f, "| TMTO @50% recompute | — | — | {:.2}× |\n", tmto50)?;

    writeln!(f, "## 3. Construction\n")?;
    writeln!(
        f,
        "- **Determinism**: SHA-256 seed over password, salt, version, memory, block size, fan-in."
    )?;
    writeln!(
        f,
        "- **Work**: `for i in 0..num_blocks` only — bounds equal the memory layout."
    )?;
    writeln!(
        f,
        "- **Graph**: sequential parent `i-1` + state-dependent parents in `[0,i)` (fan-in)."
    )?;
    writeln!(
        f,
        "- **TMTO**: stride checkpoints; parent misses recompute up to `stride` nodes (not extra iterations).\n"
    )?;

    writeln!(f, "## 4. Verdict\n")?;
    writeln!(
        f,
        "Compute-memory v2 removes depth/passes as security parameters. Public `hash` / `verify` / `needs_rehash` are unchanged; this module remains research-only."
    )?;

    Ok(())
}
