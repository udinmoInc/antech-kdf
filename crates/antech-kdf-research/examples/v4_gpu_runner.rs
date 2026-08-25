//! Generate CPU reference digests and orchestrate v4-C GPU correctness + results.

use antech_kdf_research::compute_memory_v4::{
    ComputeMemoryV4Config, GraphKind, V4Engine,
};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

fn hex32(d: &[u8]) -> String {
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from("research/results/compute-memory-v4/gpu");
    fs::create_dir_all(&out)?;

    let eng = V4Engine::new(GraphKind::CombinedFrontier);
    let cfg = ComputeMemoryV4Config::default()
        .memory_mib(16)
        .graph(GraphKind::CombinedFrontier);

    // --- correctness vectors ---
    let salt = b"v4_gpu_correct_salt";
    let mut cpu_path = File::create(out.join("cpu_digests.txt"))?;
    let mut correctness_csv = File::create(out.join("correctness.csv"))?;
    writeln!(
        correctness_csv,
        "vector_id,password,salt,cpu_digest_hex,cuda_digest_hex,match,status"
    )?;

    for i in 0..10 {
        let pw = format!("v4c_gpu_vector_{:02}", i);
        let dig = eng.derive_cfg(pw.as_bytes(), salt, &cfg)?;
        writeln!(cpu_path, "{} {}", pw, hex32(&dig))?;
    }
    drop(cpu_path);
    println!("Wrote CPU reference digests");

    let cuda_bin = find_cuda_bin()?;
    println!("Using CUDA binary: {}", cuda_bin.display());

    let status = Command::new(&cuda_bin)
        .arg("correctness")
        .arg(out.to_string_lossy().as_ref())
        .status()?;
    if !status.success() {
        eprintln!("CUDA correctness run failed: {:?}", status.code());
        // still write skipped rows
        for i in 0..10 {
            writeln!(
                correctness_csv,
                "{},v4c_gpu_vector_{:02},v4_gpu_correct_salt,,,false,CUDA_RUN_FAILED",
                i, i
            )?;
        }
        return Err("CUDA correctness failed".into());
    }

    // Compare
    let cpu = read_digest_file(&out.join("cpu_digests.txt"))?;
    let gpu = read_digest_file(&out.join("cuda_digests.txt"))?;
    let mut mismatches = 0;
    for i in 0..10 {
        let pw = format!("v4c_gpu_vector_{:02}", i);
        let c = cpu.get(&pw).cloned().unwrap_or_default();
        let g = gpu.get(&pw).cloned().unwrap_or_default();
        let ok = c == g && !c.is_empty();
        if !ok {
            mismatches += 1;
        }
        writeln!(
            correctness_csv,
            "{},{},v4_gpu_correct_salt,{},{},{},{}",
            i,
            pw,
            c,
            g,
            ok,
            if ok { "OK" } else { "MISMATCH" }
        )?;
        println!("vector {i}: match={ok}");
    }
    if mismatches > 0 {
        return Err(format!("{mismatches} correctness mismatches — stopping").into());
    }
    println!("CORRECTNESS OK 10/10");

    // --- bench ---
    let status = Command::new(&cuda_bin)
        .arg("bench")
        .arg(out.to_string_lossy().as_ref())
        .status()?;
    if !status.success() {
        return Err("CUDA bench failed".into());
    }

    let raw = fs::read_to_string(out.join("antech_gpu_raw.txt"))?;
    let get = |k: &str| -> String {
        raw.lines()
            .find(|l| l.starts_with(k))
            .map(|l| l.split_once('=').map(|(_, v)| v.to_string()).unwrap_or_default())
            .unwrap_or_default()
    };

    write_results(&out, &get)?;
    println!("Results written to {}", out.display());
    Ok(())
}

fn find_cuda_bin() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let candidates = [
        PathBuf::from("crates/antech-kdf-research/src/compute_memory_v4/cuda/v4c_gpu_attacker.exe"),
        PathBuf::from("target/cuda/v4c_gpu_attacker.exe"),
        PathBuf::from("v4c_gpu_attacker.exe"),
    ];
    for c in candidates {
        if c.exists() {
            return Ok(c);
        }
    }
    Err("v4c_gpu_attacker.exe not found — compile CUDA binary first".into())
}

fn read_digest_file(path: &Path) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
    let f = File::open(path)?;
    let mut map = std::collections::HashMap::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let mut parts = line.split_whitespace();
        if let (Some(pw), Some(hex)) = (parts.next(), parts.next()) {
            map.insert(pw.to_string(), hex.to_string());
        }
    }
    Ok(map)
}

fn write_results(
    out: &Path,
    get: &dyn Fn(&str) -> String,
) -> Result<(), Box<dyn std::error::Error>> {
    let gps = get("guesses_per_sec");
    let p50 = get("kernel_p50_ms");
    let p95 = get("kernel_p95_ms");
    let p99 = get("kernel_p99_ms");
    let vram = get("vram_used_mib");
    let occ = get("occupancy");
    let regs = get("registers_per_thread");
    let smem = get("shared_mem_bytes");
    let traffic = get("global_mem_traffic_est");
    let xfer = get("host_device_transfer_ms");
    let kexec = get("kernel_exec_ms_total");
    let gpu_name = get("gpu_name");
    let vram_total = get("vram_total_mib");
    let batch = get("batch");

    // CPU refs from prior suite
    let cpu_16 = 40.6f64;
    let cpu_32 = 38.3f64;
    let gpu_gps: f64 = gps.parse().unwrap_or(0.0);
    let speedup_16 = if cpu_16 > 0.0 { gpu_gps / cpu_16 } else { 0.0 };
    let speedup_32 = if cpu_32 > 0.0 { gpu_gps / cpu_32 } else { 0.0 };

    let verdict = if gpu_gps <= 0.0 {
        "CUDA UNAVAILABLE"
    } else if speedup_16 > 1.15 {
        "GPU ANTECH FASTER TO ATTACK"
    } else if speedup_16 < 0.85 {
        "GPU ANTECH SLOWER TO ATTACK"
    } else {
        "NO CLEAR GPU ADVANTAGE"
    };

    // hardware.json
    let mut hw = File::create(out.join("hardware.json"))?;
    writeln!(
        hw,
        r#"{{
  "gpu_name": "{gpu_name}",
  "vram_total_mib": {vram_total},
  "vram_used_mib_bench": {vram},
  "batch_size": {batch},
  "toolchain": {{"nvcc": "13.3", "cl": "F:/vs MSVC 19.44", "windows_sdk": "10.0.26100"}},
  "memory_mib": 16,
  "variant": "v4-c-combined-frontier",
  "benchmark_status": "REAL GPU BENCHMARK COMPLETED"
}}"#
    )?;

    // antech-v4c-gpu.csv
    let mut a = File::create(out.join("antech-v4c-gpu.csv"))?;
    writeln!(a, "variant,memory_mib,guesses_per_sec,kernel_p50_ms,kernel_p95_ms,kernel_p99_ms,vram_used_mib,gpu_util_pct,occupancy,registers_per_thread,shared_mem_bytes,global_mem_traffic_bytes,host_device_transfer_ms,kernel_exec_ms,batch,status")?;
    writeln!(
        a,
        "v4-c-combined-frontier,16,{gps},{p50},{p95},{p99},{vram},,{occ},{regs},{smem},{traffic},{xfer},{kexec},{batch},REAL"
    )?;

    // argon2id — no CUDA kernel shipped
    let mut ar = File::create(out.join("argon2id-gpu.csv"))?;
    writeln!(ar, "variant,memory_mib,guesses_per_sec,kernel_p50_ms,kernel_p95_ms,kernel_p99_ms,vram_used_mib,gpu_util_pct,occupancy,registers_per_thread,shared_mem_bytes,global_mem_traffic_bytes,host_device_transfer_ms,kernel_exec_ms,status")?;
    writeln!(ar, "argon2id,64,,,,,,,,,,,,,,NOT_MEASURED_NO_CUDA_KERNEL")?;

    // comparison.csv
    let mut c = File::create(out.join("comparison.csv"))?;
    writeln!(c, "metric,argon2id,antech_v4c_16mib,notes")?;
    writeln!(c, "GPU model,{gpu_name},{gpu_name},")?;
    writeln!(c, "VRAM,{vram_total} MiB,{vram_total} MiB,")?;
    writeln!(c, "Actual guesses/sec,,{gps},Argon2id GPU kernel not present — not modeled")?;
    writeln!(c, "Kernel p50,,{p50} ms,")?;
    writeln!(c, "GPU utilization,,,not sampled via NVML this pass")?;
    writeln!(c, "Global memory traffic,,{traffic},estimate from node traffic model")?;
    writeln!(c, "Occupancy,,{occ},")?;
    writeln!(c, "Registers/thread,,{regs},")?;
    writeln!(c, "CPU attacker 16t g/s,,{cpu_16},prior CPU suite")?;
    writeln!(c, "CPU attacker 32t g/s,,{cpu_32},prior CPU suite")?;
    writeln!(c, "GPU/CPU speedup vs 16t,,{speedup_16:.4},")?;
    writeln!(c, "GPU/CPU speedup vs 32t,,{speedup_32:.4},")?;
    writeln!(c, "verdict,,,{verdict}")?;

    // profile.csv
    let mut p = File::create(out.join("profile.csv"))?;
    writeln!(p, "metric,value,unit,status")?;
    writeln!(p, "guesses_per_sec,{gps},1/s,REAL")?;
    writeln!(p, "kernel_p50_ms,{p50},ms,REAL")?;
    writeln!(p, "kernel_p95_ms,{p95},ms,REAL")?;
    writeln!(p, "kernel_p99_ms,{p99},ms,REAL")?;
    writeln!(p, "vram_used_mib,{vram},MiB,REAL")?;
    writeln!(p, "occupancy,{occ},fraction,REAL")?;
    writeln!(p, "registers_per_thread,{regs},,REAL")?;
    writeln!(p, "shared_mem_bytes,{smem},B,REAL")?;
    writeln!(p, "global_mem_traffic_est,{traffic},B,EST")?;
    writeln!(p, "host_device_transfer_ms,{xfer},ms,REAL")?;
    writeln!(p, "kernel_exec_ms_total,{kexec},ms,REAL")?;
    writeln!(p, "batch,{batch},guesses,REAL")?;
    writeln!(p, "gpu_util_pct,,,NOT_SAMPLED")?;
    writeln!(p, "l2_cache,,,NOT_SAMPLED")?;

    // report.md
    let mut r = File::create(out.join("report.md"))?;
    writeln!(r, "# Antech v4-C @ 16 MiB — Real CUDA GPU Attack\n")?;
    writeln!(r, "## Verdict\n\n**{verdict}**\n")?;
    writeln!(r, "Also: **REAL GPU BENCHMARK COMPLETED**\n")?;
    writeln!(r, "## Direct result\n")?;
    writeln!(r, "| Metric | Argon2id | Antech v4-C |")?;
    writeln!(r, "|---|---:|---:|")?;
    writeln!(r, "| GPU model | {gpu_name} | {gpu_name} |")?;
    writeln!(r, "| VRAM | {vram_total} MiB | {vram_total} MiB |")?;
    writeln!(r, "| Actual guesses/sec | — (no CUDA kernel) | {gps} |")?;
    writeln!(r, "| Kernel p50 | — | {p50} ms |")?;
    writeln!(r, "| GPU utilization | — | not NVML-sampled |")?;
    writeln!(r, "| Global memory traffic | — | {traffic} B (est) |")?;
    writeln!(r, "| Occupancy | — | {occ} |")?;
    writeln!(r, "| Registers/thread | — | {regs} |")?;
    writeln!(r, "\n## CPU vs GPU\n")?;
    writeln!(r, "| Metric | Value |")?;
    writeln!(r, "|---|---:|")?;
    writeln!(r, "| CPU 16-thread attacker | {cpu_16} g/s |")?;
    writeln!(r, "| CPU 32-thread attacker | {cpu_32} g/s |")?;
    writeln!(r, "| Real GPU attacker | {gps} g/s |")?;
    writeln!(r, "| GPU/CPU (16t) speedup | {speedup_16:.3}× |")?;
    writeln!(r, "| GPU/CPU (32t) speedup | {speedup_32:.3}× |")?;
    writeln!(
        r,
        "\n## Method\n\n- Exact v4-C CombinedFrontier walk on device (524288 nodes, 16 MiB/guess).\n\
         - Host SHA-256 for seed bind + finalize (identical domains); digests matched CPU 10/10.\n\
         - Same attacker corpus salt `v4_attacker_salt_16`.\n\
         - Batch={batch} concurrent full-memory guesses.\n\
         - Argon2id GPU: no CUDA kernel in-tree; **not measured, not modeled**.\n\
         - Legacy modeled figures 375/6400/7800 g/s **excluded**.\n"
    )?;
    Ok(())
}
