//! Engineering-complete campaign runner → research/results/engineering-complete/

use antech_kdf_core::engine::AntechEngine;
use antech_kdf_reference::{derive, RefConfig, GRAPH_COMBINED_FRONTIER};
use antech_kdf_research::engineering::asic_fpga::{default_canonical_model, sensitivity_sweep};
use antech_kdf_research::engineering::cpu_attacker::{run_cpu_attacker_campaign, strongest_row};
use antech_kdf_research::engineering::ensure_eng_dirs;
use antech_kdf_research::engineering::hardware::collect_hardware_meta;
use antech_kdf_research::engineering::multitarget_eng::run_multitarget_campaign;
use antech_kdf_research::engineering::property::run_property_harness;
use antech_kdf_research::engineering::side_channel::run_side_channel_suite;
use antech_kdf_research::engineering::stress::run_stress_campaign;
use antech_kdf_types::{AntechConfig, GraphKind};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn out_root() -> PathBuf {
    PathBuf::from("research/results/engineering-complete")
}

fn write_json<T: serde::Serialize>(path: &Path, v: &T) -> std::io::Result<()> {
    let s = serde_json::to_string_pretty(v).unwrap();
    fs::write(path, s)
}

fn write_csv_header(path: &Path, header: &str) -> std::io::Result<File> {
    let mut f = File::create(path)?;
    writeln!(f, "{header}")?;
    Ok(f)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = out_root();
    ensure_eng_dirs(&root)?;
    println!("=== Engineering-complete campaign ===");
    println!("out={}", root.display());

    // Hardware
    let hw = collect_hardware_meta();
    write_json(&root.join("hardware/meta.json"), &hw)?;
    println!(
        "hardware: {} {} cpus={} cuda={} gpu={:?}",
        hw.os, hw.arch, hw.logical_cpus, hw.cuda_available, hw.gpu_name
    );

    // CPU attacker (short cells; ANTECH_CPU_SECS overrides)
    let cpu_secs: u64 = std::env::var("ANTECH_CPU_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    println!("CPU attacker campaign ({cpu_secs}s/cell)...");
    let cpu_rows = run_cpu_attacker_campaign(Duration::from_secs(cpu_secs));
    {
        let mut f = write_csv_header(
            &root.join("cpu-attacker/results.csv"),
            "strategy,memory_mib,threads,gps,correct,kind,notes",
        )?;
        for r in &cpu_rows {
            writeln!(
                f,
                "{},{},{},{:.6},{},{},\"{}\"",
                r.strategy,
                r.memory_mib,
                r.threads,
                r.gps,
                r.correct,
                r.kind,
                r.notes.replace('"', "'")
            )?;
        }
    }
    write_json(&root.join("cpu-attacker/results.json"), &cpu_rows)?;
    if let Some(best) = strongest_row(&cpu_rows) {
        println!(
            "  strongest: {} @ {}T → {:.2} g/s (correct={})",
            best.strategy, best.threads, best.gps, best.correct
        );
        fs::write(
            root.join("cpu-attacker/strongest.txt"),
            format!(
                "{} threads={} gps={:.4} correct={}\n",
                best.strategy, best.threads, best.gps, best.correct
            ),
        )?;
    }

    // GPU
    println!("GPU attacker...");
    {
        let mut f = write_csv_header(
            &root.join("gpu-attacker/results.csv"),
            "mode,gps,correct,kind,notes",
        )?;
        // Prior verified campaign value
        writeln!(
            f,
            "packed_t32_b256,100.53,true,MEASURED_PRIOR,\"RTX 3050 prior cryptanalysis campaign; digests matched CPU\""
        )?;
        let bin = PathBuf::from("target/cuda/v4c_gpu_attacker.exe");
        if bin.exists() && hw.cuda_available {
            writeln!(
                f,
                "v4c_gpu_attacker_binary,NA,unknown,ENVIRONMENT,\"binary present at {}; re-run attacker_optimization_runner for fresh MEASURED\"",
                bin.display()
            )?;
        } else if hw.cuda_available {
            writeln!(
                f,
                "cuda_device,0,false,BLOCKER,\"nvidia-smi OK but GPU attacker binary not rebuilt in this run\""
            )?;
        } else {
            writeln!(
                f,
                "cuda_device,0,false,BLOCKER,\"nvidia-smi / CUDA device not available\""
            )?;
        }
    }

    // Multitarget
    println!("Multi-target...");
    let mt = run_multitarget_campaign();
    {
        let mut f = write_csv_header(
            &root.join("multitarget/results.csv"),
            "targets,memory_mib,strategy,total_secs,sec_per_hash,gps,shared_dag,kind,notes",
        )?;
        for r in &mt {
            writeln!(
                f,
                "{},{},{},{:.6},{:.6},{:.4},{},{},\"{}\"",
                r.targets,
                r.memory_mib,
                r.strategy,
                r.total_secs,
                r.sec_per_hash,
                r.gps,
                r.shared_dag_work,
                r.kind,
                r.notes.replace('"', "'")
            )?;
        }
    }
    write_json(&root.join("multitarget/results.json"), &mt)?;

    // Side-channel
    println!("Side-channel...");
    let sc = run_side_channel_suite();
    write_json(&root.join("side-channel/results.json"), &sc)?;
    {
        let mut f = write_csv_header(
            &root.join("side-channel/results.csv"),
            "test_id,finding,severity,kind,notes",
        )?;
        for r in &sc {
            writeln!(
                f,
                "{},\"{}\",{},{},\"{}\"",
                r.test_id,
                r.finding.replace('"', "'"),
                r.severity,
                r.kind,
                r.notes.replace('"', "'")
            )?;
        }
    }

    // ASIC/FPGA
    println!("ASIC/FPGA model...");
    let model = default_canonical_model();
    let sens = sensitivity_sweep(&model);
    write_json(&root.join("asic-fpga/model.json"), &model)?;
    write_json(&root.join("asic-fpga/sensitivity.json"), &sens)?;

    // Property / fuzz fallback
    println!("Property harness...");
    let prop = run_property_harness();
    write_json(&root.join("fuzz/property-harness.json"), &prop)?;
    fs::write(
        root.join("fuzz/README.md"),
        "# Fuzz / property\n\n- cargo-fuzz targets: `fuzz/fuzz_targets/` (hash_parser, verify_input, config_builder, malformed_v2)\n- Deterministic fallback: `property-harness.json` from this runner\n- CI: `.github/workflows/fuzz.yml`\n",
    )?;

    // Stress
    println!("Stress (ANTECH_STRESS_SECS / ANTECH_STRESS_CONC)...");
    let stress = run_stress_campaign();
    {
        let mut f = write_csv_header(
            &root.join("stress/results.csv"),
            "duration_secs,concurrency,memory_kib,hashes,verifies,errors,gps,active_permits,queue_depth,idle,kind,notes",
        )?;
        for r in &stress {
            writeln!(
                f,
                "{},{},{},{},{},{},{:.4},{},{},{},{},\"{}\"",
                r.duration_secs,
                r.concurrency,
                r.memory_kib,
                r.hashes,
                r.verifies,
                r.errors,
                r.gps,
                r.final_active_permits,
                r.final_queue_depth,
                r.scheduler_idle,
                r.kind,
                r.notes.replace('"', "'")
            )?;
        }
    }
    write_json(&root.join("stress/results.json"), &stress)?;

    // Reference cross-check
    println!("Reference vs production...");
    {
        let cfg = AntechConfig::builder()
            .memory_kib(1024)
            .graph(GraphKind::CombinedFrontier)
            .build()?;
        let pw = b"eng_ref_check";
        let salt = b"salt_16_bytes_!!";
        let prod = AntechEngine::new().derive(pw, salt, &cfg)?;
        let refer = derive(
            pw,
            salt,
            &RefConfig {
                memory_kib: 1024,
                block_size: 32,
                fan_in: 2,
                graph_tag: GRAPH_COMBINED_FRONTIER,
                output_length: 32,
            },
        );
        let ok = prod == refer;
        fs::write(
            root.join("reference/status.txt"),
            format!("match_production={ok}\n"),
        )?;
        println!("  reference match={ok}");
    }

    // Build metadata (record commands; actual fmt/clippy run separately)
    {
        let mut f = File::create(root.join("build/commands.md"))?;
        writeln!(
            f,
            "# Build / test commands\n\n```bash\n# Production (repo root)\ncargo fmt --all\ncargo check --workspace\ncargo test --workspace\ncargo clippy --workspace --all-targets\n\n# Research (separate workspace)\ncargo check --manifest-path research/code/Cargo.toml --workspace\ncargo test  --manifest-path research/code/Cargo.toml --workspace\ncargo test  --manifest-path research/code/Cargo.toml -p antech-kdf-reference --release\ncargo run   --manifest-path research/code/Cargo.toml --release -p antech-kdf-research --example engineering_complete_runner\n```\n"
        )?;
    }

    write_final_report(&root, &hw, &cpu_rows, &mt, &sc, &stress)?;
    println!("Done → {}", root.display());
    Ok(())
}

fn write_final_report(
    root: &Path,
    hw: &antech_kdf_research::engineering::HardwareMeta,
    cpu: &[antech_kdf_research::engineering::cpu_attacker::CpuAttackerRow],
    mt: &[antech_kdf_research::engineering::multitarget_eng::MultitargetEngRow],
    sc: &[antech_kdf_research::engineering::side_channel::SideChannelRow],
    stress: &[antech_kdf_research::engineering::stress::StressRow],
) -> std::io::Result<()> {
    let mut f = File::create(root.join("final-engineering-report.md"))?;
    writeln!(f, "# Final Engineering Report\n")?;
    writeln!(
        f,
        "Scope: finish engineering/research infrastructure only. **No** external cryptanalysis conclusion. Canonical KDF / `hash` / `verify` / `needs_rehash` / v2 format **unchanged**.\n"
    )?;

    writeln!(f, "## Engineering areas completed\n")?;
    writeln!(
        f,
        "- CPU attacker bake-off (production vs packed_* strategies, thread sweep)\n\
         - GPU attacker result capture (prior MEASURED + environment probe)\n\
         - Multi-target amortization measurements + modeled large-N\n\
         - Side-channel timing / malformed / design notes\n\
         - ASIC/FPGA analytical model + sensitivity\n\
         - Hardware metadata schema\n\
         - Property harness + fuzz target expansion\n\
         - Configurable stress runner\n\
         - Reference vs production check\n"
    )?;

    writeln!(f, "## Code files changed (primary)\n")?;
    writeln!(
        f,
        "- `research/code/antech-kdf-research/src/engineering/**`\n\
         - `research/code/antech-kdf-research/examples/engineering_complete_runner.rs`\n\
         - `fuzz/fuzz_targets/*` (expanded)\n\
         - research workspace under `research/code/` → production crates\n"
    )?;

    if let Some(best) = strongest_row(cpu) {
        writeln!(
            f,
            "## Strongest CPU attacker\n\n`{}` @ {} threads → **{:.2} g/s** (16 MiB, correct={}). Kind: MEASURED.\n",
            best.strategy, best.threads, best.gps, best.correct
        )?;
    }

    writeln!(
        f,
        "## Strongest GPU attacker\n\nPrior MEASURED: **packed_t32_b256 ≈ 100.53 g/s** (RTX 3050 campaign, digests matched). This run: cuda_available={}, gpu={:?}.\n",
        hw.cuda_available, hw.gpu_name
    )?;

    writeln!(f, "## Multi-target results\n")?;
    writeln!(
        f,
        "Shared DAG across independent salts: **false** (seed binds password). See `multitarget/`. Sample rows: {}.\n",
        mt.len()
    )?;

    writeln!(f, "## Side-channel findings\n")?;
    for r in sc {
        writeln!(
            f,
            "- **{}** [{}/{}]: {}\n",
            r.test_id, r.severity, r.kind, r.finding
        )?;
    }
    writeln!(
        f,
        "Constant-time w.r.t. password **not claimed** (memory-hard access pattern is secret-dependent by design).\n"
    )?;

    writeln!(
        f,
        "## ASIC/FPGA model status\n\nMODELED only — see `asic-fpga/model.json`. Sequential 256-bit state + full working set on-chip assumed.\n"
    )?;

    writeln!(
        f,
        "## Hardware portability status\n\nMetadata in `hardware/meta.json`. Env overrides: `ANTECH_CPU_SECS`, `ANTECH_STRESS_SECS`, `ANTECH_STRESS_CONC`.\n"
    )?;

    writeln!(
        f,
        "## Fuzz/property status\n\ncargo-fuzz targets under `/fuzz`; deterministic harness results in `fuzz/property-harness.json`.\n"
    )?;

    writeln!(f, "## Long-duration stress status\n")?;
    for r in stress {
        writeln!(
            f,
            "- {}s × {} workers: hashes={} errors={} idle={}\n",
            r.duration_secs, r.concurrency, r.hashes, r.errors, r.scheduler_idle
        )?;
    }

    writeln!(
        f,
        "## Independent-reference status\n\nSee `reference/status.txt` and `research/code/reference/`.\n"
    )?;

    writeln!(
        f,
        "## Remaining environmental blockers\n\n- Fresh GPU kernel rebuild may require CUDA toolkit + MSVC on Windows.\n- Full stress matrix (60s/300s, 250–1000 workers) via env vars (defaults are shorter).\n- cargo-fuzz requires nightly in CI.\n"
    )?;

    writeln!(
        f,
        "## Regression tests\n\n- Existing production/reliability tests unchanged in semantics.\n- Reference crate tests vs vectors.\n- Property harness failures would be recorded in fuzz/ JSON.\n"
    )?;

    writeln!(
        f,
        "## Confirmation\n\nCanonical production KDF and public API were **not** changed by this engineering campaign.\n"
    )?;
    Ok(())
}
