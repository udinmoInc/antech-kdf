//! ASIC/FPGA cost model for the frozen CombinedFrontier construction.
//!
//! Digests and algorithm are unchanged. Numbers are derived from
//! `AntechConfig` defaults plus MEASURED op counts / TMTO results from
//! `research/results/cryptanalysis/tmto-advanced/` and compute-memory-v4.
//! Silicon metrics are MODELED or ASSUMED ranges — never sold as measured die results.

use antech_kdf_types::{AntechConfig, GraphKind, FRONTIER_WIDTH, MIX_ROUNDS, TILE_BLOCKS};
use serde::{Deserialize, Serialize};

/// Canonical production defaults used throughout this model.
pub fn canonical_config() -> AntechConfig {
    AntechConfig::builder()
        .memory_mib(16)
        .block_size(32)
        .fan_in(2)
        .graph(GraphKind::CombinedFrontier)
        .salt_length(16)
        .output_length(32)
        .build()
        .expect("canonical config")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructionFacts {
    pub label: String,
    pub construction: String,
    pub graph: String,
    pub memory_bytes: usize,
    pub memory_mib: usize,
    pub block_bytes: usize,
    pub num_blocks: usize,
    pub fan_in: u32,
    pub mix_rounds: u32,
    pub state_bytes: usize,
    pub frontier_width: usize,
    pub tile_blocks: usize,
    pub dual_far_scatter: bool,
    pub sequential_within_guess: bool,
    pub independent_across_guesses: bool,
    pub evidence: String,
}

pub fn construction_facts(cfg: &AntechConfig) -> ConstructionFacts {
    ConstructionFacts {
        label: "MEASURED".into(),
        construction: "compute-memory-v4 / $antech$v2$".into(),
        graph: format!("{:?}", cfg.graph),
        memory_bytes: cfg.memory.as_bytes(),
        memory_mib: cfg.memory.as_mib(),
        block_bytes: cfg.block_size.as_bytes(),
        num_blocks: cfg.num_blocks(),
        fan_in: cfg.fan_in.get(),
        mix_rounds: MIX_ROUNDS,
        state_bytes: 32,
        frontier_width: FRONTIER_WIDTH,
        tile_blocks: TILE_BLOCKS.min(cfg.num_blocks().max(1)),
        dual_far_scatter: matches!(cfg.graph, GraphKind::CombinedFrontier),
        sequential_within_guess: true,
        independent_across_guesses: true,
        evidence: "crates/antech-kdf-core engine+graph; multitarget.csv (no DAG reuse)".into(),
    }
}

/// Operation counts for one password guess.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationCount {
    pub memory_mib: usize,
    pub num_blocks: u64,
    pub mix_pairs: u64,
    pub parent_block_reads: u64,
    pub block_writes: u64,
    pub scatter_rmw: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub arx_rounds_total: u64,
    pub evidence: String,
    pub kind: String,
}

/// 16 MiB MEASURED mix_pairs from tmto-advanced memory-sweep-16mib (full_packed).
const MEASURED_MIX_PAIRS_16MIB: u64 = 1_171_024;
const MEASURED_NODES_16MIB: u64 = 524_288;

pub fn operation_count(cfg: &AntechConfig) -> OperationCount {
    let n = cfg.num_blocks() as u64;
    let b = cfg.block_size.as_bytes() as u64;
    // Scale MEASURED 16 MiB mix_pair density when memory changes.
    let mix_pairs = if cfg.memory.as_mib() == 16 && b == 32 {
        MEASURED_MIX_PAIRS_16MIB
    } else {
        ((n as f64) * (MEASURED_MIX_PAIRS_16MIB as f64 / MEASURED_NODES_16MIB as f64)).round() as u64
    };
    // CombinedFrontier: dual scatter for i > FRONTIER_WIDTH ≈ 2*(N - 64).
    let scatter_rmw = n.saturating_sub(FRONTIER_WIDTH as u64).saturating_mul(2);
    // Parents: fan_in nominal reads/node (engine gathers parents.len; fan_in=2 default).
    let parent_reads = n.saturating_mul(cfg.fan_in.get() as u64);
    let block_writes = n; // state_to_block at i
    let bytes_read = (parent_reads + scatter_rmw) * b; // scatter RMW reads old block
    let bytes_written = (block_writes + scatter_rmw) * b;
    let arx_rounds = mix_pairs.saturating_mul(MIX_ROUNDS as u64);
    OperationCount {
        memory_mib: cfg.memory.as_mib(),
        num_blocks: n,
        mix_pairs,
        parent_block_reads: parent_reads,
        block_writes,
        scatter_rmw,
        bytes_read,
        bytes_written,
        arx_rounds_total: arx_rounds,
        evidence: "mix_pairs MEASURED@16MiB tmto-advanced; scatters from CombinedFrontier dual dest".into(),
        kind: if cfg.memory.as_mib() == 16 {
            "MEASURED+MODELED".into()
        } else {
            "MODELED".into()
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemArch {
    OnChipSram,
    FpgaBramUram,
    ExternalDdr,
    Hbm,
}

impl MemArch {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnChipSram => "on_chip_sram",
            Self::FpgaBramUram => "fpga_bram_uram",
            Self::ExternalDdr => "external_ddr",
            Self::Hbm => "hbm",
        }
    }
}

/// Documented ASSUMED technology ranges (not die measurements).
#[derive(Debug, Clone)]
pub struct TechAssumptions {
    pub asic_clock_hz_lo: f64,
    pub asic_clock_hz_hi: f64,
    pub fpga_clock_hz_lo: f64,
    pub fpga_clock_hz_hi: f64,
    /// Cycles/node when working set is on-chip multi-port SRAM (custom ARX datapath).
    pub cycles_node_onchip: f64,
    /// Cycles/node FPGA fabric + BRAM/URAM.
    pub cycles_node_fpga: f64,
    /// Effective random-access latency cycles at ASIC clock when using DDR.
    pub cycles_node_ddr: f64,
    /// Effective cycles/node with HBM (better BW, still random RMW).
    pub cycles_node_hbm: f64,
    pub ddr_bandwidth_bytes_s: f64,
    pub hbm_bandwidth_bytes_s: f64,
    pub sram_bytes_per_mm2: f64,
    pub asic_logic_mm2_per_pipeline: f64,
    pub fpga_logic_util_per_pipeline: f64,
    pub power_w_per_pipeline_onchip: f64,
    pub power_w_per_pipeline_ddr: f64,
    pub power_w_per_pipeline_hbm: f64,
    pub chip_sram_budget_bytes: f64,
    pub chip_hbm_budget_bytes: f64,
    pub chip_power_budget_w: f64,
}

impl Default for TechAssumptions {
    fn default() -> Self {
        Self {
            // ASSUMED: modern ASIC / mid FPGA fabric ranges
            asic_clock_hz_lo: 800e6,
            asic_clock_hz_hi: 1.5e9,
            fpga_clock_hz_lo: 200e6,
            fpga_clock_hz_hi: 400e6,
            // ASSUMED after removing CPU decode/branch; limited by sequential state + RMW
            cycles_node_onchip: 24.0,
            cycles_node_fpga: 48.0,
            cycles_node_ddr: 180.0,
            cycles_node_hbm: 60.0,
            ddr_bandwidth_bytes_s: 50e9,  // ~DDR4-3200 dual-ish ASSUMED
            hbm_bandwidth_bytes_s: 460e9, // HBM2E-class ASSUMED
            sram_bytes_per_mm2: 0.8e6,    // rough modern SRAM density ASSUMED
            asic_logic_mm2_per_pipeline: 0.15,
            fpga_logic_util_per_pipeline: 0.02, // fraction of large FPGA
            power_w_per_pipeline_onchip: 0.8,
            power_w_per_pipeline_ddr: 2.5,
            power_w_per_pipeline_hbm: 1.8,
            chip_sram_budget_bytes: 64.0 * 1024.0 * 1024.0, // 64 MiB on-chip ASSUMED large ASIC
            chip_hbm_budget_bytes: 16.0 * 1024.0 * 1024.0 * 1024.0, // 16 GiB stack ASSUMED
            chip_power_budget_w: 75.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEstimate {
    pub platform: String,
    pub mem_arch: String,
    pub memory_mib_per_guess: usize,
    pub parallel_guesses: u64,
    pub on_chip_mem_bytes: u64,
    pub external_mem_bytes: u64,
    pub bytes_per_guess_traffic: u64,
    pub mem_bandwidth_needed_bytes_s: f64,
    pub cycles_per_guess: f64,
    pub clock_hz: f64,
    pub throughput_gps: f64,
    pub area_mm2_or_fpga_util: f64,
    pub power_w: f64,
    pub energy_j_per_guess: f64,
    pub area_per_gps: f64,
    pub power_per_gps: f64,
    pub bottleneck: String,
    pub kind: String,
    pub notes: String,
}

fn cycles_for(arch: MemArch, a: &TechAssumptions, n: f64) -> f64 {
    let cpn = match arch {
        MemArch::OnChipSram => a.cycles_node_onchip,
        MemArch::FpgaBramUram => a.cycles_node_fpga,
        MemArch::ExternalDdr => a.cycles_node_ddr,
        MemArch::Hbm => a.cycles_node_hbm,
    };
    cpn * n
}

fn clock_for(platform: &str, arch: MemArch, a: &TechAssumptions) -> f64 {
    match (platform, arch) {
        ("asic", MemArch::OnChipSram) => a.asic_clock_hz_hi,
        ("asic", MemArch::Hbm) => a.asic_clock_hz_lo,
        ("asic", _) => a.asic_clock_hz_lo,
        ("fpga", MemArch::FpgaBramUram) => a.fpga_clock_hz_hi,
        ("fpga", _) => a.fpga_clock_hz_lo,
        _ => a.asic_clock_hz_lo,
    }
}

pub fn estimate_chip(
    platform: &str,
    arch: MemArch,
    cfg: &AntechConfig,
    ops: &OperationCount,
    parallel: u64,
    a: &TechAssumptions,
) -> HardwareEstimate {
    let n = ops.num_blocks as f64;
    let mem_g = cfg.memory.as_bytes() as u64;
    let traffic = ops.bytes_read.saturating_add(ops.bytes_written);
    let cycles = cycles_for(arch, a, n);
    let clock = clock_for(platform, arch, a);
    let gps_one = clock / cycles;
    let mut gps = gps_one * parallel as f64;

    let (on_chip, external) = match arch {
        MemArch::OnChipSram | MemArch::FpgaBramUram => (mem_g.saturating_mul(parallel), 0),
        MemArch::ExternalDdr | MemArch::Hbm => {
            // Keep a small frontier/state scratch on-chip (~64 KiB ASSUMED) per pipeline.
            let scratch = 64 * 1024u64;
            (scratch.saturating_mul(parallel), mem_g.saturating_mul(parallel))
        }
    };

    let bw_needed = gps * traffic as f64;
    let bw_cap = match arch {
        MemArch::OnChipSram | MemArch::FpgaBramUram => f64::INFINITY,
        MemArch::ExternalDdr => a.ddr_bandwidth_bytes_s,
        MemArch::Hbm => a.hbm_bandwidth_bytes_s,
    };

    let mut bottleneck = "compute_sequential_state".to_string();
    if bw_needed > bw_cap {
        let scale = bw_cap / bw_needed;
        gps *= scale;
        bottleneck = "external_memory_bandwidth".into();
    }

    // Memory capacity ceilings
    let cap = match arch {
        MemArch::OnChipSram => a.chip_sram_budget_bytes,
        MemArch::FpgaBramUram => 40.0 * 1024.0 * 1024.0, // ~40 MiB URAM/BRAM class ASSUMED
        MemArch::Hbm => a.chip_hbm_budget_bytes,
        MemArch::ExternalDdr => 128.0 * 1024.0 * 1024.0 * 1024.0,
    };
    let mem_need = (on_chip + external) as f64;
    if mem_need > cap && parallel > 0 {
        let max_p = (cap / mem_g as f64).floor().max(0.0) as u64;
        if max_p < parallel {
            let scale = max_p as f64 / parallel as f64;
            gps *= scale;
            bottleneck = "memory_capacity".into();
        }
    }

    let power_one = match arch {
        MemArch::OnChipSram | MemArch::FpgaBramUram => a.power_w_per_pipeline_onchip,
        MemArch::ExternalDdr => a.power_w_per_pipeline_ddr,
        MemArch::Hbm => a.power_w_per_pipeline_hbm,
    };
    let mut power = power_one * parallel as f64;
    if power > a.chip_power_budget_w {
        let scale = a.chip_power_budget_w / power;
        gps *= scale;
        power = a.chip_power_budget_w;
        if bottleneck == "compute_sequential_state" {
            bottleneck = "power_budget".into();
        }
    }

    let area = match platform {
        "asic" => {
            let sram_mm2 = on_chip as f64 / a.sram_bytes_per_mm2;
            sram_mm2 + a.asic_logic_mm2_per_pipeline * parallel as f64
        }
        _ => a.fpga_logic_util_per_pipeline * parallel as f64,
    };

    let energy = if gps > 0.0 { power / gps } else { f64::INFINITY };
    let area_per = if gps > 0.0 { area / gps } else { f64::INFINITY };
    let power_per = if gps > 0.0 { power / gps } else { f64::INFINITY };

    HardwareEstimate {
        platform: platform.into(),
        mem_arch: arch.as_str().into(),
        memory_mib_per_guess: cfg.memory.as_mib(),
        parallel_guesses: parallel,
        on_chip_mem_bytes: on_chip,
        external_mem_bytes: external,
        bytes_per_guess_traffic: traffic,
        mem_bandwidth_needed_bytes_s: bw_needed.min(bw_cap),
        cycles_per_guess: cycles,
        clock_hz: clock,
        throughput_gps: gps,
        area_mm2_or_fpga_util: area,
        power_w: power,
        energy_j_per_guess: energy,
        area_per_gps: area_per,
        power_per_gps: power_per,
        bottleneck,
        kind: "MODELED".into(),
        notes: format!(
            "SW decode/branch removed; sequential 256-bit state + dual scatter RMW remain. N={n}"
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmtoHardwareRow {
    pub memory_frac: f64,
    pub working_set_mib: f64,
    pub strategy: String,
    pub correct: bool,
    pub cpu_cost_factor: f64,
    pub hw_recompute_factor: f64,
    pub area_relative: f64,
    pub power_relative: f64,
    pub throughput_relative: f64,
    pub kind: String,
    pub notes: String,
}

/// Map MEASURED TMTO walls onto hardware: reduced SRAM does not help if recompute explodes.
pub fn tmto_hardware_rows() -> Vec<TmtoHardwareRow> {
    // From memory-sweep-16mib.csv + report (MEASURED cost factors; sparse incorrect).
    let rows = [
        (1.0, "full_packed", true, 0.93),
        (0.75, "sparse_checkpoint", false, 5066.0),
        (0.5, "sparse_checkpoint", false, 15069.0),
        (0.25, "sparse_checkpoint", false, 19791.0),
        (0.125, "sparse_checkpoint", false, 15100.0),
        (1.0 / 16.0, "sparse_probe", false, 178.0), // 1 MiB-scale probe lower bound class
    ];
    rows
        .iter()
        .map(|(frac, strat, ok, cost)| {
            let ws = 16.0_f64 * *frac;
            // Hardware: SRAM area scales with working set, but cycles scale with recompute.
            let recompute = if *ok { 1.0_f64 } else { *cost };
            let area = ws / 16.0_f64;
            let throughput = if *ok { 1.0_f64 } else { 1.0_f64 / recompute };
            let power = if *ok {
                1.0_f64
            } else {
                f64::min(recompute * 0.3_f64 + area * 0.7_f64, recompute)
            };
            TmtoHardwareRow {
                memory_frac: *frac,
                working_set_mib: ws,
                strategy: (*strat).into(),
                correct: *ok,
                cpu_cost_factor: *cost,
                hw_recompute_factor: recompute,
                area_relative: area,
                power_relative: power,
                throughput_relative: throughput,
                kind: if *ok { "MEASURED+MODELED" } else { "MEASURED" }.into(),
                notes: "CPU TMTO MEASURED; HW maps cost_factor onto cycles/energy. Incorrect rows are walls.".into(),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivityRow {
    pub axis: String,
    pub value: String,
    pub relative_throughput: f64,
    pub relative_energy: f64,
    pub kind: String,
    pub notes: String,
}

pub fn sensitivity_rows(base_gps: f64) -> Vec<SensitivityRow> {
    let _ = base_gps;
    vec![
        SensitivityRow {
            axis: "sram_cost".into(),
            value: "0.5x_density".into(),
            relative_throughput: 0.5,
            relative_energy: 1.0,
            kind: "ASSUMED".into(),
            notes: "Halving on-chip SRAM budget halves parallel guesses under OnChipSram".into(),
        },
        SensitivityRow {
            axis: "sram_cost".into(),
            value: "2x_density".into(),
            relative_throughput: 2.0,
            relative_energy: 1.0,
            kind: "ASSUMED".into(),
            notes: "More pipelines if power allows".into(),
        },
        SensitivityRow {
            axis: "external_bandwidth".into(),
            value: "0.5x_ddr".into(),
            relative_throughput: 0.5,
            relative_energy: 1.2,
            kind: "MODELED".into(),
            notes: "DDR-bound regime; traffic ≈ reads+writes including scatter RMW".into(),
        },
        SensitivityRow {
            axis: "external_bandwidth".into(),
            value: "2x_hbm".into(),
            relative_throughput: 1.8,
            relative_energy: 0.9,
            kind: "MODELED".into(),
            notes: "Helps until sequential node chain dominates".into(),
        },
        SensitivityRow {
            axis: "clock".into(),
            value: "0.5x".into(),
            relative_throughput: 0.5,
            relative_energy: 0.7,
            kind: "ASSUMED".into(),
            notes: "Linear in compute-bound; less than linear if DDR latency fixed in ns".into(),
        },
        SensitivityRow {
            axis: "clock".into(),
            value: "2x".into(),
            relative_throughput: 1.6,
            relative_energy: 1.5,
            kind: "ASSUMED".into(),
            notes: "Capped by memory latency / power".into(),
        },
        SensitivityRow {
            axis: "node_dependency".into(),
            value: "force_serial".into(),
            relative_throughput: 1.0,
            relative_energy: 1.0,
            kind: "MEASURED".into(),
            notes: "Already serial within guess (state + data-dependent parents)".into(),
        },
        SensitivityRow {
            axis: "node_dependency".into(),
            value: "hypothetical_ilp_4".into(),
            relative_throughput: 1.15,
            relative_energy: 0.95,
            kind: "ASSUMED".into(),
            notes: "Limited ILP inside mix_pair only; cannot overlap nodes deeply".into(),
        },
        SensitivityRow {
            axis: "memory_compression".into(),
            value: "lossy_forbidden".into(),
            relative_throughput: 1.0,
            relative_energy: 1.0,
            kind: "MEASURED".into(),
            notes: "tmto-advanced: no useful lossless block compression".into(),
        },
        SensitivityRow {
            axis: "replication".into(),
            value: "10x_pipelines".into(),
            relative_throughput: 10.0,
            relative_energy: 1.0,
            kind: "MODELED".into(),
            notes: "Independent guesses (multitarget MEASURED); needs 10× memory".into(),
        },
        SensitivityRow {
            axis: "recomputation".into(),
            value: "50pct_working_set".into(),
            relative_throughput: 1.0 / 15069.0,
            relative_energy: 15069.0,
            kind: "MEASURED".into(),
            notes: "sparse_checkpoint @50% aborts; cost_factor from memory-sweep-16mib".into(),
        },
        SensitivityRow {
            axis: "power_limit".into(),
            value: "0.5x_budget".into(),
            relative_throughput: 0.5,
            relative_energy: 1.0,
            kind: "ASSUMED".into(),
            notes: "Caps parallel pipelines".into(),
        },
        SensitivityRow {
            axis: "attacker_regime".into(),
            value: "unlimited_mem_limited_compute".into(),
            relative_throughput: 1.0,
            relative_energy: 1.0,
            kind: "MODELED".into(),
            notes: "Still bound by sequential N×cycles/node per pipeline".into(),
        },
        SensitivityRow {
            axis: "attacker_regime".into(),
            value: "abundant_compute_limited_mem".into(),
            relative_throughput: 0.0001,
            relative_energy: 1e4,
            kind: "MEASURED".into(),
            notes: "TMTO wall: cannot trade memory for time efficiently".into(),
        },
        SensitivityRow {
            axis: "attacker_regime".into(),
            value: "abundant_onchip_sram".into(),
            relative_throughput: 4.0,
            relative_energy: 0.8,
            kind: "MODELED".into(),
            notes: "Best case: more independent pipelines; per-guess critical path unchanged".into(),
        },
        SensitivityRow {
            axis: "attacker_regime".into(),
            value: "abundant_bandwidth".into(),
            relative_throughput: 1.3,
            relative_energy: 0.9,
            kind: "MODELED".into(),
            notes: "Removes DDR bottleneck; sequential dependency remains".into(),
        },
        SensitivityRow {
            axis: "attacker_regime".into(),
            value: "many_parallel_cores".into(),
            relative_throughput: 100.0,
            relative_energy: 1.0,
            kind: "MODELED".into(),
            notes: "Needs 100×16 MiB; no cross-guess sharing (MEASURED multitarget)".into(),
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsArgon2Row {
    pub metric: String,
    pub antech: String,
    pub argon2id: String,
    pub kind: String,
    pub notes: String,
}

pub fn antech_vs_argon2() -> Vec<VsArgon2Row> {
    vec![
        VsArgon2Row {
            metric: "defender_p50_ms_16mib_cpu".into(),
            antech: "96.3".into(),
            argon2id: "n/a_at_16mib_in_table".into(),
            kind: "MEASURED".into(),
            notes: "compute-memory-v4/report.md CombinedFrontier".into(),
        },
        VsArgon2Row {
            metric: "attacker_16t_gps_cpu".into(),
            antech: "40.56".into(),
            argon2id: "22.94 (64 MiB campaign row)".into(),
            kind: "MEASURED".into(),
            notes: "comparison.csv; Argon2id row is 64 MiB in that campaign".into(),
        },
        VsArgon2Row {
            metric: "gpu_gps_rtx3050".into(),
            antech: "32.96".into(),
            argon2id: "435.56".into(),
            kind: "MEASURED".into(),
            notes: "gpu/report.md — Argon2id much faster on GPU; Antech scatter hurts occupancy".into(),
        },
        VsArgon2Row {
            metric: "asic_full_sram_1pipe_gps".into(),
            antech: "modeled_in_asic-model.csv".into(),
            argon2id: "similar_order_if_equal_mem; fewer random RMWs".into(),
            kind: "MODELED".into(),
            notes: "Both memory-hard; Antech dual far-scatter adds irregular RMW vs Argon2 fill".into(),
        },
        VsArgon2Row {
            metric: "tmto_50pct_memory".into(),
            antech: "wall ~15069× / abort".into(),
            argon2id: "known_TMTO_exists_but_costly".into(),
            kind: "MEASURED".into(),
            notes: "Antech sparse_checkpoint MEASURED wall; do not claim ASIC-proof".into(),
        },
        VsArgon2Row {
            metric: "claim_asic_resistant".into(),
            antech: "NOT_CLAIMED".into(),
            argon2id: "NOT_CLAIMED".into(),
            kind: "ASSUMED".into(),
            notes: "Custom silicon removes CPU/GPU overhead; memory+sequential path remain".into(),
        },
    ]
}

pub fn reduced_memory_cfgs() -> Vec<(AntechConfig, &'static str)> {
    // Production minimum is 1024 KiB; smaller sizes are hypothetical attacker footprints.
    let specs: &[(usize, &str)] = &[
        (16 * 1024, "production_default"),
        (8 * 1024, "valid_config"),
        (4 * 1024, "valid_config"),
        (2 * 1024, "valid_config"),
        (1024, "production_minimum"),
        (512, "hypothetical_below_min"),
        (256, "hypothetical_below_min"),
    ];
    specs
        .iter()
        .map(|&(kib, tag)| {
            let mut cfg = AntechConfig::default();
            cfg.memory = antech_kdf_types::MemorySize::kib(kib);
            cfg.block_size = antech_kdf_types::BlockSize::bytes(32);
            cfg.fan_in = antech_kdf_types::FanIn::new(2);
            cfg.graph = GraphKind::CombinedFrontier;
            (cfg, tag)
        })
        .collect()
}

pub fn replication_counts() -> &'static [u64] {
    &[1, 10, 100, 1_000, 10_000]
}

/// Compatibility helpers for older engineering runners.
pub fn default_canonical_model() -> OperationCount {
    operation_count(&canonical_config())
}

pub fn model_from_config(cfg: &AntechConfig) -> OperationCount {
    operation_count(cfg)
}

pub fn sensitivity_sweep(_base: &OperationCount) -> Vec<SensitivityRow> {
    sensitivity_rows(1.0)
}
