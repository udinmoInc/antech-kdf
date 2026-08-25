//! ASIC/FPGA research model derived from the canonical construction (estimates only).

use antech_kdf_types::{AntechConfig, GraphKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsicFpgaModel {
    pub kind: String, // MODELED
    pub memory_mib: usize,
    pub num_blocks: usize,
    pub state_bits: usize,
    pub block_bytes: usize,
    pub mix_rounds: u32,
    pub fan_in: u32,
    pub scatters_per_node_nominal: f64,
    pub estimated_mix_pairs: u64,
    pub estimated_parent_gathers: u64,
    pub estimated_scatters: u64,
    pub sequential_dependency: bool,
    pub on_chip_mem_bytes: usize,
    pub cycles_per_guess_assumption: u64,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivityRow {
    pub param: String,
    pub value: f64,
    pub relative_throughput: f64,
    pub kind: String,
    pub notes: String,
}

pub fn model_from_config(cfg: &AntechConfig) -> AsicFpgaModel {
    let n = cfg.num_blocks() as u64;
    // Conservative averages from prior instrumentation at 16 MiB.
    let mix_pairs = (n as f64 * 2.23) as u64;
    let gathers = (n as f64 * 3.73) as u64;
    let scatters = (n as f64 * 2.0) as u64;
    AsicFpgaModel {
        kind: "MODELED".into(),
        memory_mib: cfg.memory.as_mib(),
        num_blocks: cfg.num_blocks(),
        state_bits: 256,
        block_bytes: cfg.block_size.as_bytes(),
        mix_rounds: antech_kdf_types::MIX_ROUNDS,
        fan_in: cfg.fan_in.get(),
        scatters_per_node_nominal: 2.0,
        estimated_mix_pairs: mix_pairs,
        estimated_parent_gathers: gathers,
        estimated_scatters: scatters,
        sequential_dependency: true,
        on_chip_mem_bytes: cfg.memory.as_bytes(),
        // Assume ~4 cycles/mix-round * 4 words loosely → placeholder sensitivity baseline.
        cycles_per_guess_assumption: mix_pairs.saturating_mul(16),
        notes: "Derived from CombinedFrontier structure + prior MEASURED op counts; NOT silicon measurement.".into(),
    }
}

pub fn default_canonical_model() -> AsicFpgaModel {
    let cfg = AntechConfig::builder()
        .memory_mib(16)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap();
    model_from_config(&cfg)
}

pub fn sensitivity_sweep(base: &AsicFpgaModel) -> Vec<SensitivityRow> {
    let base_cyc = base.cycles_per_guess_assumption as f64;
    let mut rows = Vec::new();
    for &(label, factor) in &[
        ("cycles_x0.5", 0.5),
        ("cycles_x1.0", 1.0),
        ("cycles_x2.0", 2.0),
        ("cycles_x4.0", 4.0),
        ("mem_ports_2x_throughput", 0.7),
    ] {
        rows.push(SensitivityRow {
            param: label.into(),
            value: factor,
            relative_throughput: 1.0 / factor,
            kind: "MODELED".into(),
            notes: format!("baseline_cycles={base_cyc}; sequential state chain limits ILP"),
        });
    }
    rows
}
