//! Research configuration aliases for the canonical compute-memory engine.

pub use antech_kdf_core::{
    CONSTRUCTION_VERSION as V4_VERSION, DEFAULT_BLOCK_SIZE, DEFAULT_FAN_IN, DEFAULT_MEMORY_KIB,
};
pub use antech_kdf_types::{AntechConfig, GraphKind, FRONTIER_WIDTH, MIX_ROUNDS, TILE_BLOCKS};

pub use crate::compute_memory::config::{
    CPU_WORKER_COUNTS, DEFAULT_MEMORY_KIB as V4_DEFAULT_MEMORY_KIB, MEMORY_TARGETS_MIB,
    TMTO_FRACTIONS,
};

pub const DEFAULT_MEMORY_MIB: u32 = DEFAULT_MEMORY_KIB / 1024;

/// Research alias — canonical parameters live in [`AntechConfig`].
pub type ComputeMemoryV4Config = AntechConfig;

use crate::candidates::cand_004::ResearchParams;

pub fn resolve_v4_config(defaults: &AntechConfig, params: &ResearchParams) -> AntechConfig {
    let mut cfg = *defaults;
    if params.memory_kib > 0 {
        cfg.memory = antech_kdf_types::MemorySize::kib(params.memory_kib as usize);
    }
    if params.block_size > 0 {
        cfg.block_size = antech_kdf_types::BlockSize::bytes(params.block_size as usize);
    }
    cfg
}

pub fn validate_v4_config(cfg: &AntechConfig) -> Result<(), String> {
    cfg.validate().map_err(|e| e.to_string())
}

pub fn to_research_params(cfg: &AntechConfig) -> ResearchParams {
    ResearchParams {
        memory_kib: cfg.memory.as_kib() as u32,
        passes: 0,
        dependency_depth: 0,
        block_size: cfg.block_size.as_bytes() as u32,
    }
}

pub fn memory_targets_mib() -> &'static [usize] {
    &MEMORY_TARGETS_MIB
}
