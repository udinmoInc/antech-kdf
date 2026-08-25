//! Structural configuration for compute-memory v4.
//!
//! Work = one traversal of `num_blocks` DAG nodes derived from
//! `memory_bytes / block_size`. Graph *kind* changes critical-path
//! shape / locality, not iteration count. No depth/passes knobs.

use crate::candidates::cand_004::ResearchParams;
use crate::compute_memory::config::{
    DEFAULT_BLOCK_SIZE, DEFAULT_FAN_IN, DEFAULT_MEMORY_KIB, MEMORY_TARGETS_MIB as MEM_TARGETS,
};

pub use crate::compute_memory::config::{
    CPU_WORKER_COUNTS, DEFAULT_MEMORY_KIB as V4_DEFAULT_MEMORY_KIB, MEMORY_TARGETS_MIB,
    TMTO_FRACTIONS,
};

pub const DEFAULT_MEMORY_MIB: u32 = DEFAULT_MEMORY_KIB / 1024;

/// Construction version bound into the seed.
pub const V4_VERSION: u32 = 4;

/// Recent-frontier ring width (protocol constant; also drives critical stride).
pub const FRONTIER_WIDTH: usize = 64;

/// Tile size in blocks for locality-optimized remotes (structure-derived multiple of frontier).
pub const TILE_BLOCKS: usize = FRONTIER_WIDTH * 8; // 512 blocks ≈ 16 KiB @ 32 B

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphKind {
    /// A — Reduced critical path: cheap local nodes + sparse remote/scatter criticals.
    ReducedCriticalPath,
    /// B — Cache/locality: remotes prefer current tile; far remote on tile boundaries.
    CacheLocality,
    /// C — Combined: sparsified criticals + tiled remotes + private frontier ring.
    CombinedFrontier,
}

impl GraphKind {
    pub fn label(self) -> &'static str {
        match self {
            GraphKind::ReducedCriticalPath => "v4-a-reduced-critical-path",
            GraphKind::CacheLocality => "v4-b-cache-locality",
            GraphKind::CombinedFrontier => "v4-c-combined-frontier",
        }
    }

    pub fn all() -> [GraphKind; 3] {
        [
            GraphKind::ReducedCriticalPath,
            GraphKind::CacheLocality,
            GraphKind::CombinedFrontier,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeMemoryV4Config {
    pub memory_kib: u32,
    pub block_size: u32,
    pub fan_in: u32,
    pub graph: GraphKind,
}

impl Default for ComputeMemoryV4Config {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            block_size: DEFAULT_BLOCK_SIZE,
            fan_in: DEFAULT_FAN_IN,
            graph: GraphKind::CombinedFrontier,
        }
    }
}

impl ComputeMemoryV4Config {
    pub fn memory_mib(mut self, mib: u32) -> Self {
        self.memory_kib = mib.saturating_mul(1024);
        self
    }

    pub fn memory_kib(mut self, kib: u32) -> Self {
        self.memory_kib = kib;
        self
    }

    pub fn block_size(mut self, bytes: u32) -> Self {
        self.block_size = bytes;
        self
    }

    pub fn fan_in(mut self, fan_in: u32) -> Self {
        self.fan_in = fan_in;
        self
    }

    pub fn graph(mut self, graph: GraphKind) -> Self {
        self.graph = graph;
        self
    }

    pub fn total_bytes(&self) -> usize {
        (self.memory_kib as usize).saturating_mul(1024)
    }

    pub fn num_blocks(&self) -> usize {
        self.total_bytes() / self.block_size.max(1) as usize
    }

    /// Critical-node period from frontier width (not a user work knob).
    /// Every `critical_period` nodes performs heavy remote gather + scatter.
    pub fn critical_period(&self) -> usize {
        // FRONTIER_WIDTH/16 = 4 → denser criticals than the first v4 cut,
        // restoring multi-instance DRAM contention while keeping most nodes lighter.
        (FRONTIER_WIDTH / 16).max(2)
    }

    /// Tile length in blocks for locality variants.
    pub fn tile_len(&self) -> usize {
        TILE_BLOCKS.min(self.num_blocks().max(1))
    }

    pub fn to_research_params(&self) -> ResearchParams {
        ResearchParams {
            memory_kib: self.memory_kib,
            passes: 0,
            dependency_depth: 0,
            block_size: self.block_size,
        }
    }

    pub fn resolve(defaults: &Self, params: &ResearchParams) -> Self {
        Self {
            memory_kib: if params.memory_kib > 0 {
                params.memory_kib
            } else {
                defaults.memory_kib
            },
            block_size: if params.block_size > 0 {
                params.block_size
            } else {
                defaults.block_size
            },
            fan_in: defaults.fan_in,
            graph: defaults.graph,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.memory_kib < 1024 {
            return Err("memory_kib must be >= 1024".into());
        }
        if self.block_size < 16 || !self.block_size.is_power_of_two() {
            return Err("block_size must be power of two >= 16".into());
        }
        if self.fan_in < 2 || self.fan_in > 8 {
            return Err("fan_in must be in 2..=8".into());
        }
        if self.num_blocks() < 64 {
            return Err("num_blocks too small".into());
        }
        Ok(())
    }

    pub fn memory_targets_mib() -> &'static [usize] {
        &MEM_TARGETS
    }
}
