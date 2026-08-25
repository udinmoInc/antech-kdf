//! Structural configuration for compute-memory v3.
//!
//! Work = one traversal of `num_blocks` DAG nodes. Graph *kind* changes
//! dependency shape (and thus contention / TMTO), not iteration count.

use crate::candidates::cand_004::ResearchParams;
use crate::compute_memory::config::{
    DEFAULT_BLOCK_SIZE, DEFAULT_FAN_IN, DEFAULT_MEMORY_KIB, MEMORY_TARGETS_MIB as MEM_TARGETS,
};

pub use crate::compute_memory::config::{
    CPU_WORKER_COUNTS, DEFAULT_MEMORY_KIB as V3_DEFAULT_MEMORY_KIB, MEMORY_TARGETS_MIB,
    TMTO_FRACTIONS,
};

/// Re-export under the expected name for suite code.
pub const DEFAULT_MEMORY_MIB: u32 = DEFAULT_MEMORY_KIB / 1024;

/// Construction version bound into the seed.
pub const V3_VERSION: u32 = 3;

/// Frontier width for narrow-frontier variant (protocol constant).
pub const FRONTIER_WIDTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphKind {
    /// A — Sequential-cut: epoch checkpoints + far back-edges.
    SequentialCut,
    /// B — Recursive power-of-two / interval parents.
    Recursive,
    /// C — Narrow frontier + mandatory remote gather/scatter.
    NarrowFrontier,
}

impl GraphKind {
    pub fn label(self) -> &'static str {
        match self {
            GraphKind::SequentialCut => "v3-a-sequential-cut",
            GraphKind::Recursive => "v3-b-recursive",
            GraphKind::NarrowFrontier => "v3-c-narrow-frontier",
        }
    }

    pub fn all() -> [GraphKind; 3] {
        [
            GraphKind::SequentialCut,
            GraphKind::Recursive,
            GraphKind::NarrowFrontier,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeMemoryV3Config {
    pub memory_kib: u32,
    pub block_size: u32,
    pub fan_in: u32,
    pub graph: GraphKind,
}

impl Default for ComputeMemoryV3Config {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            block_size: DEFAULT_BLOCK_SIZE,
            fan_in: DEFAULT_FAN_IN,
            graph: GraphKind::NarrowFrontier,
        }
    }
}

impl ComputeMemoryV3Config {
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

    /// Epoch length for sequential-cut: √n (structure-derived, not a user work knob).
    pub fn epoch_len(&self) -> usize {
        let n = self.num_blocks();
        let root = (n as f64).sqrt() as usize;
        root.max(16).min(n.max(1))
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
        if !(12..=32).contains(&(self.memory_kib / 1024)) && self.memory_kib != 1024 {
            // Allow 1 MiB for unit tests; production research targets 12–32.
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
