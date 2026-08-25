//! Tunable parameters for the compute-memory research construction.
//!
//! All runtime knobs flow through this type (or via [`AntechConfig`] /
//! [`ResearchParams`] conversion). Nothing algorithmic is hardcoded in the
//! derive loop beyond protocol domain labels.

use antech_kdf_types::AntechConfig;
use crate::candidates::cand_004::ResearchParams;

/// Working-memory grid used by the research suite (MiB).
pub const MEMORY_TARGETS_MIB: [usize; 6] = [12, 16, 20, 24, 28, 32];

/// TMTO memory fractions evaluated by the research suite.
pub const TMTO_FRACTIONS: [f64; 6] = [1.0, 0.75, 0.50, 0.25, 0.125, 0.0625];

/// CPU attacker worker counts.
pub const CPU_WORKER_COUNTS: [usize; 6] = [1, 2, 4, 8, 16, 32];

/// Default sequential depth — meaningful per-step work, not a giant empty loop.
pub const DEFAULT_DEPENDENCY_DEPTH: u32 = 4096;

/// Default ARX mix rounds applied per state transition.
pub const DEFAULT_MIX_ROUNDS: u32 = 4;

/// Default fill-segment size (bytes). Larger segments cut SHA-256 init cost
/// while keeping password/salt binding via the segment key.
pub const DEFAULT_SEGMENT_BYTES: u32 = 1024;

/// Default block size (bytes) — one SHA-256 digest.
pub const DEFAULT_BLOCK_SIZE: u32 = 32;

/// Default pass count.
pub const DEFAULT_PASSES: u32 = 1;

/// Stride for the final memory-coverage fold (every Nth block).
/// Ensures the full working set is committed without a DRAM-saturating sweep.
pub const DEFAULT_FOLD_STRIDE: u32 = 4;

/// Default research working set (16 MiB).
pub const DEFAULT_MEMORY_KIB: u32 = 16 * 1024;

/// Fully resolved compute-memory configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeMemoryConfig {
    pub memory_kib: u32,
    pub passes: u32,
    pub dependency_depth: u32,
    pub block_size: u32,
    pub mix_rounds: u32,
    pub segment_bytes: u32,
    pub fold_stride: u32,
}

impl Default for ComputeMemoryConfig {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            passes: DEFAULT_PASSES,
            dependency_depth: DEFAULT_DEPENDENCY_DEPTH,
            block_size: DEFAULT_BLOCK_SIZE,
            mix_rounds: DEFAULT_MIX_ROUNDS,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
            fold_stride: DEFAULT_FOLD_STRIDE,
        }
    }
}

impl ComputeMemoryConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn memory_mib(mut self, mib: u32) -> Self {
        self.memory_kib = mib.saturating_mul(1024);
        self
    }

    pub fn memory_kib(mut self, kib: u32) -> Self {
        self.memory_kib = kib;
        self
    }

    pub fn passes(mut self, passes: u32) -> Self {
        self.passes = passes;
        self
    }

    pub fn dependency_depth(mut self, depth: u32) -> Self {
        self.dependency_depth = depth;
        self
    }

    pub fn block_size(mut self, bytes: u32) -> Self {
        self.block_size = bytes;
        self
    }

    pub fn mix_rounds(mut self, rounds: u32) -> Self {
        self.mix_rounds = rounds;
        self
    }

    pub fn segment_bytes(mut self, bytes: u32) -> Self {
        self.segment_bytes = bytes;
        self
    }

    pub fn fold_stride(mut self, stride: u32) -> Self {
        self.fold_stride = stride;
        self
    }

    pub fn total_bytes(&self) -> usize {
        (self.memory_kib as usize).saturating_mul(1024)
    }

    pub fn num_blocks(&self) -> usize {
        let bs = self.block_size.max(1) as usize;
        self.total_bytes() / bs
    }

    /// Map production [`AntechConfig`] fields into research knobs.
    /// Extra research-only fields keep their defaults.
    pub fn from_antech_config(config: &AntechConfig) -> Self {
        Self {
            memory_kib: config.memory.as_kib() as u32,
            passes: config.passes.get(),
            dependency_depth: config.dependency_depth.get(),
            block_size: config.block_size.as_bytes() as u32,
            mix_rounds: DEFAULT_MIX_ROUNDS,
            segment_bytes: DEFAULT_SEGMENT_BYTES,
            fold_stride: DEFAULT_FOLD_STRIDE,
        }
    }

    /// Resolve against a [`ResearchParams`] overlay (zero means “keep default”).
    pub fn resolve(defaults: &Self, params: &ResearchParams) -> Self {
        Self {
            memory_kib: if params.memory_kib > 0 {
                params.memory_kib
            } else {
                defaults.memory_kib
            },
            passes: if params.passes > 0 {
                params.passes
            } else {
                defaults.passes
            },
            dependency_depth: if params.dependency_depth > 0 {
                params.dependency_depth
            } else {
                defaults.dependency_depth
            },
            block_size: if params.block_size > 0 {
                params.block_size
            } else {
                defaults.block_size
            },
            mix_rounds: defaults.mix_rounds,
            segment_bytes: defaults.segment_bytes,
            fold_stride: defaults.fold_stride,
        }
    }

    pub fn to_research_params(&self) -> ResearchParams {
        ResearchParams {
            memory_kib: self.memory_kib,
            passes: self.passes,
            dependency_depth: self.dependency_depth,
            block_size: self.block_size,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.memory_kib < 1024 {
            return Err("memory_kib must be at least 1024 (1 MiB)".into());
        }
        if self.passes < 1 {
            return Err("passes must be >= 1".into());
        }
        if self.dependency_depth < 10 {
            return Err("dependency_depth must be >= 10".into());
        }
        if self.block_size < 16 || !self.block_size.is_power_of_two() {
            return Err("block_size must be a power of two >= 16".into());
        }
        if self.mix_rounds < 1 {
            return Err("mix_rounds must be >= 1".into());
        }
        if self.segment_bytes < self.block_size
            || self.segment_bytes % self.block_size != 0
        {
            return Err("segment_bytes must be a multiple of block_size".into());
        }
        if self.fold_stride < 1 {
            return Err("fold_stride must be >= 1".into());
        }
        if self.total_bytes() % self.block_size as usize != 0 {
            return Err("memory size must be a multiple of block_size".into());
        }
        Ok(())
    }
}

impl From<&AntechConfig> for ComputeMemoryConfig {
    fn from(config: &AntechConfig) -> Self {
        Self::from_antech_config(config)
    }
}

impl From<&ResearchParams> for ComputeMemoryConfig {
    fn from(params: &ResearchParams) -> Self {
        Self::resolve(&Self::default(), params)
    }
}
