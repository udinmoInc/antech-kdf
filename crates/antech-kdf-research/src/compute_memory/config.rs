//! Structural configuration for the compute-memory v2 construction.
//!
//! Total work is **not** a user-selected depth/iteration count. It is exactly
//! one traversal of the dependency DAG whose node count is
//! `memory_bytes / block_size`, with per-node fan-in fixed by graph structure.
//!
//! Tunables: `memory_kib`, `block_size`, `fan_in`.
//! Protocol constants (not work knobs): version label, ARX mix rounds.

use antech_kdf_types::AntechConfig;
use crate::candidates::cand_004::ResearchParams;

/// Working-memory grid used by the research suite (MiB).
pub const MEMORY_TARGETS_MIB: [usize; 6] = [12, 16, 20, 24, 28, 32];

/// TMTO memory fractions evaluated by the research suite.
pub const TMTO_FRACTIONS: [f64; 6] = [1.0, 0.75, 0.50, 0.25, 0.125, 0.0625];

/// CPU attacker worker counts.
pub const CPU_WORKER_COUNTS: [usize; 6] = [1, 2, 4, 8, 16, 32];

/// Construction version bound into the seed (protocol constant).
pub const CONSTRUCTION_VERSION: u32 = 2;

/// Cryptographic ARX diffusion rounds per node (protocol constant — not a work knob).
pub const MIX_ROUNDS: u32 = 4;

/// Default block size (bytes).
pub const DEFAULT_BLOCK_SIZE: u32 = 32;

/// Default graph fan-in (parents mixed into each node).
pub const DEFAULT_FAN_IN: u32 = 2;

/// Default research working set (16 MiB).
pub const DEFAULT_MEMORY_KIB: u32 = 16 * 1024;

/// Fully resolved structural configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeMemoryConfig {
    pub memory_kib: u32,
    pub block_size: u32,
    pub fan_in: u32,
}

impl Default for ComputeMemoryConfig {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            block_size: DEFAULT_BLOCK_SIZE,
            fan_in: DEFAULT_FAN_IN,
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

    pub fn block_size(mut self, bytes: u32) -> Self {
        self.block_size = bytes;
        self
    }

    pub fn fan_in(mut self, fan_in: u32) -> Self {
        self.fan_in = fan_in;
        self
    }

    pub fn total_bytes(&self) -> usize {
        (self.memory_kib as usize).saturating_mul(1024)
    }

    /// Number of DAG nodes — this *is* the work bound.
    pub fn num_blocks(&self) -> usize {
        let bs = self.block_size.max(1) as usize;
        self.total_bytes() / bs
    }

    /// Map production config: only structural fields (memory, block size).
    /// `dependency_depth` / `passes` from AntechConfig are intentionally ignored.
    pub fn from_antech_config(config: &AntechConfig) -> Self {
        Self {
            memory_kib: config.memory.as_kib() as u32,
            block_size: config.block_size.as_bytes() as u32,
            fan_in: DEFAULT_FAN_IN,
        }
    }

    /// Resolve against [`ResearchParams`]: only `memory_kib` and `block_size`.
    /// `dependency_depth` and `passes` are ignored (not part of this construction).
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
        }
    }

    /// Bridge to the shared research trait params (depth/passes unused → 0).
    pub fn to_research_params(&self) -> ResearchParams {
        ResearchParams {
            memory_kib: self.memory_kib,
            passes: 0,
            dependency_depth: 0,
            block_size: self.block_size,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.memory_kib < 1024 {
            return Err("memory_kib must be at least 1024 (1 MiB)".into());
        }
        if self.block_size < 16 || !self.block_size.is_power_of_two() {
            return Err("block_size must be a power of two >= 16".into());
        }
        if self.fan_in < 1 || self.fan_in > 8 {
            return Err("fan_in must be in 1..=8".into());
        }
        if self.total_bytes() % self.block_size as usize != 0 {
            return Err("memory size must be a multiple of block_size".into());
        }
        if self.num_blocks() < 16 {
            return Err("num_blocks too small for dependency graph".into());
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
