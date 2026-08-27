//! Research-suite structural knobs (memory grids, TMTO fractions, worker counts).
//!
//! Protocol constants for the shipping KDF live in `antech_kdf_core` /
//! `antech_kdf_types`. This module only holds campaign schedules.

use antech_kdf_types::AntechConfig;

/// Working-memory grid used by research suites (MiB).
pub const MEMORY_TARGETS_MIB: [usize; 6] = [12, 16, 20, 24, 28, 32];

/// TMTO memory fractions evaluated by research suites.
pub const TMTO_FRACTIONS: [f64; 6] = [1.0, 0.75, 0.50, 0.25, 0.125, 0.0625];

/// CPU attacker worker counts.
pub const CPU_WORKER_COUNTS: [usize; 6] = [1, 2, 4, 8, 16, 32];

/// Default research working set (16 MiB) — matches production default.
pub const DEFAULT_MEMORY_KIB: u32 = 16 * 1024;

/// Alias kept for older campaign scripts.
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
            block_size: 32,
            fan_in: 2,
        }
    }
}

impl ComputeMemoryConfig {
    pub fn memory_kib(mut self, kib: u32) -> Self {
        self.memory_kib = kib;
        self
    }

    pub fn memory_mib(mut self, mib: u32) -> Self {
        self.memory_kib = mib.saturating_mul(1024);
        self
    }

    pub fn to_antech_config(&self) -> AntechConfig {
        AntechConfig::builder()
            .memory_kib(self.memory_kib as usize)
            .block_size(self.block_size as usize)
            .fan_in(self.fan_in)
            .build()
            .expect("research ComputeMemoryConfig maps to valid AntechConfig")
    }
}
