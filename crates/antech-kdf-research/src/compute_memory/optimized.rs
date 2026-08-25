//! Optimized research engine — same digests as the reference path.

use super::config::ComputeMemoryConfig;
use super::core::{derive_optimized, derive_sparse};
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

/// Optimized research implementation used for attacker / TMTO / GPU harnesses.
pub struct OptimizedEngine {
    pub defaults: ComputeMemoryConfig,
}

impl OptimizedEngine {
    pub fn new() -> Self {
        Self {
            defaults: ComputeMemoryConfig::default(),
        }
    }

    pub fn with_config(defaults: ComputeMemoryConfig) -> Self {
        Self { defaults }
    }

    /// Derive under a restricted resident-block fraction (TMTO attacker model).
    pub fn derive_tmto(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
        memory_fraction: f64,
    ) -> Result<Vec<u8>, ResearchError> {
        let cfg = ComputeMemoryConfig::resolve(&self.defaults, params);
        derive_sparse(password, salt, &cfg, memory_fraction)
    }
}

impl Default for OptimizedEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for OptimizedEngine {
    fn name(&self) -> &'static str {
        "compute-memory-optimized"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let cfg = ComputeMemoryConfig::resolve(&self.defaults, params);
        derive_optimized(password, salt, &cfg)
    }
}
