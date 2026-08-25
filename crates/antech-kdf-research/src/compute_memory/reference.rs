//! Clarity-first reference engine for the compute-memory construction.

use super::config::ComputeMemoryConfig;
use super::core::derive_reference;
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

/// Reference implementation — readable control flow, identical digests to optimized.
pub struct ReferenceEngine {
    pub defaults: ComputeMemoryConfig,
}

impl ReferenceEngine {
    pub fn new() -> Self {
        Self {
            defaults: ComputeMemoryConfig::default(),
        }
    }

    pub fn with_config(defaults: ComputeMemoryConfig) -> Self {
        Self { defaults }
    }
}

impl Default for ReferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for ReferenceEngine {
    fn name(&self) -> &'static str {
        "compute-memory-reference"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let cfg = ComputeMemoryConfig::resolve(&self.defaults, params);
        derive_reference(password, salt, &cfg)
    }
}
