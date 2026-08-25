//! Variant D — combined preset (default mix rounds; primary comparison target).

use super::config::ComputeMemoryConfig;
use super::core::derive_optimized;
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

pub struct VariantD {
    pub defaults: ComputeMemoryConfig,
}

impl VariantD {
    pub fn new() -> Self {
        Self {
            defaults: ComputeMemoryConfig::default(),
        }
    }
}

impl Default for VariantD {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for VariantD {
    fn name(&self) -> &'static str {
        "variant-d-combined"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let cfg = ComputeMemoryConfig::resolve(&self.defaults, params);
        // Combined = same core as optimized defaults (graph + mix + writeback).
        derive_optimized(password, salt, &cfg)
    }
}
