//! Variant B — lighter mix, same sequential state-dependent memory graph.

use super::config::ComputeMemoryConfig;
use super::core::derive_optimized;
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

pub struct VariantB {
    pub defaults: ComputeMemoryConfig,
}

impl VariantB {
    pub fn new() -> Self {
        Self {
            defaults: ComputeMemoryConfig::default().mix_rounds(2),
        }
    }
}

impl Default for VariantB {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for VariantB {
    fn name(&self) -> &'static str {
        "variant-b-state-dependent"
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
