//! Variant A — fan-in 3 graph preset.

use super::config::ComputeMemoryConfig;
use super::core::derive_optimized;
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

pub struct VariantA {
    pub defaults: ComputeMemoryConfig,
}

impl VariantA {
    pub fn new() -> Self {
        Self {
            defaults: ComputeMemoryConfig::default().fan_in(3),
        }
    }
}

impl Default for VariantA {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for VariantA {
    fn name(&self) -> &'static str {
        "variant-a-compute-dependency"
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
