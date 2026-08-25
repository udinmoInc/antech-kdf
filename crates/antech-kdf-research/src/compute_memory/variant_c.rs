//! Variant C — pebble-graph default (same core graph, baseline mix rounds).

use super::config::ComputeMemoryConfig;
use super::core::derive_optimized;
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

pub struct VariantC {
    pub defaults: ComputeMemoryConfig,
}

impl VariantC {
    pub fn new() -> Self {
        Self {
            defaults: ComputeMemoryConfig::default().mix_rounds(3),
        }
    }
}

impl Default for VariantC {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for VariantC {
    fn name(&self) -> &'static str {
        "variant-c-recomputation-graph"
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
