//! Named research variants A/B/C for v4.

use super::config::{ComputeMemoryV4Config, GraphKind};
use super::engine::V4Engine;
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

macro_rules! v4_variant {
    ($name:ident, $kind:expr, $label:expr) => {
        pub struct $name {
            engine: V4Engine,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    engine: V4Engine::new($kind),
                }
            }

            pub fn config(&self) -> ComputeMemoryV4Config {
                self.engine.defaults
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ResearchKdf for $name {
            fn name(&self) -> &'static str {
                $label
            }

            fn derive(
                &self,
                password: &[u8],
                salt: &[u8],
                params: &ResearchParams,
            ) -> Result<Vec<u8>, ResearchError> {
                self.engine.derive(password, salt, params)
            }
        }
    };
}

v4_variant!(
    VariantA,
    GraphKind::ReducedCriticalPath,
    "v4-a-reduced-critical-path"
);
v4_variant!(VariantB, GraphKind::CacheLocality, "v4-b-cache-locality");
v4_variant!(
    VariantC,
    GraphKind::CombinedFrontier,
    "v4-c-combined-frontier"
);
