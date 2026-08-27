//! Named research variants A/B/C.

use super::config::{ComputeMemoryV3Config, GraphKind};
use super::engine::V3Engine;
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

macro_rules! v3_variant {
    ($name:ident, $kind:expr, $label:expr) => {
        pub struct $name {
            engine: V3Engine,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    engine: V3Engine::new($kind),
                }
            }

            pub fn config(&self) -> ComputeMemoryV3Config {
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

v3_variant!(VariantA, GraphKind::SequentialCut, "v3-a-sequential-cut");
v3_variant!(VariantB, GraphKind::Recursive, "v3-b-recursive");
v3_variant!(VariantC, GraphKind::NarrowFrontier, "v3-c-narrow-frontier");
