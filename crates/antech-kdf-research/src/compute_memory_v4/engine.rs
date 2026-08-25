//! v4 derive engine — delegates to the canonical core implementation.

use super::config::{resolve_v4_config, ComputeMemoryV4Config};
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};
use antech_kdf_core::AntechEngine;
use antech_kdf_types::AntechConfig;

pub struct V4Engine {
    pub defaults: ComputeMemoryV4Config,
    core: AntechEngine,
}

impl V4Engine {
    pub fn new(graph: antech_kdf_types::GraphKind) -> Self {
        Self {
            defaults: AntechConfig::default().with_graph(graph),
            core: AntechEngine::new(),
        }
    }

    pub fn with_config(defaults: ComputeMemoryV4Config) -> Self {
        Self {
            defaults,
            core: AntechEngine::new(),
        }
    }

    pub fn derive_cfg(
        &self,
        password: &[u8],
        salt: &[u8],
        cfg: &ComputeMemoryV4Config,
    ) -> Result<Vec<u8>, ResearchError> {
        cfg.validate()
            .map_err(|e| ResearchError::InvalidParameters(e.to_string()))?;
        self.core
            .derive(password, salt, cfg)
            .map_err(|e| ResearchError::DerivationError(e.to_string()))
    }
}

impl ResearchKdf for V4Engine {
    fn name(&self) -> &'static str {
        self.defaults.graph.as_str()
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let cfg = resolve_v4_config(&self.defaults, params);
        self.derive_cfg(password, salt, &cfg)
    }
}
