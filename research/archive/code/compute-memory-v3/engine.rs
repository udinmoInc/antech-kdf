//! v3 derive engine — single in-order pass over num_blocks.

use super::config::ComputeMemoryV3Config;
use super::graph;
use super::state::{
    bind_seed_v3, finalize_v3, mix_parent_blocks, phantom_parents, state_from_seed, state_to_block,
    xor_state_into_block,
};
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

/// Optimized v3 engine (graph kind selected via config).
pub struct V3Engine {
    pub defaults: ComputeMemoryV3Config,
}

impl V3Engine {
    pub fn new(graph: super::config::GraphKind) -> Self {
        Self {
            defaults: ComputeMemoryV3Config::default().graph(graph),
        }
    }

    pub fn with_config(defaults: ComputeMemoryV3Config) -> Self {
        Self { defaults }
    }

    pub fn derive_cfg(
        &self,
        password: &[u8],
        salt: &[u8],
        cfg: &ComputeMemoryV3Config,
    ) -> Result<Vec<u8>, ResearchError> {
        cfg.validate().map_err(ResearchError::InvalidParameters)?;

        let seed = bind_seed_v3(password, salt, cfg);
        let block_size = cfg.block_size as usize;
        let num_blocks = cfg.num_blocks();
        let epoch_len = cfg.epoch_len();
        let mut buffer = vec![0u8; cfg.total_bytes()];
        let mut state = state_from_seed(&seed);

        for i in 0..num_blocks {
            let parents = graph::parents_for_node(cfg.graph, &state, i, cfg.fan_in, epoch_len);
            let parent_blocks = if i == 0 {
                phantom_parents(&seed, cfg.fan_in, block_size)
            } else {
                parents
                    .indices
                    .iter()
                    .map(|&p| buffer[p * block_size..(p + 1) * block_size].to_vec())
                    .collect()
            };

            mix_parent_blocks(&mut state, &parent_blocks);
            state_to_block(&state, &mut buffer[i * block_size..(i + 1) * block_size]);

            if let Some(dest) = parents.scatter_dest {
                if dest < num_blocks && dest != i {
                    xor_state_into_block(
                        &state,
                        &mut buffer[dest * block_size..(dest + 1) * block_size],
                    );
                }
            }
        }

        let last = &buffer[(num_blocks - 1) * block_size..num_blocks * block_size];
        Ok(finalize_v3(&seed, &state, last, cfg.graph))
    }
}

impl ResearchKdf for V3Engine {
    fn name(&self) -> &'static str {
        self.defaults.graph.label()
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let cfg = ComputeMemoryV3Config::resolve(&self.defaults, params);
        self.derive_cfg(password, salt, &cfg)
    }
}
