//! v4 derive engine — allocation-free hot path over num_blocks.

use super::config::ComputeMemoryV4Config;
use super::frontier::FrontierRing;
use super::graph::{self, MAX_PARENTS};
use super::state::{
    bind_seed_v4, finalize_v4, mix_parent_views, phantom_block, state_from_seed,
    state_to_block_fast, xor_state_into_block_fast,
};
use crate::candidates::cand_004::{ResearchError, ResearchKdf, ResearchParams};

/// Max block size supported on the stack scratch (protocol uses 32).
const MAX_BLOCK: usize = 64;

pub struct V4Engine {
    pub defaults: ComputeMemoryV4Config,
}

impl V4Engine {
    pub fn new(graph: super::config::GraphKind) -> Self {
        Self {
            defaults: ComputeMemoryV4Config::default().graph(graph),
        }
    }

    pub fn with_config(defaults: ComputeMemoryV4Config) -> Self {
        Self { defaults }
    }

    pub fn derive_cfg(
        &self,
        password: &[u8],
        salt: &[u8],
        cfg: &ComputeMemoryV4Config,
    ) -> Result<Vec<u8>, ResearchError> {
        cfg.validate()
            .map_err(ResearchError::InvalidParameters)?;

        let seed = bind_seed_v4(password, salt, cfg);
        let block_size = cfg.block_size as usize;
        if block_size > MAX_BLOCK {
            return Err(ResearchError::InvalidParameters(
                "block_size exceeds v4 stack scratch".into(),
            ));
        }
        let num_blocks = cfg.num_blocks();
        let period = cfg.critical_period();
        let tile_len = cfg.tile_len();
        let mut buffer = vec![0u8; cfg.total_bytes()];
        let mut state = state_from_seed(&seed);
        let mut ring = FrontierRing::new(block_size);

        let mut phantoms = [[0u8; MAX_BLOCK]; MAX_PARENTS];
        let fan = (cfg.fan_in as usize).min(MAX_PARENTS);
        for slot in 0..fan {
            phantom_block(&seed, slot as u32, block_size, &mut phantoms[slot][..block_size]);
        }

        for i in 0..num_blocks {
            let parents =
                graph::parents_for_node(cfg.graph, &state, i, cfg.fan_in, period, tile_len);

            let mut views: [&[u8]; MAX_PARENTS] = [&[]; MAX_PARENTS];
            let mut n_views = 0usize;

            if i == 0 {
                for slot in 0..fan {
                    views[slot] = &phantoms[slot][..block_size];
                }
                n_views = fan;
            } else {
                // Zero-copy: parent blocks are either in the frontier ring or
                // earlier in `buffer` (indices < i). Scatter writes happen after mix.
                #[cfg(target_arch = "x86_64")]
                {
                    for k in 0..parents.len {
                        let p = parents.indices[k];
                        let ptr = buffer.as_ptr().wrapping_add(p * block_size);
                        unsafe {
                            core::arch::x86_64::_mm_prefetch(
                                ptr as *const i8,
                                core::arch::x86_64::_MM_HINT_T0,
                            );
                        }
                    }
                }
                for k in 0..parents.len {
                    let p = parents.indices[k];
                    views[n_views] = match ring.get(p) {
                        Some(v) => v,
                        None => &buffer[p * block_size..(p + 1) * block_size],
                    };
                    n_views += 1;
                }
            }

            mix_parent_views(&mut state, &views[..n_views]);

            {
                let out = &mut buffer[i * block_size..(i + 1) * block_size];
                state_to_block_fast(&state, out);
                ring.push(i, out);
            }

            if let Some(dest) = parents.scatter_dest {
                if dest < num_blocks && dest != i {
                    xor_state_into_block_fast(
                        &state,
                        &mut buffer[dest * block_size..(dest + 1) * block_size],
                    );
                }
            }
            if let Some(dest) = parents.scatter_dest2 {
                if dest < num_blocks && dest != i {
                    xor_state_into_block_fast(
                        &state,
                        &mut buffer[dest * block_size..(dest + 1) * block_size],
                    );
                }
            }
        }

        let last = &buffer[(num_blocks - 1) * block_size..num_blocks * block_size];
        Ok(finalize_v4(&seed, &state, last, cfg.graph))
    }
}

impl ResearchKdf for V4Engine {
    fn name(&self) -> &'static str {
        self.defaults.graph.label()
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let cfg = ComputeMemoryV4Config::resolve(&self.defaults, params);
        self.derive_cfg(password, salt, &cfg)
    }
}
