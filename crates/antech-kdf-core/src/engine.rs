//! Canonical compute-memory derivation engine.
//!
//! # Security notice
//!
//! This is the project's current Antech construction. Benchmark results do not
//! establish cryptographic security; independent review is still required.

use crate::graph::{self, MAX_PARENTS};
use crate::memory::FrontierRing;
use crate::state::{
    bind_seed, finalize, mix_parent_views, phantom_block, seed_to_state, state_to_block_fast,
    xor_state_into_block_fast,
};
use crate::traits::KdfEngine;
use antech_kdf_types::{Algorithm, AntechConfig, KdfError};

const MAX_BLOCK: usize = 64; // must match antech_kdf_types::BlockSize::MAX_BYTES

/// Canonical Antech compute-memory engine.
#[derive(Debug, Clone, Default)]
pub struct AntechEngine;

impl AntechEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        cfg: &AntechConfig,
    ) -> Result<Vec<u8>, KdfError> {
        cfg.validate()?;
        if cfg.algorithm != Algorithm::Antech {
            return Err(KdfError::Derivation("unsupported algorithm".into()));
        }

        let block_size = cfg.block_size.as_bytes();
        if block_size > MAX_BLOCK {
            return Err(KdfError::Derivation(
                "block size exceeds engine stack scratch".into(),
            ));
        }

        let num_blocks = cfg.num_blocks();
        let period = cfg.critical_period();
        let tile_len = cfg.tile_len();
        let seed = bind_seed(password, salt, cfg);
        let mut buffer = vec![0u8; cfg.memory.as_bytes()];
        let mut state = seed_to_state(&seed);
        let mut ring = FrontierRing::new(block_size);

        let mut phantoms = [[0u8; MAX_BLOCK]; MAX_PARENTS];
        let fan = (cfg.fan_in.get() as usize).min(MAX_PARENTS);
        for (slot, phantom) in phantoms.iter_mut().enumerate().take(fan) {
            phantom_block(&seed, slot as u32, block_size, &mut phantom[..block_size]);
        }

        for i in 0..num_blocks {
            let parents =
                graph::parents_for_node(cfg.graph, &state, i, cfg.fan_in.get(), period, tile_len);

            let mut views: [&[u8]; MAX_PARENTS] = [&[]; MAX_PARENTS];
            let mut n_views = 0usize;

            if i == 0 {
                for slot in 0..fan {
                    views[slot] = &phantoms[slot][..block_size];
                }
                n_views = fan;
            } else {
                #[cfg(target_arch = "x86_64")]
                {
                    for k in 0..parents.len {
                        let p = parents.indices[k];
                        let ptr = buffer.as_ptr().wrapping_add(p * block_size);
                        // SAFETY: prefetch hint only; pointer is within `buffer`.
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
        let mut digest = finalize(&seed, &state, last, cfg.graph);
        let out_len = cfg.output_length.as_bytes();
        if digest.len() > out_len {
            digest.truncate(out_len);
        } else if digest.len() < out_len {
            digest.resize(out_len, 0);
        }
        Ok(digest)
    }
}

impl KdfEngine for AntechEngine {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Antech
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        config: &AntechConfig,
    ) -> Result<Vec<u8>, KdfError> {
        AntechEngine::derive(self, password, salt, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antech_kdf_types::GraphKind;

    #[test]
    fn deterministic_default_config() {
        let cfg = AntechConfig::default();
        let engine = AntechEngine::new();
        let a = engine.derive(b"pwd", b"salt_16_bytes!!", &cfg).unwrap();
        let b = engine.derive(b"pwd", b"salt_16_bytes!!", &cfg).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn graph_kinds_distinct() {
        let engine = AntechEngine::new();
        let salt = b"salt_16_bytes!!";
        let pwd = b"pwd";
        let a = engine
            .derive(
                pwd,
                salt,
                &AntechConfig::builder()
                    .graph(GraphKind::ReducedCriticalPath)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let b = engine
            .derive(
                pwd,
                salt,
                &AntechConfig::builder()
                    .graph(GraphKind::CacheLocality)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let c = engine
            .derive(
                pwd,
                salt,
                &AntechConfig::builder()
                    .graph(GraphKind::CombinedFrontier)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
    }
}
