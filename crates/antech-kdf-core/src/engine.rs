//! Canonical compute-memory derivation engine.

use crate::graph::{self, MAX_PARENTS};
use crate::memory::FrontierRing;
use crate::mixing::{mix_pair_words, mix_parent_words};
use crate::state::{
    bind_seed_with_inputs, finalize, mix_parent_views, phantom_block, seed_to_state,
    state_to_block_fast, xor_state_into_block_fast,
};
use crate::traits::KdfEngine;
use antech_kdf_types::{Algorithm, AntechConfig, DeriveInputs, KdfError};
use std::cell::RefCell;

const MAX_BLOCK: usize = 64; // must match antech_kdf_types::BlockSize::MAX_BYTES

thread_local! {
    /// Reused CombinedFrontier word buffer (defender asymmetry vs per-guess alloc+memset).
    static WORD_BUF: RefCell<Vec<[u64; 4]>> = const { RefCell::new(Vec::new()) };
}

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
        self.derive_with_inputs(password, salt, cfg, &DeriveInputs::default())
    }

    pub fn derive_with_inputs(
        &self,
        password: &[u8],
        salt: &[u8],
        cfg: &AntechConfig,
        inputs: &DeriveInputs,
    ) -> Result<Vec<u8>, KdfError> {
        cfg.validate()?;
        inputs.validate()?;
        if cfg.algorithm != Algorithm::Antech {
            return Err(KdfError::Derivation("unsupported algorithm".into()));
        }

        let block_size = cfg.block_size.as_bytes();
        if block_size > MAX_BLOCK {
            return Err(KdfError::Derivation(
                "block size exceeds engine stack scratch".into(),
            ));
        }

        // CombinedFrontier @ 32 B: word-packed walk (normative digests).
        if cfg.graph == antech_kdf_types::GraphKind::CombinedFrontier && block_size == 32 {
            return derive_combined_frontier_words(password, salt, cfg, inputs);
        }

        derive_generic_bytes(password, salt, cfg, inputs, block_size)
    }
}

fn derive_combined_frontier_words(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    inputs: &DeriveInputs,
) -> Result<Vec<u8>, KdfError> {
    let num_blocks = cfg.num_blocks();
    let period = cfg.critical_period();
    let tile_len = cfg.tile_len();
    let seed = bind_seed_with_inputs(password, salt, cfg, inputs);
    let mut state = seed_to_state(&seed);

    // CombinedFrontier node 0 always mixes two phantoms (slots 0 and 1).
    let mut phantoms = [[0u64; 4]; 2];
    for (slot, phantom) in phantoms.iter_mut().enumerate() {
        let mut raw = [0u8; 32];
        phantom_block(&seed, slot as u32, 32, &mut raw);
        *phantom = [
            u64::from_le_bytes(raw[0..8].try_into().unwrap()),
            u64::from_le_bytes(raw[8..16].try_into().unwrap()),
            u64::from_le_bytes(raw[16..24].try_into().unwrap()),
            u64::from_le_bytes(raw[24..32].try_into().unwrap()),
        ];
    }

    WORD_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        if buf.len() < num_blocks {
            buf.resize(num_blocks, [0u64; 4]);
        }
        let buf = &mut buf[..num_blocks];

        for i in 0..num_blocks {
            if i == 0 {
                mix_pair_words(&mut state, &phantoms[0], &phantoms[1]);
            } else {
                let local = graph::combined_local_parents(&state, i);
                gather_mix_words(&mut state, buf, local.as_slice());
                let remote =
                    graph::combined_remote_parents(&state, i, cfg.fan_in.get(), period, tile_len);
                gather_mix_words(&mut state, buf, remote.as_slice());
            }
            buf[i] = state;
            let (s1, s2) = graph::scatter_dests_from_state(&state, i);
            apply_scatter_words(&state, buf, i, s1, s2);
        }

        let mut last_bytes = [0u8; 32];
        for w in 0..4 {
            last_bytes[w * 8..(w + 1) * 8].copy_from_slice(&buf[num_blocks - 1][w].to_le_bytes());
        }
        let mut digest = finalize(&seed, &state, &last_bytes, cfg.graph);
        let out_len = cfg.output_length.as_bytes();
        if digest.len() > out_len {
            digest.truncate(out_len);
        } else if digest.len() < out_len {
            digest.resize(out_len, 0);
        }
        Ok(digest)
    })
}

#[inline(always)]
fn gather_mix_words(state: &mut [u64; 4], buf: &[[u64; 4]], parents: &[usize]) {
    if parents.is_empty() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        for &p in parents {
            let ptr = buf.as_ptr().wrapping_add(p) as *const i8;
            // SAFETY: prefetch hint only.
            unsafe {
                core::arch::x86_64::_mm_prefetch(ptr, core::arch::x86_64::_MM_HINT_T0);
            }
        }
    }
    let mut views = [[0u64; 4]; MAX_PARENTS];
    let n = parents.len().min(MAX_PARENTS);
    for (k, &p) in parents.iter().take(n).enumerate() {
        views[k] = buf[p];
    }
    mix_parent_words(state, &views, n);
}

#[inline(always)]
fn apply_scatter_words(
    state: &[u64; 4],
    buf: &mut [[u64; 4]],
    i: usize,
    s1: Option<usize>,
    s2: Option<usize>,
) {
    for dest in [s1, s2].into_iter().flatten() {
        if dest < buf.len() && dest != i {
            buf[dest][0] ^= state[0];
            buf[dest][1] ^= state[1];
            buf[dest][2] ^= state[2];
            buf[dest][3] ^= state[3];
        }
    }
}

fn derive_generic_bytes(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    inputs: &DeriveInputs,
    block_size: usize,
) -> Result<Vec<u8>, KdfError> {
    let num_blocks = cfg.num_blocks();
    let period = cfg.critical_period();
    let tile_len = cfg.tile_len();
    let seed = bind_seed_with_inputs(password, salt, cfg, inputs);
    let mut buffer = vec![0u8; cfg.memory.as_bytes()];
    let mut state = seed_to_state(&seed);
    let mut ring = FrontierRing::new(block_size);

    let mut phantoms = [[0u8; MAX_BLOCK]; MAX_PARENTS];
    let fan = (cfg.fan_in.get() as usize).min(MAX_PARENTS);
    // CombinedFrontier node 0: always two phantoms (matches word-packed path).
    // Other graphs: fan_in phantoms.
    let node0_count = if cfg.graph == antech_kdf_types::GraphKind::CombinedFrontier {
        2
    } else {
        fan
    };
    for (slot, phantom) in phantoms.iter_mut().enumerate().take(node0_count) {
        phantom_block(&seed, slot as u32, block_size, &mut phantom[..block_size]);
    }

    for i in 0..num_blocks {
        if i == 0 {
            let mut views: [&[u8]; MAX_PARENTS] = [&[]; MAX_PARENTS];
            for slot in 0..node0_count {
                views[slot] = &phantoms[slot][..block_size];
            }
            mix_parent_views(&mut state, &views[..node0_count]);
        } else if cfg.graph == antech_kdf_types::GraphKind::CombinedFrontier {
            let local = graph::combined_local_parents(&state, i);
            gather_and_mix(&mut state, &buffer, &ring, block_size, local.as_slice());

            let remote =
                graph::combined_remote_parents(&state, i, cfg.fan_in.get(), period, tile_len);
            gather_and_mix(&mut state, &buffer, &ring, block_size, remote.as_slice());

            let (s1, s2) = graph::scatter_dests_from_state(&state, i);
            {
                let out = &mut buffer[i * block_size..(i + 1) * block_size];
                state_to_block_fast(&state, out);
                ring.push(i, out);
            }
            apply_scatter(&state, &mut buffer, block_size, num_blocks, i, s1, s2);
            continue;
        } else {
            let parents =
                graph::parents_for_node(cfg.graph, &state, i, cfg.fan_in.get(), period, tile_len);
            gather_and_mix(&mut state, &buffer, &ring, block_size, parents.as_slice());
            {
                let out = &mut buffer[i * block_size..(i + 1) * block_size];
                state_to_block_fast(&state, out);
                ring.push(i, out);
            }
            apply_scatter(
                &state,
                &mut buffer,
                block_size,
                num_blocks,
                i,
                parents.scatter_dest,
                parents.scatter_dest2,
            );
            continue;
        }

        {
            let out = &mut buffer[i * block_size..(i + 1) * block_size];
            state_to_block_fast(&state, out);
            ring.push(i, out);
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

#[inline(always)]
fn gather_and_mix(
    state: &mut [u64; 4],
    buffer: &[u8],
    ring: &FrontierRing,
    block_size: usize,
    parents: &[usize],
) {
    if parents.is_empty() {
        return;
    }
    let mut views: [&[u8]; MAX_PARENTS] = [&[]; MAX_PARENTS];
    let mut n_views = 0usize;
    #[cfg(target_arch = "x86_64")]
    {
        for &p in parents {
            let ptr = buffer.as_ptr().wrapping_add(p * block_size);
            // SAFETY: prefetch hint only; pointer is within `buffer`.
            unsafe {
                core::arch::x86_64::_mm_prefetch(ptr as *const i8, core::arch::x86_64::_MM_HINT_T0);
            }
        }
    }
    for &p in parents {
        views[n_views] = match ring.get(p) {
            Some(v) => v,
            None => &buffer[p * block_size..(p + 1) * block_size],
        };
        n_views += 1;
    }
    mix_parent_views(state, &views[..n_views]);
}

#[inline(always)]
fn apply_scatter(
    state: &[u64; 4],
    buffer: &mut [u8],
    block_size: usize,
    num_blocks: usize,
    i: usize,
    s1: Option<usize>,
    s2: Option<usize>,
) {
    for dest in [s1, s2].into_iter().flatten() {
        if dest < num_blocks && dest != i {
            xor_state_into_block_fast(
                state,
                &mut buffer[dest * block_size..(dest + 1) * block_size],
            );
        }
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
    fn deterministic_small_config() {
        // Use 1 MiB so Miri finishes in CI; digests remain deterministic.
        let cfg = AntechConfig::builder()
            .memory_kib(1024)
            .salt_length(16)
            .build()
            .unwrap();
        let engine = AntechEngine::new();
        let a = engine.derive(b"pwd", b"salt_16_bytes!!", &cfg).unwrap();
        let b = engine.derive(b"pwd", b"salt_16_bytes!!", &cfg).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "2×1MiB derive paths; single-derive Miri covers prefetch unsafe"
    )]
    fn word_path_matches_byte_path_1mib() {
        let cfg = AntechConfig::builder()
            .memory_mib(1)
            .graph(GraphKind::CombinedFrontier)
            .build()
            .unwrap();
        let engine = AntechEngine::new();
        let salt = b"salt_16_bytes!!";
        let word = engine.derive(b"match_words", salt, &cfg).unwrap();
        // Force byte path by using a temporary graph round-trip via generic with same logic:
        // re-derive through generic bytes by calling derive_generic_bytes directly.
        let byte =
            derive_generic_bytes(b"match_words", salt, &cfg, &DeriveInputs::default(), 32).unwrap();
        assert_eq!(word, byte);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "3×1MiB derives; covered by normal cargo test + single-derive Miri paths"
    )]
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
