//! Live mixing state and seed binding for v3 (reuses v2 ARX mix).

use super::config::{ComputeMemoryV3Config, GraphKind, V3_VERSION};
use crate::compute_memory::config::MIX_ROUNDS;
use crate::compute_memory::crypto_mixing::node0_material;
use sha2::{Digest, Sha256};

pub use crate::compute_memory::crypto_mixing::{
    mix_parents as mix_parent_blocks, state_from_seed, state_to_block,
};

pub const DOMAIN_SEED: &[u8] = b"antech-compute-memory-v3-seed";
pub const DOMAIN_FINAL: &[u8] = b"antech-compute-memory-v3-final";

pub fn bind_seed_v3(password: &[u8], salt: &[u8], cfg: &ComputeMemoryV3Config) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEED);
    hasher.update(V3_VERSION.to_le_bytes());
    hasher.update(graph_tag(cfg.graph).to_le_bytes());
    hasher.update((password.len() as u32).to_le_bytes());
    hasher.update(password);
    hasher.update((salt.len() as u32).to_le_bytes());
    hasher.update(salt);
    hasher.update(cfg.memory_kib.to_le_bytes());
    hasher.update(cfg.block_size.to_le_bytes());
    hasher.update(cfg.fan_in.to_le_bytes());
    hasher.update(MIX_ROUNDS.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn graph_tag(kind: GraphKind) -> u32 {
    match kind {
        GraphKind::SequentialCut => 1,
        GraphKind::Recursive => 2,
        GraphKind::NarrowFrontier => 3,
    }
}

pub fn phantom_parents(seed: &[u8; 32], fan_in: u32, block_size: usize) -> Vec<Vec<u8>> {
    (0..fan_in)
        .map(|slot| node0_material(seed, slot, block_size))
        .collect()
}

pub fn finalize_v3(
    seed: &[u8; 32],
    state: &[u64; 4],
    last_block: &[u8],
    kind: GraphKind,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_FINAL);
    hasher.update(V3_VERSION.to_le_bytes());
    hasher.update(graph_tag(kind).to_le_bytes());
    hasher.update(seed);
    for w in state {
        hasher.update(w.to_le_bytes());
    }
    hasher.update(last_block);
    hasher.finalize().to_vec()
}

#[inline(always)]
pub fn xor_state_into_block(state: &[u64; 4], block: &mut [u8]) {
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        for (j, b) in bytes.iter().enumerate() {
            let idx = i * 8 + j;
            if idx < block.len() {
                block[idx] ^= b;
            }
        }
    }
}
