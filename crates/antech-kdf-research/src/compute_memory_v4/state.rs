//! Live mixing state and seed binding for v4.

use super::config::{ComputeMemoryV4Config, GraphKind, V4_VERSION};
use crate::compute_memory::config::MIX_ROUNDS;
use crate::compute_memory::crypto_mixing::{mix_pair, node0_material};
use sha2::{Digest, Sha256};

pub use crate::compute_memory::crypto_mixing::{state_from_seed, state_to_block};

pub const DOMAIN_SEED: &[u8] = b"antech-compute-memory-v4-seed";
pub const DOMAIN_FINAL: &[u8] = b"antech-compute-memory-v4-final";

pub fn bind_seed_v4(password: &[u8], salt: &[u8], cfg: &ComputeMemoryV4Config) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEED);
    hasher.update(V4_VERSION.to_le_bytes());
    hasher.update(graph_tag(cfg.graph).to_le_bytes());
    hasher.update((password.len() as u32).to_le_bytes());
    hasher.update(password);
    hasher.update((salt.len() as u32).to_le_bytes());
    hasher.update(salt);
    hasher.update(cfg.memory_kib.to_le_bytes());
    hasher.update(cfg.block_size.to_le_bytes());
    hasher.update(cfg.fan_in.to_le_bytes());
    hasher.update(MIX_ROUNDS.to_le_bytes());
    hasher.update((cfg.critical_period() as u32).to_le_bytes());
    hasher.update((cfg.tile_len() as u32).to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn graph_tag(kind: GraphKind) -> u32 {
    match kind {
        GraphKind::ReducedCriticalPath => 1,
        GraphKind::CacheLocality => 2,
        GraphKind::CombinedFrontier => 3,
    }
}

pub fn phantom_block(seed: &[u8; 32], slot: u32, block_size: usize, out: &mut [u8]) {
    let mat = node0_material(seed, slot, block_size);
    let n = out.len().min(mat.len());
    out[..n].copy_from_slice(&mat[..n]);
    if n < out.len() {
        out[n..].fill(0);
    }
}

pub fn finalize_v4(
    seed: &[u8; 32],
    state: &[u64; 4],
    last_block: &[u8],
    kind: GraphKind,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_FINAL);
    hasher.update(V4_VERSION.to_le_bytes());
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
    xor_state_into_block_fast(state, block);
}

/// Hot-path XOR; specializes the common 32-byte block.
#[inline(always)]
pub fn xor_state_into_block_fast(state: &[u64; 4], block: &mut [u8]) {
    if block.len() >= 32 {
        for i in 0..4 {
            let bytes = state[i].to_le_bytes();
            let off = i * 8;
            block[off] ^= bytes[0];
            block[off + 1] ^= bytes[1];
            block[off + 2] ^= bytes[2];
            block[off + 3] ^= bytes[3];
            block[off + 4] ^= bytes[4];
            block[off + 5] ^= bytes[5];
            block[off + 6] ^= bytes[6];
            block[off + 7] ^= bytes[7];
        }
        return;
    }
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

/// Hot-path state→block; specializes the common 32-byte block.
#[inline(always)]
pub fn state_to_block_fast(state: &[u64; 4], block: &mut [u8]) {
    if block.len() >= 32 {
        for i in 0..4 {
            block[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
        }
        return;
    }
    state_to_block(state, block);
}

/// Allocation-free parent fold (pairs of block views).
#[inline(always)]
pub fn mix_parent_views(state: &mut [u64; 4], parents: &[&[u8]]) {
    if parents.is_empty() {
        return;
    }
    if parents.len() == 1 {
        mix_pair(state, parents[0], parents[0]);
        return;
    }
    let mut i = 0;
    while i + 1 < parents.len() {
        mix_pair(state, parents[i], parents[i + 1]);
        i += 2;
    }
    if i < parents.len() {
        mix_pair(state, parents[i], parents[i]);
    }
}
