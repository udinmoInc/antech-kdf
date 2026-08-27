//! Seed binding, finalization, and hot-path state/block conversions.

use crate::config::CONSTRUCTION_VERSION;
use crate::mixing::{mix_pair, state_to_block};
use antech_kdf_types::{AntechConfig, DeriveInputs, GraphKind};
use sha2::{Digest, Sha256};

pub use crate::mixing::{node0_material, state_from_seed as seed_to_state};

/// Domain separators mixed into seed/final digests. Byte values are protocol-fixed.
pub const DOMAIN_SEED: &[u8] = b"antech-compute-memory-v4-seed";
pub const DOMAIN_FINAL: &[u8] = b"antech-compute-memory-v4-final";
/// Appended only when secret and/or associated data are supplied (not for legacy calls).
pub const DOMAIN_SEED_EXTRAS: &[u8] = b"antech-compute-memory-v4-extras";

/// Bind password, salt, and structural config into a 32-byte seed (no secret/AD).
pub fn bind_seed(password: &[u8], salt: &[u8], cfg: &AntechConfig) -> [u8; 32] {
    bind_seed_with_inputs(password, salt, cfg, &DeriveInputs::default())
}

/// Bind password, salt, config, and optional secret/AD.
///
/// When both secret and AD are [`None`], the digest matches [`bind_seed`] exactly
/// (existing hashes unchanged). Empty `Some([])` is distinct from [`None`].
pub fn bind_seed_with_inputs(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    inputs: &DeriveInputs,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEED);
    hasher.update(CONSTRUCTION_VERSION.to_le_bytes());
    hasher.update(cfg.graph.tag().to_le_bytes());
    hasher.update((password.len() as u32).to_le_bytes());
    hasher.update(password);
    hasher.update((salt.len() as u32).to_le_bytes());
    hasher.update(salt);
    hasher.update((cfg.memory.as_kib() as u32).to_le_bytes());
    hasher.update((cfg.block_size.as_bytes() as u32).to_le_bytes());
    hasher.update(cfg.fan_in.get().to_le_bytes());
    hasher.update(crate::config::MIX_ROUNDS.to_le_bytes());
    hasher.update((cfg.critical_period() as u32).to_le_bytes());
    hasher.update((cfg.tile_len() as u32).to_le_bytes());

    if inputs.has_extras() {
        hasher.update(DOMAIN_SEED_EXTRAS);
        match &inputs.secret {
            Some(secret) => {
                hasher.update([1u8]);
                hasher.update((secret.len() as u32).to_le_bytes());
                hasher.update(secret.expose());
            }
            None => {
                hasher.update([0u8]);
                hasher.update(0u32.to_le_bytes());
            }
        }
        match &inputs.associated_data {
            Some(ad) => {
                hasher.update([1u8]);
                hasher.update((ad.len() as u32).to_le_bytes());
                hasher.update(ad);
            }
            None => {
                hasher.update([0u8]);
                hasher.update(0u32.to_le_bytes());
            }
        }
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn phantom_block(seed: &[u8; 32], slot: u32, block_size: usize, out: &mut [u8]) {
    let mat = node0_material(seed, slot, block_size);
    let n = out.len().min(mat.len());
    out[..n].copy_from_slice(&mat[..n]);
    if n < out.len() {
        out[n..].fill(0);
    }
}

pub fn finalize(seed: &[u8; 32], state: &[u64; 4], last_block: &[u8], graph: GraphKind) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_FINAL);
    hasher.update(CONSTRUCTION_VERSION.to_le_bytes());
    hasher.update(graph.tag().to_le_bytes());
    hasher.update(seed);
    for w in state {
        hasher.update(w.to_le_bytes());
    }
    hasher.update(last_block);
    hasher.finalize().to_vec()
}

#[inline(always)]
pub fn xor_state_into_block_fast(state: &[u64; 4], block: &mut [u8]) {
    if block.len() >= 32 {
        for (i, word) in state.iter().enumerate().take(4) {
            let bytes = word.to_le_bytes();
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
