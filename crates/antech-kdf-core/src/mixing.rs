//! Cryptographic mixing for the compute-memory construction.

use crate::config::MIX_ROUNDS;
use sha2::{Digest, Sha256};

/// Domain separator for node-0 phantom material (fixed protocol bytes).
pub const DOMAIN_NODE0: &[u8] = b"antech-compute-memory-v2-node0";

const C1: u64 = 0xBF58476D1CE4E5B9;
const C2: u64 = 0x94D049BB133111EB;
const GOLDEN: u64 = 0x9E3779B97F4A7C15;

pub fn state_from_seed(seed: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes(seed[0..8].try_into().unwrap()),
        u64::from_le_bytes(seed[8..16].try_into().unwrap()),
        u64::from_le_bytes(seed[16..24].try_into().unwrap()),
        u64::from_le_bytes(seed[24..32].try_into().unwrap()),
    ]
}

pub fn node0_material(seed: &[u8; 32], parent_slot: u32, block_size: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_NODE0);
    hasher.update(seed);
    hasher.update(parent_slot.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = vec![0u8; block_size];
    let copy = block_size.min(32);
    out[..copy].copy_from_slice(&digest[..copy]);
    if block_size > 32 {
        let mut s = state_from_seed(&{
            let mut k = [0u8; 32];
            k.copy_from_slice(&digest);
            k
        });
        let mut off = 32;
        while off < block_size {
            s[0] = s[0].wrapping_add(GOLDEN).wrapping_mul(C1);
            s[1] ^= s[0].rotate_left(17);
            s[2] = s[2].wrapping_add(s[1]).wrapping_mul(C2);
            s[3] ^= s[2].rotate_left(41);
            for (i, word) in s.iter().enumerate() {
                let bytes = word.to_le_bytes();
                let start = off + i * 8;
                if start >= block_size {
                    break;
                }
                let end = (start + 8).min(block_size);
                out[start..end].copy_from_slice(&bytes[..end - start]);
            }
            off += 32;
        }
    }
    out
}

#[inline(always)]
pub fn mix_pair_words(state: &mut [u64; 4], a: &[u64; 4], b: &[u64; 4]) {
    let (b10, b11, b12, b13) = (a[0], a[1], a[2], a[3]);
    let (b20, b21, b22, b23) = (b[0], b[1], b[2], b[3]);
    for r in 0..MIX_ROUNDS {
        let rr = r as u64;
        state[0] = state[0]
            .wrapping_add(b10 ^ b20.wrapping_add(rr))
            .rotate_left(13)
            ^ state[3];
        state[1] = state[1]
            .wrapping_add(b11.wrapping_mul(C1) ^ b21)
            .rotate_left(17)
            ^ state[0];
        state[2] = state[2]
            .wrapping_add(b12 ^ b22.wrapping_mul(C2))
            .rotate_left(19)
            ^ state[1];
        state[3] = state[3]
            .wrapping_add(b13.wrapping_add(b23) ^ GOLDEN.wrapping_mul(rr + 1))
            .rotate_left(23)
            ^ state[2];
    }
}

#[inline(always)]
pub fn mix_parent_words(state: &mut [u64; 4], views: &[[u64; 4]], n: usize) {
    if n == 0 {
        return;
    }
    if n == 1 {
        mix_pair_words(state, &views[0], &views[0]);
        return;
    }
    let mut i = 0;
    while i + 1 < n {
        mix_pair_words(state, &views[i], &views[i + 1]);
        i += 2;
    }
    if i < n {
        mix_pair_words(state, &views[i], &views[i]);
    }
}

#[inline(always)]
pub fn mix_pair(state: &mut [u64; 4], block1: &[u8], block2: &[u8]) {
    mix_pair_words(
        state,
        &[
            load_u64(block1, 0),
            load_u64(block1, 8),
            load_u64(block1, 16),
            load_u64(block1, 24),
        ],
        &[
            load_u64(block2, 0),
            load_u64(block2, 8),
            load_u64(block2, 16),
            load_u64(block2, 24),
        ],
    );
}

#[inline(always)]
fn load_u64(block: &[u8], offset: usize) -> u64 {
    if offset + 8 <= block.len() {
        u64::from_le_bytes(block[offset..offset + 8].try_into().unwrap())
    } else {
        0
    }
}

pub fn state_to_block(state: &[u64; 4], block: &mut [u8]) {
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        for (j, b) in bytes.iter().enumerate() {
            let idx = i * 8 + j;
            if idx < block.len() {
                block[idx] = *b;
            }
        }
    }
}
