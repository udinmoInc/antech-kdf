//! Cryptographic mixing primitives for the compute-memory construction.
//!
//! Uses SHA-256 for domain-separated password/salt binding and finalization.
//! Per-step diffusion uses established ARX constants (SplitMix / SipHash-family
//! odd multipliers) rather than an ad-hoc giant empty loop.

use sha2::{Digest, Sha256};

/// Domain separator for the compute-memory research construction.
pub const DOMAIN_SEED: &[u8] = b"antech-compute-memory-v1-seed";
pub const DOMAIN_FILL: &[u8] = b"antech-compute-memory-v1-fill";
pub const DOMAIN_FINAL: &[u8] = b"antech-compute-memory-v1-final";

const C1: u64 = 0xBF58476D1CE4E5B9; // SplitMix64
const C2: u64 = 0x94D049BB133111EB; // SplitMix64
const GOLDEN: u64 = 0x9E3779B97F4A7C15;

/// Bind password + salt + parameters into a 32-byte seed via SHA-256.
pub fn bind_seed(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    depth: u32,
    passes: u32,
    block_size: u32,
    mix_rounds: u32,
    segment_bytes: u32,
    fold_stride: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEED);
    hasher.update((password.len() as u32).to_le_bytes());
    hasher.update(password);
    hasher.update((salt.len() as u32).to_le_bytes());
    hasher.update(salt);
    hasher.update(memory_kib.to_le_bytes());
    hasher.update(depth.to_le_bytes());
    hasher.update(passes.to_le_bytes());
    hasher.update(block_size.to_le_bytes());
    hasher.update(mix_rounds.to_le_bytes());
    hasher.update(segment_bytes.to_le_bytes());
    hasher.update(fold_stride.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derive the 4×u64 working state from the seed.
pub fn state_from_seed(seed: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes(seed[0..8].try_into().unwrap()),
        u64::from_le_bytes(seed[8..16].try_into().unwrap()),
        u64::from_le_bytes(seed[16..24].try_into().unwrap()),
        u64::from_le_bytes(seed[24..32].try_into().unwrap()),
    ]
}

/// Segment key for counter-mode fill: SHA-256(DOMAIN_FILL || seed || index).
pub fn segment_key(seed: &[u8; 32], segment_index: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_FILL);
    hasher.update(seed);
    hasher.update(segment_index.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Expand a 32-byte key into `out` using ARX (no extra SHA-256 per block).
/// Deterministic and password-bound through the segment key.
pub fn expand_segment(key: &[u8; 32], out: &mut [u8]) {
    let mut s = state_from_seed(key);
    let mut offset = 0;
    while offset < out.len() {
        // Four rounds of SplitMix-style ARX diffusion per 32-byte chunk.
        s[0] = s[0].wrapping_add(GOLDEN).wrapping_mul(C1);
        s[1] ^= s[0].rotate_left(17);
        s[2] = s[2].wrapping_add(s[1]).wrapping_mul(C2);
        s[3] ^= s[2].rotate_left(41);
        s[0] = s[0].wrapping_add(s[3]).rotate_left(13) ^ s[1];
        s[1] = s[1].wrapping_add(s[0]).rotate_left(19) ^ s[2];
        s[2] = s[2].wrapping_add(s[1]).rotate_left(23) ^ s[3];
        s[3] = s[3].wrapping_add(s[2]).rotate_left(29) ^ s[0];

        for (i, word) in s.iter().enumerate() {
            let bytes = word.to_le_bytes();
            let start = offset + i * 8;
            if start >= out.len() {
                break;
            }
            let end = (start + 8).min(out.len());
            out[start..end].copy_from_slice(&bytes[..end - start]);
        }
        offset += 32;
    }
}

/// Fill the working buffer using segmented SHA-256 keys + ARX expansion.
pub fn fill_buffer(seed: &[u8; 32], buffer: &mut [u8], segment_bytes: usize) {
    let seg = segment_bytes.max(32);
    let mut index = 0u64;
    for chunk in buffer.chunks_mut(seg) {
        let key = segment_key(seed, index);
        expand_segment(&key, chunk);
        index += 1;
    }
}

/// Recompute a single block from the seed (used by TMTO sparse mode).
pub fn recompute_block(
    seed: &[u8; 32],
    block_index: usize,
    block_size: usize,
    segment_bytes: usize,
) -> Vec<u8> {
    let seg = segment_bytes.max(block_size);
    let byte_offset = block_index * block_size;
    let segment_index = (byte_offset / seg) as u64;
    let within = byte_offset % seg;
    let mut segment = vec![0u8; seg];
    let key = segment_key(seed, segment_index);
    expand_segment(&key, &mut segment);
    segment[within..within + block_size].to_vec()
}

/// Multi-round ARX mix of state with two memory blocks.
#[inline(always)]
pub fn mix_state(state: &mut [u64; 4], block1: &[u8], block2: &[u8], rounds: u32) {
    let b10 = load_u64(block1, 0);
    let b11 = load_u64(block1, 8);
    let b12 = load_u64(block1, 16);
    let b13 = load_u64(block1, 24);
    let b20 = load_u64(block2, 0);
    let b21 = load_u64(block2, 8);
    let b22 = load_u64(block2, 16);
    let b23 = load_u64(block2, 24);

    for r in 0..rounds {
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

/// Single-block mix used by the coverage fold.
#[inline(always)]
pub fn mix_block(state: &mut [u64; 4], block: &[u8], rounds: u32) {
    mix_state(state, block, block, rounds.max(1));
}

/// Fold every `stride`-th block into state so the working set is committed.
pub fn fold_buffer(state: &mut [u64; 4], buffer: &[u8], block_size: usize, stride: usize, rounds: u32) {
    let stride = stride.max(1);
    let num_blocks = buffer.len() / block_size.max(1);
    let mut idx = 0usize;
    while idx < num_blocks {
        let start = idx * block_size;
        mix_block(state, &buffer[start..start + block_size], rounds);
        idx += stride;
    }
}

#[inline(always)]
fn load_u64(block: &[u8], offset: usize) -> u64 {
    if offset + 8 <= block.len() {
        u64::from_le_bytes(block[offset..offset + 8].try_into().unwrap())
    } else {
        0
    }
}

/// Finalize digest from state + first block of the buffer.
pub fn finalize(seed: &[u8; 32], state: &[u64; 4], head: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_FINAL);
    hasher.update(seed);
    for w in state {
        hasher.update(w.to_le_bytes());
    }
    hasher.update(head);
    hasher.finalize().to_vec()
}
