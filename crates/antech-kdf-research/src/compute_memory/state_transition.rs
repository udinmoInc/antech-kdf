//! Single state transition: prior state + state-derived memory → new state + writeback.

use super::crypto_mixing::mix_state;
use super::dependency_graph::{self, GraphAddresses};

/// Execute one sequential transition against an in-memory block buffer.
#[inline(always)]
pub fn transition(
    state: &mut [u64; 4],
    buffer: &mut [u8],
    block_size: usize,
    num_blocks: usize,
    step: u32,
    pass: u32,
    mix_rounds: u32,
) -> GraphAddresses {
    let addrs = dependency_graph::addresses(state, step, pass, num_blocks);
    let bs = block_size;

    let mut b1 = vec![0u8; bs];
    let mut b2 = vec![0u8; bs];
    b1.copy_from_slice(&buffer[addrs.parent1 * bs..(addrs.parent1 + 1) * bs]);
    b2.copy_from_slice(&buffer[addrs.parent2 * bs..(addrs.parent2 + 1) * bs]);

    mix_state(state, &b1, &b2, mix_rounds);

    // XOR writeback — dest contents depend on the new state.
    let dest_start = addrs.dest * bs;
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        for (j, b) in bytes.iter().enumerate() {
            let idx = dest_start + i * 8 + j;
            if idx < dest_start + bs && idx < buffer.len() {
                buffer[idx] ^= b;
            }
        }
    }

    addrs
}

/// Optimized transition that avoids per-step heap allocation of parent blocks.
#[inline(always)]
pub fn transition_inplace(
    state: &mut [u64; 4],
    buffer: &mut [u8],
    block_size: usize,
    num_blocks: usize,
    step: u32,
    pass: u32,
    mix_rounds: u32,
) -> GraphAddresses {
    let addrs = dependency_graph::addresses(state, step, pass, num_blocks);
    let bs = block_size;

    // Copy parents into stack buffers (block_size is typically 32).
    let mut b1 = [0u8; 64];
    let mut b2 = [0u8; 64];
    let len = bs.min(64);
    b1[..len].copy_from_slice(&buffer[addrs.parent1 * bs..addrs.parent1 * bs + len]);
    b2[..len].copy_from_slice(&buffer[addrs.parent2 * bs..addrs.parent2 * bs + len]);

    mix_state(state, &b1[..len], &b2[..len], mix_rounds);

    let dest_start = addrs.dest * bs;
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        for (j, b) in bytes.iter().enumerate() {
            let idx = i * 8 + j;
            if idx < bs {
                buffer[dest_start + idx] ^= b;
            }
        }
    }

    addrs
}
