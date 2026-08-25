//! Per-node state transition along the memory-sized dependency DAG.

use super::crypto_mixing::{mix_parents, node0_material, state_to_block};
use super::dependency_graph;

/// Compute DAG node `i`: read parents → mix into state → write block `i`.
///
/// This is the only per-node work unit; the outer loop runs exactly `num_blocks`
/// times (structure-derived).
#[inline(always)]
pub fn compute_node(
    state: &mut [u64; 4],
    buffer: &mut [u8],
    seed: &[u8; 32],
    i: usize,
    block_size: usize,
    fan_in: u32,
) {
    let parents = dependency_graph::parents_for_node(state, i, fan_in);
    let mut parent_blocks: Vec<Vec<u8>> = Vec::with_capacity(fan_in as usize);

    if i == 0 {
        for slot in 0..fan_in {
            parent_blocks.push(node0_material(seed, slot, block_size));
        }
    } else {
        for &idx in &parents.indices {
            let start = idx * block_size;
            parent_blocks.push(buffer[start..start + block_size].to_vec());
        }
    }

    mix_parents(state, &parent_blocks);

    let dest = i * block_size;
    state_to_block(state, &mut buffer[dest..dest + block_size]);
}

/// Optimized path: stack parents for the common fan_in=2 / block_size=32 case.
#[inline(always)]
pub fn compute_node_inplace(
    state: &mut [u64; 4],
    buffer: &mut [u8],
    seed: &[u8; 32],
    i: usize,
    block_size: usize,
    fan_in: u32,
) {
    use super::crypto_mixing::{mix_pair, mix_parents};

    if i == 0 {
        let p0 = node0_material(seed, 0, block_size);
        let p1 = node0_material(seed, 1.min(fan_in.saturating_sub(1)), block_size);
        mix_pair(state, &p0, &p1);
        if fan_in > 2 {
            let mut extras = Vec::new();
            for slot in 2..fan_in {
                extras.push(node0_material(seed, slot, block_size));
            }
            mix_parents(state, &extras);
        }
    } else {
        let parents = dependency_graph::parents_for_node(state, i, fan_in);
        if parents.indices.len() >= 2 && block_size <= 64 {
            let mut b0 = [0u8; 64];
            let mut b1 = [0u8; 64];
            let len = block_size;
            let i0 = parents.indices[0];
            let i1 = parents.indices[1];
            b0[..len].copy_from_slice(&buffer[i0 * block_size..i0 * block_size + len]);
            b1[..len].copy_from_slice(&buffer[i1 * block_size..i1 * block_size + len]);
            mix_pair(state, &b0[..len], &b1[..len]);
            if parents.indices.len() > 2 {
                let mut extras = Vec::new();
                for &idx in &parents.indices[2..] {
                    extras.push(buffer[idx * block_size..idx * block_size + block_size].to_vec());
                }
                mix_parents(state, &extras);
            }
        } else {
            let mut parent_blocks = Vec::with_capacity(parents.indices.len());
            for &idx in &parents.indices {
                parent_blocks.push(buffer[idx * block_size..idx * block_size + block_size].to_vec());
            }
            mix_parents(state, &parent_blocks);
        }
    }

    let dest = i * block_size;
    state_to_block(state, &mut buffer[dest..dest + block_size]);
}
