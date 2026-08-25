//! Shared derive pipeline for reference and optimized engines.

use super::config::ComputeMemoryConfig;
use super::crypto_mixing::{
    bind_seed, fill_buffer, finalize, fold_buffer, mix_block, mix_state, recompute_block,
    state_from_seed,
};
use super::dependency_graph;
use super::state_transition::{transition, transition_inplace};
use crate::candidates::cand_004::ResearchError;
use std::collections::{HashMap, VecDeque};

fn bind(cfg: &ComputeMemoryConfig, password: &[u8], salt: &[u8]) -> [u8; 32] {
    bind_seed(
        password,
        salt,
        cfg.memory_kib,
        cfg.dependency_depth,
        cfg.passes,
        cfg.block_size,
        cfg.mix_rounds,
        cfg.segment_bytes,
        cfg.fold_stride,
    )
}

/// Reference (clarity-first) derive — identical digests to the optimized path.
pub fn derive_reference(
    password: &[u8],
    salt: &[u8],
    cfg: &ComputeMemoryConfig,
) -> Result<Vec<u8>, ResearchError> {
    cfg.validate()
        .map_err(ResearchError::InvalidParameters)?;

    let seed = bind(cfg, password, salt);
    let total = cfg.total_bytes();
    let block_size = cfg.block_size as usize;
    let num_blocks = cfg.num_blocks();
    let mut buffer = vec![0u8; total];
    fill_buffer(&seed, &mut buffer, cfg.segment_bytes as usize);

    let mut state = state_from_seed(&seed);
    for pass in 0..cfg.passes {
        for step in 0..cfg.dependency_depth {
            transition(
                &mut state,
                &mut buffer,
                block_size,
                num_blocks,
                step,
                pass,
                cfg.mix_rounds,
            );
        }
    }

    fold_buffer(
        &mut state,
        &buffer,
        block_size,
        cfg.fold_stride as usize,
        cfg.mix_rounds,
    );

    let head_len = block_size.min(buffer.len());
    Ok(finalize(&seed, &state, &buffer[..head_len]))
}

/// Optimized derive — same math, fewer allocations in the hot loop.
pub fn derive_optimized(
    password: &[u8],
    salt: &[u8],
    cfg: &ComputeMemoryConfig,
) -> Result<Vec<u8>, ResearchError> {
    cfg.validate()
        .map_err(ResearchError::InvalidParameters)?;

    let seed = bind(cfg, password, salt);
    let total = cfg.total_bytes();
    let block_size = cfg.block_size as usize;
    let num_blocks = cfg.num_blocks();
    let mut buffer = vec![0u8; total];
    fill_buffer(&seed, &mut buffer, cfg.segment_bytes as usize);

    let mut state = state_from_seed(&seed);
    for pass in 0..cfg.passes {
        for step in 0..cfg.dependency_depth {
            transition_inplace(
                &mut state,
                &mut buffer,
                block_size,
                num_blocks,
                step,
                pass,
                cfg.mix_rounds,
            );
        }
    }

    fold_buffer(
        &mut state,
        &buffer,
        block_size,
        cfg.fold_stride as usize,
        cfg.mix_rounds,
    );

    let head_len = block_size.min(buffer.len());
    Ok(finalize(&seed, &state, &buffer[..head_len]))
}

#[derive(Clone)]
struct WriteEvent {
    dest: usize,
    payload: Vec<u8>,
}

/// Correct sparse/TMTO derive: resident set limited to `memory_fraction` of blocks.
/// Evicted dirty blocks are reconstructed from the seed fill + write-log replay.
/// The coverage fold still visits every stride-th block, forcing recomputation.
pub fn derive_sparse(
    password: &[u8],
    salt: &[u8],
    cfg: &ComputeMemoryConfig,
    memory_fraction: f64,
) -> Result<Vec<u8>, ResearchError> {
    cfg.validate()
        .map_err(ResearchError::InvalidParameters)?;

    let frac = memory_fraction.clamp(0.01, 1.0);
    if (frac - 1.0).abs() < 1e-9 {
        return derive_optimized(password, salt, cfg);
    }

    let seed = bind(cfg, password, salt);
    let block_size = cfg.block_size as usize;
    let num_blocks = cfg.num_blocks();
    let capacity = ((num_blocks as f64) * frac).ceil() as usize;
    let capacity = capacity.max(2).min(num_blocks);
    let segment_bytes = cfg.segment_bytes as usize;

    let mut resident: HashMap<usize, Vec<u8>> = HashMap::with_capacity(capacity);
    let mut lru: VecDeque<usize> = VecDeque::with_capacity(capacity);
    let mut write_log: Vec<WriteEvent> = Vec::with_capacity(cfg.dependency_depth as usize);

    let materialize = |resident: &mut HashMap<usize, Vec<u8>>,
                       lru: &mut VecDeque<usize>,
                       write_log: &[WriteEvent],
                       idx: usize|
     -> Vec<u8> {
        if let Some(block) = resident.get(&idx) {
            return block.clone();
        }
        let mut block = recompute_block(&seed, idx, block_size, segment_bytes);
        for event in write_log {
            if event.dest == idx {
                for (a, b) in block.iter_mut().zip(event.payload.iter()) {
                    *a ^= b;
                }
            }
        }
        if resident.len() >= capacity {
            if let Some(evict) = lru.pop_front() {
                resident.remove(&evict);
            }
        }
        resident.insert(idx, block.clone());
        lru.push_back(idx);
        block
    };

    let mut state = state_from_seed(&seed);

    for pass in 0..cfg.passes {
        for step in 0..cfg.dependency_depth {
            let addrs = dependency_graph::addresses(&state, step, pass, num_blocks);
            let b1 = materialize(&mut resident, &mut lru, &write_log, addrs.parent1);
            let b2 = materialize(&mut resident, &mut lru, &write_log, addrs.parent2);
            mix_state(&mut state, &b1, &b2, cfg.mix_rounds);

            let mut payload = vec![0u8; block_size];
            for (i, word) in state.iter().enumerate() {
                let bytes = word.to_le_bytes();
                for (j, b) in bytes.iter().enumerate() {
                    let idx = i * 8 + j;
                    if idx < block_size {
                        payload[idx] = *b;
                    }
                }
            }

            let mut dest = materialize(&mut resident, &mut lru, &write_log, addrs.dest);
            for (a, b) in dest.iter_mut().zip(payload.iter()) {
                *a ^= b;
            }
            resident.insert(addrs.dest, dest);
            write_log.push(WriteEvent {
                dest: addrs.dest,
                payload,
            });
        }
    }

    // Coverage fold — visits stride-th blocks; sparse misses recompute via write-log.
    let stride = (cfg.fold_stride as usize).max(1);
    let mut idx = 0usize;
    while idx < num_blocks {
        let block = materialize(&mut resident, &mut lru, &write_log, idx);
        mix_block(&mut state, &block, cfg.mix_rounds);
        idx += stride;
    }

    let head = materialize(&mut resident, &mut lru, &write_log, 0);
    Ok(finalize(&seed, &state, &head))
}
