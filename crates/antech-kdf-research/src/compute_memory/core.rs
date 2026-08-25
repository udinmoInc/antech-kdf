//! Shared derive pipeline: work = traverse all DAG nodes (num_blocks).

use super::config::ComputeMemoryConfig;
use super::crypto_mixing::{
    bind_seed, finalize, mix_parents, node0_material, state_from_seed, state_to_block,
};
use super::dependency_graph;
use super::state_transition::{compute_node, compute_node_inplace};
use crate::candidates::cand_004::ResearchError;
use std::collections::HashMap;

fn bind(cfg: &ComputeMemoryConfig, password: &[u8], salt: &[u8]) -> [u8; 32] {
    bind_seed(
        password,
        salt,
        cfg.memory_kib,
        cfg.block_size,
        cfg.fan_in, 
    )
}

/// Reference derive — clarity-first traversal of the memory-sized DAG.
pub fn derive_reference(
    password: &[u8],
    salt: &[u8],
    cfg: &ComputeMemoryConfig,
) -> Result<Vec<u8>, ResearchError> {
    cfg.validate()
        .map_err(ResearchError::InvalidParameters)?;

    let seed = bind(cfg, password, salt);
    let block_size = cfg.block_size as usize;
    let num_blocks = cfg.num_blocks();
    let mut buffer = vec![0u8; cfg.total_bytes()];
    let mut state = state_from_seed(&seed);

    for i in 0..num_blocks {
        compute_node(&mut state, &mut buffer, &seed, i, block_size, cfg.fan_in);
    }

    let last = &buffer[(num_blocks - 1) * block_size..num_blocks * block_size];
    Ok(finalize(&seed, &state, last))
}

/// Optimized derive — identical digests, tighter inner path.
pub fn derive_optimized(
    password: &[u8],
    salt: &[u8],
    cfg: &ComputeMemoryConfig,
) -> Result<Vec<u8>, ResearchError> {
    cfg.validate()
        .map_err(ResearchError::InvalidParameters)?;

    let seed = bind(cfg, password, salt);
    let block_size = cfg.block_size as usize;
    let num_blocks = cfg.num_blocks();
    let mut buffer = vec![0u8; cfg.total_bytes()];
    let mut state = state_from_seed(&seed);

    for i in 0..num_blocks {
        compute_node_inplace(&mut state, &mut buffer, &seed, i, block_size, cfg.fan_in);
    }

    let last = &buffer[(num_blocks - 1) * block_size..num_blocks * block_size];
    Ok(finalize(&seed, &state, last))
}

/// Checkpoint TMTO store: keep stride-aligned blocks + recent window.
struct CheckpointStore {
    seed: [u8; 32],
    block_size: usize,
    fan_in: u32,
    stride: usize,
    blocks: HashMap<usize, Vec<u8>>,
    state_before: HashMap<usize, [u64; 4]>,
}

impl CheckpointStore {
    fn new(seed: [u8; 32], block_size: usize, fan_in: u32, stride: usize) -> Self {
        let mut state_before = HashMap::new();
        state_before.insert(0, state_from_seed(&seed));
        Self {
            seed,
            block_size,
            fan_in,
            stride: stride.max(1),
            blocks: HashMap::new(),
            state_before,
        }
    }

    fn get_block(&mut self, idx: usize) -> Vec<u8> {
        if let Some(b) = self.blocks.get(&idx) {
            return b.clone();
        }
        self.recompute_through(idx);
        self.blocks
            .get(&idx)
            .cloned()
            .expect("block must exist after recompute")
    }

    fn recompute_through(&mut self, idx: usize) {
        let base = (idx / self.stride) * self.stride;
        if !self.state_before.contains_key(&base) {
            if base == 0 {
                self.state_before.insert(0, state_from_seed(&self.seed));
            } else {
                // Establish prior checkpoint by recomputing through base-1.
                self.recompute_through(base - 1);
            }
        }

        let mut state = self.state_before[&base];
        for j in base..=idx {
            let parents = dependency_graph::parents_for_node(&state, j, self.fan_in);
            let mut parent_blocks = Vec::with_capacity(self.fan_in as usize);
            if j == 0 {
                for slot in 0..self.fan_in {
                    parent_blocks.push(node0_material(&self.seed, slot, self.block_size));
                }
            } else {
                for &p in &parents.indices {
                    if p < base {
                        parent_blocks.push(self.get_block(p));
                    } else if let Some(b) = self.blocks.get(&p) {
                        parent_blocks.push(b.clone());
                    } else {
                        // Parent in [base, j) must already have been written in this loop.
                        parent_blocks.push(
                            self.blocks
                                .get(&p)
                                .cloned()
                                .expect("in-range parent missing"),
                        );
                    }
                }
            }
            mix_parents(&mut state, &parent_blocks);
            let mut block = vec![0u8; self.block_size];
            state_to_block(&state, &mut block);
            self.blocks.insert(j, block);
            if (j + 1) % self.stride == 0 {
                self.state_before.insert(j + 1, state);
            }
        }
    }

    fn run(&mut self, num_blocks: usize) -> ([u64; 4], Vec<u8>) {
        let mut state = state_from_seed(&self.seed);
        self.state_before.insert(0, state);

        for i in 0..num_blocks {
            let parents = dependency_graph::parents_for_node(&state, i, self.fan_in);
            let mut parent_blocks = Vec::with_capacity(self.fan_in as usize);
            if i == 0 {
                for slot in 0..self.fan_in {
                    parent_blocks.push(node0_material(&self.seed, slot, self.block_size));
                }
            } else {
                for &p in &parents.indices {
                    parent_blocks.push(self.get_block(p));
                }
            }
            mix_parents(&mut state, &parent_blocks);
            let mut block = vec![0u8; self.block_size];
            state_to_block(&state, &mut block);
            self.blocks.insert(i, block);

            if (i + 1) % self.stride == 0 {
                self.state_before.insert(i + 1, state);
            }

            // Bound memory: drop non-checkpoint blocks outside the recent window.
            if i >= self.stride {
                let old = i - self.stride;
                if old % self.stride != 0 {
                    self.blocks.remove(&old);
                }
            }
        }

        let last = self.blocks.get(&(num_blocks - 1)).cloned().unwrap();
        (state, last)
    }
}

/// Sparse/TMTO derive: reduced checkpoints → parent misses recompute up to `stride` nodes.
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
    let stride = ((1.0 / frac).round() as usize).max(2);

    let mut store = CheckpointStore::new(seed, block_size, cfg.fan_in, stride);
    let (state, last) = store.run(num_blocks);
    Ok(finalize(&seed, &state, &last))
}
