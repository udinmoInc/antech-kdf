//! TMTO evaluation for v4 graphs (checkpoint replay under reduced resident set).

use super::config::{ComputeMemoryV4Config, TMTO_FRACTIONS};
use super::engine::V4Engine;
use super::graph;
use super::state::{
    bind_seed_v4, finalize_v4, mix_parent_views, phantom_block, state_from_seed, state_to_block,
    xor_state_into_block,
};
use crate::candidates::cand_004::ResearchKdf;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmtoRecord {
    pub variant: String,
    pub memory_percentage: f64,
    pub allocated_memory_mib: f64,
    pub recomputation_factor: f64,
    pub attacker_guesses_per_sec: f64,
    pub digest_matches_full: bool,
}

struct CheckpointStore<'a> {
    cfg: &'a ComputeMemoryV4Config,
    seed: [u8; 32],
    stride: usize,
    blocks: HashMap<usize, Vec<u8>>,
    state_before: HashMap<usize, [u64; 4]>,
}

impl<'a> CheckpointStore<'a> {
    fn new(cfg: &'a ComputeMemoryV4Config, seed: [u8; 32], stride: usize) -> Self {
        let mut state_before = HashMap::new();
        state_before.insert(0, state_from_seed(&seed));
        Self {
            cfg,
            seed,
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
        self.blocks.get(&idx).cloned().expect("after recompute")
    }

    fn recompute_through(&mut self, idx: usize) {
        let base = (idx / self.stride) * self.stride;
        if !self.state_before.contains_key(&base) {
            if base == 0 {
                self.state_before.insert(0, state_from_seed(&self.seed));
            } else {
                self.recompute_through(base - 1);
            }
        }
        let block_size = self.cfg.block_size as usize;
        let period = self.cfg.critical_period();
        let tile_len = self.cfg.tile_len();
        let mut state = self.state_before[&base];
        for j in base..=idx {
            let parents = graph::parents_for_node(
                self.cfg.graph,
                &state,
                j,
                self.cfg.fan_in,
                period,
                tile_len,
            );
            let parent_views: Vec<Vec<u8>> = if j == 0 {
                (0..self.cfg.fan_in)
                    .map(|slot| {
                        let mut b = vec![0u8; block_size];
                        phantom_block(&self.seed, slot, block_size, &mut b);
                        b
                    })
                    .collect()
            } else {
                parents
                    .as_slice()
                    .iter()
                    .map(|&p| {
                        if p < base {
                            self.get_block(p)
                        } else {
                            self.blocks.get(&p).cloned().expect("in-window parent")
                        }
                    })
                    .collect()
            };
            let refs: Vec<&[u8]> = parent_views.iter().map(|v| v.as_slice()).collect();
            mix_parent_views(&mut state, &refs);
            let mut block = vec![0u8; block_size];
            state_to_block(&state, &mut block);
            self.blocks.insert(j, block);
            if let Some(dest) = parents.scatter_dest {
                if let Some(b) = self.blocks.get_mut(&dest) {
                    xor_state_into_block(&state, b);
                }
            }
            if let Some(dest) = parents.scatter_dest2 {
                if let Some(b) = self.blocks.get_mut(&dest) {
                    xor_state_into_block(&state, b);
                }
            }
            if (j + 1) % self.stride == 0 {
                self.state_before.insert(j + 1, state);
            }
        }
    }

    fn run(&mut self) -> ([u64; 4], Vec<u8>) {
        let block_size = self.cfg.block_size as usize;
        let num_blocks = self.cfg.num_blocks();
        let period = self.cfg.critical_period();
        let tile_len = self.cfg.tile_len();
        let mut state = state_from_seed(&self.seed);
        self.state_before.insert(0, state);

        for i in 0..num_blocks {
            let parents = graph::parents_for_node(
                self.cfg.graph,
                &state,
                i,
                self.cfg.fan_in,
                period,
                tile_len,
            );
            let parent_views: Vec<Vec<u8>> = if i == 0 {
                (0..self.cfg.fan_in)
                    .map(|slot| {
                        let mut b = vec![0u8; block_size];
                        phantom_block(&self.seed, slot, block_size, &mut b);
                        b
                    })
                    .collect()
            } else {
                parents
                    .as_slice()
                    .iter()
                    .map(|&p| self.get_block(p))
                    .collect()
            };
            let refs: Vec<&[u8]> = parent_views.iter().map(|v| v.as_slice()).collect();
            mix_parent_views(&mut state, &refs);
            let mut block = vec![0u8; block_size];
            state_to_block(&state, &mut block);
            self.blocks.insert(i, block);
            if let Some(dest) = parents.scatter_dest {
                if dest != i {
                    let mut remote = self.get_block(dest);
                    xor_state_into_block(&state, &mut remote);
                    self.blocks.insert(dest, remote);
                }
            }
            if let Some(dest) = parents.scatter_dest2 {
                if dest != i {
                    let mut remote = self.get_block(dest);
                    xor_state_into_block(&state, &mut remote);
                    self.blocks.insert(dest, remote);
                }
            }
            if (i + 1) % self.stride == 0 {
                self.state_before.insert(i + 1, state);
            }
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

pub fn derive_sparse(
    engine: &V4Engine,
    password: &[u8],
    salt: &[u8],
    cfg: &ComputeMemoryV4Config,
    memory_fraction: f64,
) -> Result<Vec<u8>, crate::candidates::cand_004::ResearchError> {
    let frac = memory_fraction.clamp(0.01, 1.0);
    if (frac - 1.0).abs() < 1e-9 {
        return engine.derive_cfg(password, salt, cfg);
    }
    let seed = bind_seed_v4(password, salt, cfg);
    let stride = ((1.0 / frac).round() as usize).max(2);
    let mut store = CheckpointStore::new(cfg, seed, stride);
    let (state, last) = store.run();
    Ok(finalize_v4(&seed, &state, &last, cfg.graph))
}

pub struct TmtoEvaluator;

impl TmtoEvaluator {
    pub fn evaluate(engine: &V4Engine, cfg: &ComputeMemoryV4Config) -> Vec<TmtoRecord> {
        let password = b"tmto_password_v4";
        let salt = b"tmto_salt_16b_v4!";
        let full = engine.derive_cfg(password, salt, cfg).unwrap_or_default();

        let t0 = Instant::now();
        let _ = engine.derive_cfg(password, salt, cfg);
        let base = t0.elapsed().as_secs_f64().max(1e-6);
        let base_gps = 1.0 / base;
        let mem_mib = cfg.memory_kib as f64 / 1024.0;

        TMTO_FRACTIONS
            .iter()
            .map(|&frac| {
                let start = Instant::now();
                let out = derive_sparse(engine, password, salt, cfg, frac).unwrap_or_default();
                let elapsed = start.elapsed().as_secs_f64().max(1e-6);
                let recompute = elapsed / base;
                TmtoRecord {
                    variant: engine.name().to_string(),
                    memory_percentage: frac * 100.0,
                    allocated_memory_mib: mem_mib * frac,
                    recomputation_factor: recompute,
                    attacker_guesses_per_sec: base_gps / recompute,
                    digest_matches_full: out == full,
                }
            })
            .collect()
    }
}
