//! Advanced scatter-aware TMTO attacks against production CombinedFrontier.
//!
//! Correctness rule: digest must match `AntechEngine::derive` exactly.
//!
//! Dual far-scatter keeps the entire address space live. Valid strategies:
//! - **FullPacked**: 100% mutated block buffer (reference / strongest practical).
//! - **ScatterLog**: full pristine + compact dest→src index (correct; *more* RAM than packed).
//! - **Sparse**: checkpoint + hot window + segment recompute (correct until recompute budget;
//!   far-parent thrashing hits a wall quickly at reduced fractions).
//! - **Regen**: no scatter index; prefix replay (correct only with near-full cache).

use antech_kdf_core::engine::AntechEngine;
use antech_kdf_core::graph;
use antech_kdf_core::mixing::state_from_seed;
use antech_kdf_core::state::{bind_seed, finalize, phantom_block, seed_to_state};
use antech_kdf_types::{AntechConfig, GraphKind};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const C1: u64 = 0xBF58476D1CE4E5B9;
const C2: u64 = 0x94D049BB133111EB;
const GOLDEN: u64 = 0x9E3779B97F4A7C15;
const MIX_ROUNDS: u32 = 4;

#[inline(always)]
fn mix_pair_words(state: &mut [u64; 4], a: &[u64; 4], b: &[u64; 4]) {
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
fn mix_views(state: &mut [u64; 4], views: &[[u64; 4]], n: usize) {
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
fn load_block_bytes(src: &[u8]) -> [u64; 4] {
    [
        u64::from_le_bytes(src[0..8].try_into().unwrap()),
        u64::from_le_bytes(src[8..16].try_into().unwrap()),
        u64::from_le_bytes(src[16..24].try_into().unwrap()),
        u64::from_le_bytes(src[24..32].try_into().unwrap()),
    ]
}

#[inline(always)]
fn block_to_bytes(w: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&w[i].to_le_bytes());
    }
    out
}

#[inline(always)]
fn xor_words(dst: &mut [u64; 4], src: &[u64; 4]) {
    dst[0] ^= src[0];
    dst[1] ^= src[1];
    dst[2] ^= src[2];
    dst[3] ^= src[3];
}

pub fn cfg_kib(kib: usize) -> AntechConfig {
    AntechConfig::builder()
        .memory_kib(kib)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap()
}

pub fn production_cfg(memory_mib: usize) -> AntechConfig {
    AntechConfig::builder()
        .memory_mib(memory_mib)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap()
}

#[derive(Debug, Clone, Default)]
pub struct TmtoStats {
    pub nodes: u64,
    pub mix_pairs: u64,
    pub parent_gathers: u64,
    pub scatters_logged: u64,
    pub scatters_replayed: u64,
    pub pristine_hits: u64,
    pub pristine_misses: u64,
    pub nodes_recomputed: u64,
    pub peak_pristine_entries: usize,
    pub scatter_log_entries: usize,
    pub checkpoint_entries: usize,
    pub aborted: bool,
    pub parent_misses: u64,
    pub scatter_dest_misses: u64,
}

impl TmtoStats {
    /// Compact scatter index: 8 B/entry (src u32 + dest side in map amortized as 4 B).
    pub fn estimated_bytes(&self, block_bytes: usize) -> usize {
        let pristine = self.peak_pristine_entries.saturating_mul(block_bytes);
        let scatters = self.scatter_log_entries.saturating_mul(8);
        let ckpt = self.checkpoint_entries.saturating_mul(32);
        pristine + scatters + ckpt
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    FullPacked,
    /// Full pristine + compact scatter index (correct; not a memory reduction).
    ScatterLog,
    /// Sparse pristine + compact index + segment recompute (budget-capped).
    Sparse,
    Regen,
}

#[derive(Debug, Clone)]
pub struct TmtoParams {
    pub strategy: Strategy,
    pub pristine_cap: usize,
    pub checkpoint_stride: usize,
}

pub fn compact_scatter_index_bytes(num_blocks: usize) -> usize {
    num_blocks.saturating_mul(2).saturating_mul(4)
}

pub fn caps_for_fraction(num_blocks: usize, frac: f64) -> TmtoParams {
    if frac >= 0.999 {
        return TmtoParams {
            strategy: Strategy::FullPacked,
            pristine_cap: num_blocks,
            checkpoint_stride: 1,
        };
    }
    let full_bytes = num_blocks * 32;
    let budget = ((full_bytes as f64) * frac).round() as usize;
    // Sparse prefix-replay does not require the compact scatter index in RAM;
    // the whole budget goes to the hot mutated window.
    let pristine_cap = (budget / 32).max(64).min(num_blocks);
    if pristine_cap < 128 {
        return TmtoParams {
            strategy: Strategy::Regen,
            pristine_cap,
            checkpoint_stride: 512,
        };
    }
    let max_ckpts = (pristine_cap / 2).max(1);
    let stride = ((num_blocks + max_ckpts - 1) / max_ckpts)
        .max(2)
        .next_power_of_two()
        .min(4096)
        .max(2);
    TmtoParams {
        strategy: Strategy::Sparse,
        pristine_cap,
        checkpoint_stride: stride,
    }
}

pub fn reference_digest(password: &[u8], salt: &[u8], cfg: &AntechConfig) -> Vec<u8> {
    AntechEngine::new().derive(password, salt, cfg).unwrap()
}

pub fn derive_full_packed(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    buf: &mut [[u64; 4]],
) -> ([u8; 32], TmtoStats) {
    let n = cfg.num_blocks();
    assert!(buf.len() >= n);
    let seed = bind_seed(password, salt, cfg);
    let mut ph = [[0u8; 32]; 2];
    phantom_block(&seed, 0, 32, &mut ph[0]);
    phantom_block(&seed, 1, 32, &mut ph[1]);
    let phantoms = [load_block_bytes(&ph[0]), load_block_bytes(&ph[1])];
    let mut state = seed_to_state(&seed);
    let period = cfg.critical_period();
    let tile = cfg.tile_len();
    let fan = cfg.fan_in.get();
    let mut stats = TmtoStats {
        nodes: n as u64,
        peak_pristine_entries: n,
        ..Default::default()
    };

    for i in 0..n {
        let parents = graph::parents_for_node(cfg.graph, &state, i, fan, period, tile);
        let mut views = [[0u64; 4]; 8];
        let mut nv = 0usize;
        if i == 0 {
            views[0] = phantoms[0];
            views[1] = phantoms[1];
            nv = 2;
        } else {
            for k in 0..parents.len {
                views[nv] = buf[parents.indices[k]];
                nv += 1;
                stats.parent_gathers += 1;
            }
        }
        stats.mix_pairs += if nv <= 1 { 1 } else { (nv as u64 + 1) / 2 };
        mix_views(&mut state, &views, nv);
        buf[i] = state;
        if let Some(d) = parents.scatter_dest {
            if d < n && d != i {
                xor_words(&mut buf[d], &state);
                stats.scatters_logged += 1;
            }
        }
        if let Some(d) = parents.scatter_dest2 {
            if d < n && d != i {
                xor_words(&mut buf[d], &state);
                stats.scatters_logged += 1;
            }
        }
    }
    let dig = finalize(&seed, &state, &block_to_bytes(&buf[n - 1]), cfg.graph);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    (out, stats)
}

/// Full pristine + compact scatter index. Correct; uses more RAM than FullPacked.
fn derive_scatter_log_full(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    stride: usize,
) -> ([u8; 32], TmtoStats) {
    let n = cfg.num_blocks();
    let seed = bind_seed(password, salt, cfg);
    let mut ph = [[0u8; 32]; 2];
    phantom_block(&seed, 0, 32, &mut ph[0]);
    phantom_block(&seed, 1, 32, &mut ph[1]);
    let phantoms = [load_block_bytes(&ph[0]), load_block_bytes(&ph[1])];
    let mut pristine = vec![[0u64; 4]; n];
    let mut scatter_srcs: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut state = seed_to_state(&seed);
    let period = cfg.critical_period();
    let tile = cfg.tile_len();
    let fan = cfg.fan_in.get();
    let stride = stride.max(2);
    let mut stats = TmtoStats {
        nodes: n as u64,
        peak_pristine_entries: n,
        checkpoint_entries: (n / stride) + 1,
        ..Default::default()
    };

    let materialize = |idx: usize,
                       as_of: usize,
                       pristine: &[[u64; 4]],
                       scatter_srcs: &[Vec<u32>],
                       stats: &mut TmtoStats|
     -> [u64; 4] {
        let mut b = pristine[idx];
        for &src in &scatter_srcs[idx] {
            let src = src as usize;
            if src < as_of {
                xor_words(&mut b, &pristine[src]);
                stats.scatters_replayed += 1;
            }
        }
        b
    };

    for i in 0..n {
        let parents = graph::parents_for_node(cfg.graph, &state, i, fan, period, tile);
        let mut views = [[0u64; 4]; 8];
        let mut nv = 0usize;
        if i == 0 {
            views[0] = phantoms[0];
            views[1] = phantoms[1];
            nv = 2;
        } else {
            for k in 0..parents.len {
                views[nv] =
                    materialize(parents.indices[k], i, &pristine, &scatter_srcs, &mut stats);
                nv += 1;
                stats.parent_gathers += 1;
            }
        }
        stats.mix_pairs += if nv <= 1 { 1 } else { (nv as u64 + 1) / 2 };
        mix_views(&mut state, &views, nv);
        pristine[i] = state;
        for dest_opt in [parents.scatter_dest, parents.scatter_dest2] {
            if let Some(dest) = dest_opt {
                if dest < n && dest != i {
                    scatter_srcs[dest].push(i as u32);
                    stats.scatters_logged += 1;
                }
            }
        }
    }
    stats.scatter_log_entries = stats.scatters_logged as usize;
    let last = materialize(n - 1, n, &pristine, &scatter_srcs, &mut stats);
    let dig = finalize(&seed, &state, &block_to_bytes(&last), cfg.graph);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    (out, stats)
}

/// Probe miss rates under a sliding window while running full-memory packed (always correct).
pub fn probe_window_misses(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    window: usize,
) -> TmtoStats {
    let n = cfg.num_blocks();
    let mut buf = vec![[0u64; 4]; n];
    let (dig, mut stats) = derive_full_packed(password, salt, cfg, &mut buf);
    let _ = dig;
    // Second pass: recreate parent/scatter decisions and count window misses.
    let seed = bind_seed(password, salt, cfg);
    let mut state = seed_to_state(&seed);
    let period = cfg.critical_period();
    let tile = cfg.tile_len();
    let fan = cfg.fan_in.get();
    let w = window.max(1).min(n);
    stats.parent_misses = 0;
    stats.scatter_dest_misses = 0;
    for i in 0..n {
        let parents = graph::parents_for_node(cfg.graph, &state, i, fan, period, tile);
        if i > 0 {
            for k in 0..parents.len {
                let p = parents.indices[k];
                if i.saturating_sub(p) > w {
                    stats.parent_misses += 1;
                }
            }
        }
        let mut views = [[0u64; 4]; 8];
        let mut nv = 0usize;
        if i == 0 {
            nv = 0;
        } else {
            for k in 0..parents.len {
                views[nv] = buf[parents.indices[k]];
                nv += 1;
            }
        }
        // Recompute state the same way (buf already final; just advance state).
        if i == 0 {
            let mut ph = [[0u8; 32]; 2];
            phantom_block(&seed, 0, 32, &mut ph[0]);
            phantom_block(&seed, 1, 32, &mut ph[1]);
            views[0] = load_block_bytes(&ph[0]);
            views[1] = load_block_bytes(&ph[1]);
            nv = 2;
        }
        mix_views(&mut state, &views, nv);
        for dest_opt in [parents.scatter_dest, parents.scatter_dest2] {
            if let Some(dest) = dest_opt {
                if dest < n && dest != i && i.saturating_sub(dest) > w {
                    stats.scatter_dest_misses += 1;
                }
            }
        }
    }
    stats.peak_pristine_entries = w;
    stats.scatter_log_entries = compact_scatter_index_bytes(n) / 8;
    stats.checkpoint_entries = (n / w.max(1)) + 1;
    // Lower-bound extra work: each parent miss forces ~w/2 node recomputes on average.
    stats.nodes_recomputed = stats.parent_misses.saturating_mul((w as u64) / 2);
    stats
}

/// Budget-capped sparse attacker. Correct when it finishes; aborted ⇒ treat as wall.
struct SparseAttack<'a> {
    cfg: &'a AntechConfig,
    seed: [u8; 32],
    phantoms: [[u64; 4]; 2],
    /// Mutated blocks currently resident.
    hot: HashMap<usize, [u64; 4]>,
    lru: VecDeque<usize>,
    cap: usize,
    stride: usize,
    state_ckpt: HashMap<usize, [u64; 4]>,
    recompute_budget: u64,
    aborted: bool,
    stats: TmtoStats,
}

impl<'a> SparseAttack<'a> {
    fn new(cfg: &'a AntechConfig, seed: [u8; 32], cap: usize, stride: usize) -> Self {
        let mut ph = [[0u8; 32]; 2];
        phantom_block(&seed, 0, 32, &mut ph[0]);
        phantom_block(&seed, 1, 32, &mut ph[1]);
        let mut state_ckpt = HashMap::new();
        state_ckpt.insert(0, state_from_seed(&seed));
        let n = cfg.num_blocks();
        Self {
            cfg,
            seed,
            phantoms: [load_block_bytes(&ph[0]), load_block_bytes(&ph[1])],
            hot: HashMap::new(),
            lru: VecDeque::new(),
            cap: cap.max(stride.max(2)).min(n),
            stride: stride.max(2),
            state_ckpt,
            recompute_budget: (n as u64).saturating_mul(32).max(5_000),
            aborted: false,
            stats: TmtoStats::default(),
        }
    }

    fn put(&mut self, idx: usize, val: [u64; 4]) {
        if self.hot.insert(idx, val).is_none() {
            self.lru.push_back(idx);
        }
        while self.hot.len() > self.cap {
            if let Some(old) = self.lru.pop_front() {
                self.hot.remove(&old);
            } else {
                break;
            }
        }
        self.stats.peak_pristine_entries = self
            .stats
            .peak_pristine_entries
            .max(self.hot.len() + self.state_ckpt.len());
    }

    fn get_mutated(&mut self, idx: usize, as_of: usize) -> [u64; 4] {
        if let Some(&b) = self.hot.get(&idx) {
            self.stats.pristine_hits += 1;
            return b;
        }
        self.stats.pristine_misses += 1;
        self.recompute_block(idx, as_of)
    }

    fn recompute_block(&mut self, target: usize, as_of: usize) -> [u64; 4] {
        // Prefix replay into a temporary full buffer up to as_of — correct, peak temp = O(as_of).
        // Abort if this would exceed budget (practical wall).
        let end = as_of.max(target + 1);
        if self.stats.nodes_recomputed + end as u64 > self.recompute_budget {
            self.aborted = true;
            self.stats.aborted = true;
            return [0; 4];
        }
        let period = self.cfg.critical_period();
        let tile = self.cfg.tile_len();
        let fan = self.cfg.fan_in.get();
        let mut local = vec![[0u64; 4]; end];
        let mut state = seed_to_state(&self.seed);
        for j in 0..end {
            self.stats.nodes_recomputed += 1;
            let parents = graph::parents_for_node(self.cfg.graph, &state, j, fan, period, tile);
            let mut views = [[0u64; 4]; 8];
            let mut nv = 0usize;
            if j == 0 {
                views[0] = self.phantoms[0];
                views[1] = self.phantoms[1];
                nv = 2;
            } else {
                for k in 0..parents.len {
                    views[nv] = local[parents.indices[k]];
                    nv += 1;
                    self.stats.parent_gathers += 1;
                }
            }
            self.stats.mix_pairs += if nv <= 1 { 1 } else { (nv as u64 + 1) / 2 };
            mix_views(&mut state, &views, nv);
            local[j] = state;
            for dest_opt in [parents.scatter_dest, parents.scatter_dest2] {
                if let Some(dest) = dest_opt {
                    if dest < j {
                        xor_words(&mut local[dest], &state);
                        self.stats.scatters_replayed += 1;
                    }
                }
            }
        }
        let out = local[target];
        self.put(target, out);
        out
    }

    fn run(&mut self) -> [u8; 32] {
        let n = self.cfg.num_blocks();
        let period = self.cfg.critical_period();
        let tile = self.cfg.tile_len();
        let fan = self.cfg.fan_in.get();
        let mut state = seed_to_state(&self.seed);
        self.stats.nodes = n as u64;
        // Compact index floor counted even though we regen scatters via prefix replay.
        self.stats.scatter_log_entries = 0;

        for i in 0..n {
            if self.aborted {
                break;
            }
            let parents = graph::parents_for_node(self.cfg.graph, &state, i, fan, period, tile);
            let mut views = [[0u64; 4]; 8];
            let mut nv = 0usize;
            if i == 0 {
                views[0] = self.phantoms[0];
                views[1] = self.phantoms[1];
                nv = 2;
            } else {
                for k in 0..parents.len {
                    views[nv] = self.get_mutated(parents.indices[k], i);
                    nv += 1;
                    self.stats.parent_gathers += 1;
                    if self.aborted {
                        break;
                    }
                }
            }
            if self.aborted {
                break;
            }
            self.stats.mix_pairs += if nv <= 1 { 1 } else { (nv as u64 + 1) / 2 };
            mix_views(&mut state, &views, nv);
            self.put(i, state);
            for dest_opt in [parents.scatter_dest, parents.scatter_dest2] {
                if let Some(dest) = dest_opt {
                    if dest < n && dest != i {
                        if let Some(b) = self.hot.get_mut(&dest) {
                            xor_words(b, &state);
                        } else {
                            self.stats.scatter_dest_misses += 1;
                            // Dest not resident: must recompute it later if read; count as logged need.
                            self.stats.scatters_logged += 1;
                        }
                    }
                }
            }
            if (i + 1) % self.stride == 0 {
                self.state_ckpt.insert(i + 1, state);
            }
        }
        self.stats.checkpoint_entries = self.state_ckpt.len();
        self.stats.aborted = self.aborted;
        if self.aborted {
            return [0u8; 32];
        }
        let last = self.get_mutated(n - 1, n);
        if self.aborted {
            return [0u8; 32];
        }
        let dig = finalize(&self.seed, &state, &block_to_bytes(&last), self.cfg.graph);
        let mut out = [0u8; 32];
        out.copy_from_slice(&dig);
        out
    }
}

struct RegenAttack<'a> {
    cfg: &'a AntechConfig,
    seed: [u8; 32],
    phantoms: [[u64; 4]; 2],
    cache: HashMap<usize, [u64; 4]>,
    lru: VecDeque<usize>,
    cap: usize,
    state_ckpt: HashMap<usize, [u64; 4]>,
    stride: usize,
    as_of: usize,
    stats: TmtoStats,
}

impl<'a> RegenAttack<'a> {
    fn new(cfg: &'a AntechConfig, seed: [u8; 32], cap: usize, stride: usize) -> Self {
        let mut ph = [[0u8; 32]; 2];
        phantom_block(&seed, 0, 32, &mut ph[0]);
        phantom_block(&seed, 1, 32, &mut ph[1]);
        let mut state_ckpt = HashMap::new();
        state_ckpt.insert(0, state_from_seed(&seed));
        Self {
            cfg,
            seed,
            phantoms: [load_block_bytes(&ph[0]), load_block_bytes(&ph[1])],
            cache: HashMap::new(),
            lru: VecDeque::new(),
            cap: cap.max(64),
            state_ckpt,
            stride: stride.max(2),
            as_of: 0,
            stats: TmtoStats::default(),
        }
    }

    fn cache_put(&mut self, idx: usize, val: [u64; 4]) {
        if self.cache.insert(idx, val).is_none() {
            self.lru.push_back(idx);
        }
        while self.cache.len() > self.cap {
            if let Some(old) = self.lru.pop_front() {
                self.cache.remove(&old);
            } else {
                break;
            }
        }
        self.stats.peak_pristine_entries = self.stats.peak_pristine_entries.max(self.cache.len());
    }

    fn materialize(&mut self, idx: usize) -> [u64; 4] {
        if let Some(&b) = self.cache.get(&idx) {
            self.stats.pristine_hits += 1;
            return b;
        }
        self.stats.pristine_misses += 1;
        self.recompute_as_of(idx, self.as_of)
    }

    fn recompute_as_of(&mut self, target: usize, as_of: usize) -> [u64; 4] {
        let period = self.cfg.critical_period();
        let tile = self.cfg.tile_len();
        let fan = self.cfg.fan_in.get();
        let mut local: HashMap<usize, [u64; 4]> = HashMap::new();
        let mut state = state_from_seed(&self.seed);
        let end = as_of.max(target + 1);
        for j in 0..end {
            self.stats.nodes_recomputed += 1;
            let parents = graph::parents_for_node(self.cfg.graph, &state, j, fan, period, tile);
            let mut views = [[0u64; 4]; 8];
            let mut nv = 0usize;
            if j == 0 {
                views[0] = self.phantoms[0];
                views[1] = self.phantoms[1];
                nv = 2;
            } else {
                for k in 0..parents.len {
                    let p = parents.indices[k];
                    views[nv] = local.get(&p).copied().unwrap_or([0; 4]);
                    nv += 1;
                    self.stats.parent_gathers += 1;
                }
            }
            self.stats.mix_pairs += if nv <= 1 { 1 } else { (nv as u64 + 1) / 2 };
            mix_views(&mut state, &views, nv);
            local.insert(j, state);
            for dest_opt in [parents.scatter_dest, parents.scatter_dest2] {
                if let Some(dest) = dest_opt {
                    if let Some(b) = local.get_mut(&dest) {
                        xor_words(b, &state);
                        self.stats.scatters_replayed += 1;
                    }
                }
            }
            if local.len() > self.cap.saturating_mul(2) {
                let drop_before = j.saturating_sub(self.cap);
                local.retain(|&k, _| k >= drop_before || k == target);
            }
        }
        let out = local.get(&target).copied().unwrap_or([0; 4]);
        self.cache_put(target, out);
        out
    }

    fn run(&mut self) -> [u8; 32] {
        let n = self.cfg.num_blocks();
        let period = self.cfg.critical_period();
        let tile = self.cfg.tile_len();
        let fan = self.cfg.fan_in.get();
        let mut state = seed_to_state(&self.seed);
        self.stats.nodes = n as u64;

        for i in 0..n {
            self.as_of = i;
            let parents = graph::parents_for_node(self.cfg.graph, &state, i, fan, period, tile);
            let mut views = [[0u64; 4]; 8];
            let mut nv = 0usize;
            if i == 0 {
                views[0] = self.phantoms[0];
                views[1] = self.phantoms[1];
                nv = 2;
            } else {
                for k in 0..parents.len {
                    views[nv] = self.materialize(parents.indices[k]);
                    nv += 1;
                    self.stats.parent_gathers += 1;
                }
            }
            self.stats.mix_pairs += if nv <= 1 { 1 } else { (nv as u64 + 1) / 2 };
            mix_views(&mut state, &views, nv);
            self.cache_put(i, state);
            for dest_opt in [parents.scatter_dest, parents.scatter_dest2] {
                if let Some(dest) = dest_opt {
                    if dest < n && dest != i {
                        if let Some(b) = self.cache.get_mut(&dest) {
                            xor_words(b, &state);
                        }
                        self.stats.scatters_logged += 1;
                    }
                }
            }
            if (i + 1) % self.stride == 0 {
                self.state_ckpt.insert(i + 1, state);
            }
        }
        self.as_of = n;
        self.stats.checkpoint_entries = self.state_ckpt.len();
        let last = self.materialize(n - 1);
        let dig = finalize(&self.seed, &state, &block_to_bytes(&last), self.cfg.graph);
        let mut out = [0u8; 32];
        out.copy_from_slice(&dig);
        out
    }
}

pub fn derive_tmto(
    password: &[u8],
    salt: &[u8],
    cfg: &AntechConfig,
    params: &TmtoParams,
    full_buf: &mut Option<Vec<[u64; 4]>>,
) -> ([u8; 32], TmtoStats) {
    match params.strategy {
        Strategy::FullPacked => {
            let n = cfg.num_blocks();
            if full_buf.as_ref().map(|b| b.len()) != Some(n) {
                *full_buf = Some(vec![[0u64; 4]; n]);
            }
            derive_full_packed(password, salt, cfg, full_buf.as_mut().unwrap())
        }
        Strategy::ScatterLog => {
            derive_scatter_log_full(password, salt, cfg, params.checkpoint_stride)
        }
        Strategy::Sparse => {
            let seed = bind_seed(password, salt, cfg);
            let mut atk =
                SparseAttack::new(cfg, seed, params.pristine_cap, params.checkpoint_stride);
            let d = atk.run();
            (d, atk.stats)
        }
        Strategy::Regen => {
            let seed = bind_seed(password, salt, cfg);
            let mut atk =
                RegenAttack::new(cfg, seed, params.pristine_cap, params.checkpoint_stride);
            let d = atk.run();
            (d, atk.stats)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectnessRow {
    pub strategy: String,
    pub memory_frac: f64,
    pub memory_mib_cfg: f64,
    pub vectors: usize,
    pub matched: usize,
    pub correct: bool,
    pub est_attacker_mib: f64,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepRow {
    pub strategy: String,
    pub memory_frac: f64,
    pub checkpoint_stride: usize,
    pub pristine_cap: usize,
    pub correct: bool,
    pub gps: f64,
    pub baseline_gps: f64,
    pub tmto_cost_factor: f64,
    pub nodes_recomputed: u64,
    pub mix_pairs: u64,
    pub scatters_replayed: u64,
    pub est_attacker_mib: f64,
    pub latency_ms: f64,
}

pub fn strategy_name(s: Strategy) -> &'static str {
    match s {
        Strategy::FullPacked => "full_packed",
        Strategy::ScatterLog => "scatter_log",
        Strategy::Sparse => "sparse_checkpoint",
        Strategy::Regen => "regen_recompute",
    }
}

pub fn check_correctness(
    cfg: &AntechConfig,
    params: &TmtoParams,
    vectors: usize,
    salt: &[u8],
) -> CorrectnessRow {
    let mut buf = None;
    let mut matched = 0usize;
    let mut last_stats = TmtoStats::default();
    for i in 0..vectors {
        let pw = format!("tmto_adv_vector_{:04}", i);
        let refer = reference_digest(pw.as_bytes(), salt, cfg);
        let (got, stats) = derive_tmto(pw.as_bytes(), salt, cfg, params, &mut buf);
        if stats.aborted {
            last_stats = stats;
            break;
        }
        if got.as_slice() == refer.as_slice() {
            matched += 1;
        }
        last_stats = stats;
    }
    let est = last_stats.estimated_bytes(32) as f64 / (1024.0 * 1024.0);
    let note = if last_stats.aborted {
        format!(
            "ABORTED_recompute_wall stride={} cap={} recomputed={}",
            params.checkpoint_stride, params.pristine_cap, last_stats.nodes_recomputed
        )
    } else {
        format!(
            "stride={} cap={} recomputed={}",
            params.checkpoint_stride, params.pristine_cap, last_stats.nodes_recomputed
        )
    };
    CorrectnessRow {
        strategy: strategy_name(params.strategy).into(),
        memory_frac: params.pristine_cap as f64 / cfg.num_blocks().max(1) as f64,
        memory_mib_cfg: cfg.memory.as_kib() as f64 / 1024.0,
        vectors,
        matched,
        correct: !last_stats.aborted && matched == vectors,
        est_attacker_mib: est,
        notes: note,
    }
}

pub fn measure_gps(
    cfg: &AntechConfig,
    params: &TmtoParams,
    salt: &[u8],
    duration: Duration,
) -> (f64, TmtoStats) {
    let mut buf = None;
    let pw = b"tmto_throughput_pw";
    let (_, mut last_stats) = derive_tmto(pw, salt, cfg, params, &mut buf);
    if last_stats.aborted {
        return (0.0, last_stats);
    }
    let start = Instant::now();
    let mut n = 0u64;
    while start.elapsed() < duration {
        let (_, st) = derive_tmto(pw, salt, cfg, params, &mut buf);
        last_stats = st;
        if last_stats.aborted {
            return (0.0, last_stats);
        }
        n += 1;
    }
    let secs = start.elapsed().as_secs_f64().max(1e-9);
    (n as f64 / secs, last_stats)
}

pub fn measure_gps_mt(
    cfg: &AntechConfig,
    params: &TmtoParams,
    salt: &[u8],
    threads: usize,
    duration: Duration,
) -> f64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let counter = Arc::new(AtomicU64::new(0));
    let params = params.clone();
    let cfg = *cfg;
    let salt = salt.to_vec();
    std::thread::scope(|s| {
        for t in 0..threads {
            let counter = Arc::clone(&counter);
            let params = params.clone();
            let salt = salt.clone();
            s.spawn(move || {
                let mut buf = None;
                let mut local = 0u64;
                let end = Instant::now() + duration;
                let mut i = t as u64;
                while Instant::now() < end {
                    let pw = format!("tmto_mt_{i}");
                    let (_, st) = derive_tmto(pw.as_bytes(), &salt, &cfg, &params, &mut buf);
                    if st.aborted {
                        break;
                    }
                    local += 1;
                    i = i.wrapping_add(threads as u64);
                }
                counter.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    counter.load(Ordering::Relaxed) as f64 / duration.as_secs_f64().max(1e-9)
}

pub fn memory_fractions() -> &'static [f64] {
    &[
        1.0, 0.75, 0.5, 0.375, 0.25, 0.1875, 0.125, 0.09375, 0.0625, 0.03125, 0.015625,
    ]
}

pub fn checkpoint_strides() -> &'static [usize] {
    &[2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"tmto_adv_salt_16b";

    #[test]
    fn full_packed_matches_engine() {
        let cfg = cfg_kib(1024);
        let mut buf = None;
        let params = TmtoParams {
            strategy: Strategy::FullPacked,
            pristine_cap: cfg.num_blocks(),
            checkpoint_stride: 1,
        };
        let (d, _) = derive_tmto(b"pwd", SALT, &cfg, &params, &mut buf);
        assert_eq!(
            d.as_slice(),
            reference_digest(b"pwd", SALT, &cfg).as_slice()
        );
    }

    #[test]
    fn scatter_log_full_matches_engine() {
        let cfg = cfg_kib(1024);
        let mut buf = None;
        let params = TmtoParams {
            strategy: Strategy::ScatterLog,
            pristine_cap: cfg.num_blocks(),
            checkpoint_stride: 64,
        };
        let (d, stats) = derive_tmto(b"pwd", SALT, &cfg, &params, &mut buf);
        assert_eq!(
            d.as_slice(),
            reference_digest(b"pwd", SALT, &cfg).as_slice()
        );
        assert!(stats.scatters_logged > 0);
    }

    #[test]
    fn sparse_half_cap_aborts_or_matches() {
        let cfg = cfg_kib(1024);
        let mut buf = None;
        let params = TmtoParams {
            strategy: Strategy::Sparse,
            pristine_cap: cfg.num_blocks() / 2,
            checkpoint_stride: 64,
        };
        let (d, stats) = derive_tmto(b"pwd_sparse", SALT, &cfg, &params, &mut buf);
        if stats.aborted {
            assert_eq!(d, [0u8; 32]);
            assert!(stats.nodes_recomputed > 0);
        } else {
            assert_eq!(
                d.as_slice(),
                reference_digest(b"pwd_sparse", SALT, &cfg).as_slice()
            );
        }
    }

    #[test]
    fn sparse_full_cap_matches() {
        let cfg = cfg_kib(1024);
        let mut buf = None;
        let params = TmtoParams {
            strategy: Strategy::Sparse,
            pristine_cap: cfg.num_blocks(),
            checkpoint_stride: 64,
        };
        let (d, stats) = derive_tmto(b"pwd_full_sparse", SALT, &cfg, &params, &mut buf);
        assert!(!stats.aborted);
        assert_eq!(
            d.as_slice(),
            reference_digest(b"pwd_full_sparse", SALT, &cfg).as_slice()
        );
    }

    #[test]
    fn caps_for_fraction_selects_sparse_or_regen() {
        let n = 32768usize;
        let p = caps_for_fraction(n, 0.75);
        assert!(matches!(p.strategy, Strategy::Sparse));
        assert!(p.pristine_cap < n);
        let p25 = caps_for_fraction(n, 0.25);
        assert!(matches!(p25.strategy, Strategy::Sparse));
        let p_low = caps_for_fraction(n, 0.015625);
        // 1.5625% of 32768 ≈ 512 blocks — still Sparse; Regen only if <128.
        assert!(matches!(p_low.strategy, Strategy::Sparse | Strategy::Regen));
    }

    #[test]
    fn regen_matches_when_cache_large() {
        let cfg = cfg_kib(1024);
        let mut buf = None;
        let params = TmtoParams {
            strategy: Strategy::Regen,
            pristine_cap: cfg.num_blocks(),
            checkpoint_stride: 256,
        };
        let (d, _) = derive_tmto(b"pwd", SALT, &cfg, &params, &mut buf);
        assert_eq!(
            d.as_slice(),
            reference_digest(b"pwd", SALT, &cfg).as_slice()
        );
    }

    #[test]
    fn window_miss_probe_runs() {
        let cfg = cfg_kib(1024);
        let st = probe_window_misses(b"probe", SALT, &cfg, cfg.num_blocks() / 4);
        assert!(st.parent_misses > 0);
        assert!(st.nodes_recomputed > 0);
    }
}
