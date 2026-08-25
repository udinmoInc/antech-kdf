//! Dependency address generators for v3 graph kinds.

use super::config::{GraphKind, FRONTIER_WIDTH};

const GOLDEN: u64 = 0x9E3779B97F4A7C15;

#[derive(Debug, Clone)]
pub struct ParentSet {
    pub indices: Vec<usize>,
    /// Optional remote write target (narrow-frontier scatter).
    pub scatter_dest: Option<usize>,
}

/// Select parents for node `i` under the configured graph kind.
pub fn parents_for_node(
    kind: GraphKind,
    state: &[u64; 4],
    i: usize,
    fan_in: u32,
    epoch_len: usize,
) -> ParentSet {
    if i == 0 {
        return ParentSet {
            indices: Vec::new(),
            scatter_dest: None,
        };
    }

    match kind {
        GraphKind::SequentialCut => sequential_cut(state, i, fan_in, epoch_len),
        GraphKind::Recursive => recursive_deps(state, i, fan_in),
        GraphKind::NarrowFrontier => narrow_frontier(state, i, fan_in),
    }
}

fn sequential_cut(state: &[u64; 4], i: usize, fan_in: u32, epoch_len: usize) -> ParentSet {
    let epoch = epoch_len.max(1);
    let mut indices = Vec::with_capacity(fan_in as usize);
    indices.push(i - 1);

    let cut = if i >= epoch {
        let prev_epoch_end = (i / epoch) * epoch;
        prev_epoch_end.saturating_sub(1)
    } else {
        0
    };
    if cut != i - 1 {
        indices.push(cut);
    }

    while indices.len() < fan_in as usize {
        let mix = state[indices.len() % 4]
            ^ (i as u64).wrapping_mul(GOLDEN)
            ^ state[0].rotate_left(17);
        let min_dist = (i / 4).max(1);
        let span = i.saturating_sub(min_dist).max(1);
        let mut addr = mix as usize % span;
        if addr == i - 1 || indices.contains(&addr) {
            addr = addr.saturating_sub(1) % i.max(1);
        }
        if !indices.contains(&addr) {
            indices.push(addr);
        } else {
            break;
        }
    }

    ParentSet {
        indices,
        scatter_dest: None,
    }
}

fn recursive_deps(state: &[u64; 4], i: usize, fan_in: u32) -> ParentSet {
    let mut indices = Vec::with_capacity(fan_in as usize);
    indices.push(i - 1);

    let log = (i as u64).next_power_of_two().trailing_zeros().max(1);
    let k = (state[0] % log as u64) as u32;
    let pow_back = 1usize << k.min(30);
    if pow_back < i {
        let p = i - pow_back;
        if !indices.contains(&p) {
            indices.push(p);
        }
    }

    let left = ((state[1] ^ state[2]) as usize) % i;
    let right = i - 1;
    let mid = left + (right.saturating_sub(left) / 2);
    if mid < i && !indices.contains(&mid) {
        indices.push(mid);
    }

    while indices.len() < fan_in as usize {
        let mix = state[2].wrapping_mul(GOLDEN) ^ (indices.len() as u64);
        let addr = (mix as usize) % i;
        if !indices.contains(&addr) {
            indices.push(addr);
        } else {
            break;
        }
    }

    ParentSet {
        indices,
        scatter_dest: None,
    }
}

fn narrow_frontier(state: &[u64; 4], i: usize, fan_in: u32) -> ParentSet {
    let mut indices = Vec::with_capacity(fan_in as usize);
    indices.push(i - 1);

    let fw = FRONTIER_WIDTH.min(i);
    let frontier_slot = (state[0] as usize) % fw;
    let frontier_idx = i - 1 - frontier_slot;
    if frontier_idx < i && !indices.contains(&frontier_idx) {
        indices.push(frontier_idx);
    }

    if i > fw + 1 {
        let remote_span = i - fw;
        let remote = ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span;
        if !indices.contains(&remote) {
            indices.push(remote);
        }
    }

    while indices.len() < fan_in as usize {
        let mix = state[indices.len() % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let addr = (mix as usize) % i;
        if !indices.contains(&addr) {
            indices.push(addr);
        } else {
            break;
        }
    }

    let scatter = if i > fw {
        let span = i - fw;
        Some(((state[2] ^ GOLDEN) as usize) % span)
    } else {
        None
    };

    ParentSet {
        indices,
        scatter_dest: scatter,
    }
}
