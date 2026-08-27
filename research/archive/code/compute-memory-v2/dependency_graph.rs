//! Dependency graph generated from structural config + live state.
//!
//! For DAG node `i`, parents are chosen among already-computed nodes `[0, i)`.
//! Fan-in is structural; the first parent is always the sequential predecessor
//! when `i > 0`, so the chain cannot be parallelized away.

/// Parent indices for one DAG node (empty only when handled as node-0 phantoms).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentSet {
    pub indices: Vec<usize>,
}

const GOLDEN: u64 = 0x9E3779B97F4A7C15;

/// Compute parent addresses for block `i` from the current state and fan-in.
///
/// - `i == 0`: returns empty (callers use seed phantoms).
/// - `i > 0`: parent[0] = `i - 1` (sequential); remaining parents are
///   state-dependent indices in `[0, i)`.
pub fn parents_for_node(state: &[u64; 4], i: usize, fan_in: u32) -> ParentSet {
    if i == 0 {
        return ParentSet {
            indices: Vec::new(),
        };
    }

    let fan = fan_in.max(1) as usize;
    let mut indices = Vec::with_capacity(fan);
    indices.push(i - 1);

    for p in 1..fan {
        let mix = state[p % 4]
            ^ (i as u64).wrapping_mul(GOLDEN)
            ^ (p as u64).wrapping_mul(0xBF58476D1CE4E5B9)
            ^ state[(p + 1) % 4].rotate_left((p as u32 * 11) % 63 + 1);
        let mut addr = (mix as usize) % i;
        // Prefer diversity vs the sequential parent when possible.
        if addr == i - 1 && i > 1 {
            addr = (addr + 1 + (state[0] as usize % (i - 1))) % i;
        }
        indices.push(addr);
    }

    ParentSet { indices }
}

/// Logarithmic back-reference distance used in documentation / analysis.
pub fn graph_log_span(num_blocks: usize) -> u32 {
    (num_blocks as u64)
        .next_power_of_two()
        .trailing_zeros()
        .max(1)
}
