//! Dependency address generators for v4 optimized narrow-frontier graphs.
//!
//! Parent index lists are stack-resident (no per-node heap allocation).

use super::config::{GraphKind, FRONTIER_WIDTH, TILE_BLOCKS};

const GOLDEN: u64 = 0x9E3779B97F4A7C15;

/// Max parents resolved on the stack (fan_in <= 8, plus sparse remotes).
pub const MAX_PARENTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeClass {
    /// Cheap: sequential + local frontier only (no remote, no scatter).
    Local,
    /// Expensive: remote gather + optional scatter (attacker bottleneck).
    Critical,
}

#[derive(Debug, Clone, Copy)]
pub struct ParentSet {
    pub indices: [usize; MAX_PARENTS],
    pub len: usize,
    pub scatter_dest: Option<usize>,
    /// Optional second far-scatter (write amplification under concurrency).
    pub scatter_dest2: Option<usize>,
    pub class: NodeClass,
}

impl ParentSet {
    #[inline(always)]
    fn empty(class: NodeClass) -> Self {
        Self {
            indices: [0; MAX_PARENTS],
            len: 0,
            scatter_dest: None,
            scatter_dest2: None,
            class,
        }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[usize] {
        &self.indices[..self.len]
    }

    #[inline(always)]
    fn push_unique(&mut self, addr: usize, i: usize) {
        if addr >= i || self.len >= MAX_PARENTS {
            return;
        }
        for j in 0..self.len {
            if self.indices[j] == addr {
                return;
            }
        }
        self.indices[self.len] = addr;
        self.len += 1;
    }
}

/// Select parents for node `i` under the configured graph kind.
#[inline(always)]
pub fn parents_for_node(
    kind: GraphKind,
    state: &[u64; 4],
    i: usize,
    fan_in: u32,
    critical_period: usize,
    tile_len: usize,
) -> ParentSet {
    if i == 0 {
        return ParentSet::empty(NodeClass::Local);
    }

    match kind {
        GraphKind::ReducedCriticalPath => reduced_critical(state, i, fan_in, critical_period),
        GraphKind::CacheLocality => cache_locality(state, i, fan_in, tile_len),
        GraphKind::CombinedFrontier => combined(state, i, fan_in, critical_period, tile_len),
    }
}

#[inline(always)]
fn is_critical(i: usize, period: usize) -> bool {
    period > 0 && i % period == 0
}

#[inline(always)]
fn local_frontier_parents(out: &mut ParentSet, state: &[u64; 4], i: usize, fan_in: u32) {
    out.push_unique(i - 1, i);
    let fw = FRONTIER_WIDTH.min(i);
    let slot = (state[0] as usize) % fw;
    out.push_unique(i - 1 - slot, i);
    let mut guard = 0usize;
    while out.len < fan_in as usize && guard < fan_in as usize + 4 {
        guard += 1;
        let mix = state[out.len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let slot = (mix as usize) % fw;
        let before = out.len;
        out.push_unique(i - 1 - slot, i);
        if out.len == before {
            let slot2 = (state[2].wrapping_add(guard as u64) as usize) % fw;
            out.push_unique(i - 1 - slot2, i);
            if out.len == before {
                break;
            }
        }
    }
}

/// Local path that still performs one remote gather (no scatter).
/// Keeps per-guess DRAM footprints from collapsing when criticals are sparse.
#[inline(always)]
fn local_with_light_remote(out: &mut ParentSet, state: &[u64; 4], i: usize, fan_in: u32) {
    local_frontier_parents(out, state, i, 2);
    let fw = FRONTIER_WIDTH.min(i);
    if i > fw + 1 {
        let remote_span = i - fw;
        let remote = ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span;
        out.push_unique(remote, i);
    }
    let mut guard = 0usize;
    while out.len < fan_in as usize && guard < 4 {
        guard += 1;
        let mix = state[out.len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let before = out.len;
        out.push_unique((mix as usize) % i, i);
        if out.len == before {
            break;
        }
    }
}

/// A — Light remote every node; heavy remote+scatter every `critical_period`.
fn reduced_critical(state: &[u64; 4], i: usize, fan_in: u32, period: usize) -> ParentSet {
    if !is_critical(i, period) {
        let mut out = ParentSet::empty(NodeClass::Local);
        local_with_light_remote(&mut out, state, i, fan_in);
        return out;
    }

    let mut out = ParentSet::empty(NodeClass::Critical);
    local_with_light_remote(&mut out, state, i, fan_in.max(2));
    let fw = FRONTIER_WIDTH.min(i);
    if i > fw + 1 {
        let remote_span = i - fw;
        // Extra far remotes on critical nodes — multi-instance contention amplifier.
        let remote2 = ((state[2] ^ GOLDEN) as usize) % remote_span;
        out.push_unique(remote2, i);
        let remote3 = ((state[0] ^ state[1].rotate_left(19)) as usize) % remote_span;
        out.push_unique(remote3, i);
    }

    out.scatter_dest = if i > fw {
        let span = i - fw;
        Some(((state[2] ^ GOLDEN) as usize) % span)
    } else {
        None
    };
    out
}

/// B — Prefer remotes inside the current tile; far remote every frontier step.
/// Far *scatter* on every node (write amplification) to hurt multi-instance
/// LLC sharing while tile-local reads keep single-stream latency low.
fn cache_locality(state: &[u64; 4], i: usize, fan_in: u32, tile_len: usize) -> ParentSet {
    let tile = tile_len.max(FRONTIER_WIDTH);
    let tile_start = (i / tile) * tile;
    let fw = FRONTIER_WIDTH.min(i);
    let on_far = i > 0 && i % fw == 0;
    let on_boundary = i > 0 && i % tile == 0;

    let mut out = ParentSet::empty(if on_far || on_boundary {
        NodeClass::Critical
    } else {
        NodeClass::Local
    });
    local_frontier_parents(&mut out, state, i, 2);

    // In-tile remote (hot for a single sequential verifier).
    if i > tile_start + 1 {
        let span = i - tile_start;
        let local_remote = tile_start + ((state[1] as usize) % span);
        out.push_unique(local_remote, i);
    } else if i > 1 {
        out.push_unique((state[1] as usize) % i, i);
    }

    if i > fw {
        let far_span = i - fw;
        // Always far-scatter: write traffic crosses the growing DAG and
        // contends under concurrent independent guesses.
        out.scatter_dest = Some(((state[2] ^ GOLDEN) as usize) % far_span);
        if on_far || on_boundary {
            let far = ((state[3] ^ state[0].rotate_left(7)) as usize) % far_span;
            out.push_unique(far, i);
            let far2 = ((state[2] ^ state[1]) as usize) % far_span;
            out.push_unique(far2, i);
        }
    }

    let mut guard = 0usize;
    while out.len < fan_in as usize && guard < 4 {
        guard += 1;
        let mix = state[out.len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let addr = if i > tile_start {
            tile_start + ((mix as usize) % (i - tile_start).max(1))
        } else {
            (mix as usize) % i
        };
        let before = out.len;
        out.push_unique(addr, i);
        if out.len == before {
            break;
        }
    }
    out
}

/// C — Combined: tile-local reads, pulsed far gathers, dual far scatter every
/// node, denser critical far gathers. Tuned for <100 ms defender with write contention.
fn combined(
    state: &[u64; 4],
    i: usize,
    fan_in: u32,
    period: usize,
    tile_len: usize,
) -> ParentSet {
    let tile = tile_len.max(TILE_BLOCKS.min(512));
    let tile_start = (i / tile) * tile;
    // Use structural critical_period as-is (no artificial sparseness) so far
    // gathers fire often enough to keep multi-instance DRAM contested.
    let critical = is_critical(i, period.max(1)) || (i > 0 && i % FRONTIER_WIDTH == 0);

    let mut out = ParentSet::empty(if critical {
        NodeClass::Critical
    } else {
        NodeClass::Local
    });
    local_frontier_parents(&mut out, state, i, 2);

    // Tile-local remote (verifier locality).
    if i > tile_start + 1 {
        let span = i - tile_start;
        let local_remote = tile_start + ((state[1] as usize) % span);
        out.push_unique(local_remote, i);
    }

    let fw = FRONTIER_WIDTH.min(i);
    if i > fw + 1 {
        let remote_span = i - fw;
        // Pulse far gathers: every other node for read contention, dual far on critical.
        // Keeps most traffic tile-local for the sequential verifier.
        if critical || (i & 1) == 0 {
            let far = ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span;
            out.push_unique(far, i);
        }
        if critical {
            let far2 = ((state[0] ^ GOLDEN) as usize) % remote_span;
            out.push_unique(far2, i);
        }
    }

    let mut guard = 0usize;
    while out.len < fan_in as usize && guard < 4 {
        guard += 1;
        let mix = state[out.len % 4] ^ (i as u64).wrapping_mul(GOLDEN);
        let before = out.len;
        // Prefer in-tile fill for leftover fan-in.
        let addr = if i > tile_start {
            tile_start + ((mix as usize) % (i - tile_start).max(1))
        } else {
            (mix as usize) % i
        };
        out.push_unique(addr, i);
        if out.len == before {
            break;
        }
    }

    if i > fw {
        let span = i - fw;
        out.scatter_dest = Some(((state[2] ^ GOLDEN) as usize) % span);
        // Second far write: sequential stream still mostly hits warm L3;
        // concurrent independent guesses thrash the same address space harder.
        out.scatter_dest2 = Some(((state[3] ^ state[0].rotate_left(7)) as usize) % span);
    }
    out
}
