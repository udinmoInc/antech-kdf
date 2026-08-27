//! Dependency address generators for the compute-memory graph.

use crate::config::{FRONTIER_WIDTH, TILE_BLOCKS};
use antech_kdf_types::GraphKind;

const GOLDEN: u64 = 0x9E3779B97F4A7C15;

pub const MAX_PARENTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeClass {
    Local,
    Critical,
}

#[derive(Debug, Clone, Copy)]
pub struct ParentSet {
    pub indices: [usize; MAX_PARENTS],
    pub len: usize,
    pub scatter_dest: Option<usize>,
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
    period > 0 && i.is_multiple_of(period)
}

#[inline(always)]
fn mix_index(state: &[u64; 4], i: usize, slot: usize) -> u64 {
    state[slot % 4] ^ (i as u64).wrapping_mul(GOLDEN)
}

#[inline(always)]
fn scatter_from_state2(state: &[u64; 4], span: usize) -> usize {
    ((state[2] ^ GOLDEN) as usize) % span
}

/// Fill remaining parent slots via `addr_fn(mix)`. Stops early if a push is a no-op.
#[inline(always)]
fn fill_fan_in(
    out: &mut ParentSet,
    state: &[u64; 4],
    i: usize,
    fan_in: u32,
    mut addr_fn: impl FnMut(u64) -> usize,
) {
    let mut guard = 0usize;
    while out.len < fan_in as usize && guard < 4 {
        guard += 1;
        let mix = mix_index(state, i, out.len);
        let before = out.len;
        out.push_unique(addr_fn(mix), i);
        if out.len == before {
            break;
        }
    }
}

#[inline(always)]
fn push_tile_local(out: &mut ParentSet, state: &[u64; 4], i: usize, tile_start: usize) {
    if i > tile_start + 1 {
        let span = i - tile_start;
        out.push_unique(tile_start + ((state[1] as usize) % span), i);
    }
}

#[inline(always)]
fn tile_or_global_addr(mix: u64, i: usize, tile_start: usize) -> usize {
    if i > tile_start {
        tile_start + ((mix as usize) % (i - tile_start).max(1))
    } else {
        (mix as usize) % i
    }
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
        let mix = mix_index(state, i, out.len);
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

#[inline(always)]
fn local_with_light_remote(out: &mut ParentSet, state: &[u64; 4], i: usize, fan_in: u32) {
    local_frontier_parents(out, state, i, 2);
    let fw = FRONTIER_WIDTH.min(i);
    if i > fw + 1 {
        let remote_span = i - fw;
        let remote = ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span;
        out.push_unique(remote, i);
    }
    fill_fan_in(out, state, i, fan_in, |mix| (mix as usize) % i);
}

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
        out.push_unique(scatter_from_state2(state, remote_span), i);
        let remote3 = ((state[0] ^ state[1].rotate_left(19)) as usize) % remote_span;
        out.push_unique(remote3, i);
    }

    out.scatter_dest = if i > fw {
        Some(scatter_from_state2(state, i - fw))
    } else {
        None
    };
    out
}

fn cache_locality(state: &[u64; 4], i: usize, fan_in: u32, tile_len: usize) -> ParentSet {
    let tile = tile_len.max(FRONTIER_WIDTH);
    let tile_start = (i / tile) * tile;
    let fw = FRONTIER_WIDTH.min(i);
    let on_far = i > 0 && i.is_multiple_of(fw);
    let on_boundary = i > 0 && i.is_multiple_of(tile);

    let mut out = ParentSet::empty(if on_far || on_boundary {
        NodeClass::Critical
    } else {
        NodeClass::Local
    });
    local_frontier_parents(&mut out, state, i, 2);

    if i > tile_start + 1 {
        push_tile_local(&mut out, state, i, tile_start);
    } else if i > 1 {
        out.push_unique((state[1] as usize) % i, i);
    }

    if i > fw {
        let far_span = i - fw;
        out.scatter_dest = Some(scatter_from_state2(state, far_span));
        if on_far || on_boundary {
            let far = ((state[3] ^ state[0].rotate_left(7)) as usize) % far_span;
            out.push_unique(far, i);
            let far2 = ((state[2] ^ state[1]) as usize) % far_span;
            out.push_unique(far2, i);
        }
    }

    fill_fan_in(&mut out, state, i, fan_in, |mix| {
        tile_or_global_addr(mix, i, tile_start)
    });
    out
}

/// Phase-1 CombinedFrontier parents: sequential + frontier only (no far / scatter).
/// Far addresses are intentionally deferred until after these are mixed (v5).
pub fn combined_local_parents(state: &[u64; 4], i: usize) -> ParentSet {
    if i == 0 {
        return ParentSet::empty(NodeClass::Local);
    }
    let mut out = ParentSet::empty(NodeClass::Local);
    local_frontier_parents(&mut out, state, i, 2);
    out
}

/// Phase-2 CombinedFrontier parents: dual-global + always-2 *cold* far gathers
/// from *post-local* state (far span excludes the last `max(tile, frontier)` blocks).
/// Scatter destinations are left unset; the engine fills them from the final post-mix state.
pub fn combined_remote_parents(
    state: &[u64; 4],
    i: usize,
    fan_in: u32,
    period: usize,
    tile_len: usize,
) -> ParentSet {
    if i == 0 {
        return ParentSet::empty(NodeClass::Local);
    }
    let _tile = tile_len.max(TILE_BLOCKS.min(512));
    let critical = is_critical(i, period.max(1)) || i.is_multiple_of(FRONTIER_WIDTH);

    let mut out = ParentSet::empty(if critical {
        NodeClass::Critical
    } else {
        NodeClass::Local
    });
    // Two global (not tile-local) gathers from post-local state: independent address
    // streams that thrash shared caches under multi-candidate load more than they
    // inflate a single verifier (one extra dependent load per node).
    if i > 1 {
        out.push_unique((state[1] as usize) % i, i);
        out.push_unique(((state[2] ^ state[0].rotate_left(13)) as usize) % i, i);
    }

    let fw = FRONTIER_WIDTH.min(i);
    // Exclude a larger hot tail than the frontier ring so far gathers hit colder
    // region of the live buffer (hurts multi-candidate shared-cache reuse).
    let cold = TILE_BLOCKS.min(512).max(fw);
    if i > cold + 1 {
        let remote_span = i - cold;
        // Every node: two state-dependent far gathers from post-local state.
        let far = ((state[1] ^ state[3].rotate_left(11)) as usize) % remote_span;
        out.push_unique(far, i);
        let far2 = ((state[0] ^ GOLDEN) as usize) % remote_span;
        out.push_unique(far2, i);
    }

    fill_fan_in(&mut out, state, i, fan_in, |mix| (mix as usize) % i);
    out
}

#[inline(always)]
pub fn scatter_dests_from_state(state: &[u64; 4], i: usize) -> (Option<usize>, Option<usize>) {
    let fw = FRONTIER_WIDTH.min(i);
    if i > fw {
        let span = i - fw;
        (
            Some(scatter_from_state2(state, span)),
            Some(((state[3] ^ state[0].rotate_left(7)) as usize) % span),
        )
    } else {
        (None, None)
    }
}

fn combined(state: &[u64; 4], i: usize, fan_in: u32, period: usize, tile_len: usize) -> ParentSet {
    // Single-shot view used by non-engine callers / tests. Engine uses two-phase APIs.
    let mut out = combined_local_parents(state, i);
    let remote = combined_remote_parents(state, i, fan_in, period, tile_len);
    for k in 0..remote.len {
        out.push_unique(remote.indices[k], i);
    }
    let (s1, s2) = scatter_dests_from_state(state, i);
    out.scatter_dest = s1;
    out.scatter_dest2 = s2;
    if remote.class == NodeClass::Critical {
        out.class = NodeClass::Critical;
    }
    out
}
