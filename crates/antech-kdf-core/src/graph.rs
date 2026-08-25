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

    if i > tile_start + 1 {
        let span = i - tile_start;
        let local_remote = tile_start + ((state[1] as usize) % span);
        out.push_unique(local_remote, i);
    } else if i > 1 {
        out.push_unique((state[1] as usize) % i, i);
    }

    if i > fw {
        let far_span = i - fw;
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

fn combined(state: &[u64; 4], i: usize, fan_in: u32, period: usize, tile_len: usize) -> ParentSet {
    let tile = tile_len.max(TILE_BLOCKS.min(512));
    let tile_start = (i / tile) * tile;
    let critical = is_critical(i, period.max(1)) || (i > 0 && i % FRONTIER_WIDTH == 0);

    let mut out = ParentSet::empty(if critical {
        NodeClass::Critical
    } else {
        NodeClass::Local
    });
    local_frontier_parents(&mut out, state, i, 2);

    if i > tile_start + 1 {
        let span = i - tile_start;
        let local_remote = tile_start + ((state[1] as usize) % span);
        out.push_unique(local_remote, i);
    }

    let fw = FRONTIER_WIDTH.min(i);
    if i > fw + 1 {
        let remote_span = i - fw;
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
        out.scatter_dest2 = Some(((state[3] ^ state[0].rotate_left(7)) as usize) % span);
    }
    out
}
