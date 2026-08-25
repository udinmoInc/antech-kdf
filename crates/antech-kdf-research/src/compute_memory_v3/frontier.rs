//! Frontier helpers (narrow-frontier ring indexing).

use super::config::FRONTIER_WIDTH;

/// Map a logical frontier slot to a block index relative to current `i`.
#[inline(always)]
pub fn frontier_index(i: usize, slot: usize) -> usize {
    let fw = FRONTIER_WIDTH.min(i.max(1));
    let slot = slot % fw;
    i.saturating_sub(1).saturating_sub(slot)
}

pub fn frontier_width() -> usize {
    FRONTIER_WIDTH
}
