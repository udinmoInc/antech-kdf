//! Private frontier ring — reusable within one verification, useless across guesses.

use super::config::FRONTIER_WIDTH;

/// Compact in-process copy of the most recent `FRONTIER_WIDTH` blocks.
/// Benefits sequential verifier locality; state-dependent and password-private,
/// so independent guesses cannot share it.
pub struct FrontierRing {
    width: usize,
    block_size: usize,
    /// Contiguous ring storage: width * block_size.
    data: Vec<u8>,
    /// Absolute block index of the newest entry, or None if empty.
    newest: Option<usize>,
    count: usize,
}

impl FrontierRing {
    pub fn new(block_size: usize) -> Self {
        let width = FRONTIER_WIDTH;
        Self {
            width,
            block_size,
            data: vec![0u8; width * block_size],
            newest: None,
            count: 0,
        }
    }

    #[inline(always)]
    pub fn push(&mut self, block_idx: usize, block: &[u8]) {
        let slot = block_idx % self.width;
        let off = slot * self.block_size;
        // Protocol block_size is 32; avoid per-byte min in the hot path.
        debug_assert_eq!(block.len(), self.block_size);
        self.data[off..off + self.block_size].copy_from_slice(block);
        self.newest = Some(block_idx);
        self.count = (self.count + 1).min(self.width);
    }

    /// Try to read block `idx` from the ring; returns None on miss.
    #[inline(always)]
    pub fn get<'a>(&'a self, idx: usize) -> Option<&'a [u8]> {
        let newest = self.newest?;
        if idx > newest {
            return None;
        }
        let age = newest - idx;
        let window = self.count.min(self.width);
        if age >= window {
            return None;
        }
        let off = (idx % self.width) * self.block_size;
        Some(&self.data[off..off + self.block_size])
    }
}
