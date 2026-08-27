//! Private frontier ring for sequential verifier locality.

use crate::config::FRONTIER_WIDTH;

pub struct FrontierRing {
    width: usize,
    block_size: usize,
    data: Vec<u8>,
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
        debug_assert_eq!(block.len(), self.block_size);
        self.data[off..off + self.block_size].copy_from_slice(block);
        self.newest = Some(block_idx);
        self.count = (self.count + 1).min(self.width);
    }

    #[inline(always)]
    pub fn get(&self, idx: usize) -> Option<&[u8]> {
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
