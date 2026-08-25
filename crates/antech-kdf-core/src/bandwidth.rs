//! Memory bandwidth access rate evaluation.

use crate::error::CoreError;

#[derive(Debug, Clone, Copy)]
pub struct BandwidthTracker {
    pub target_mb_per_sec: u64,
}

impl BandwidthTracker {
    pub fn new(target_mb_per_sec: u64) -> Self {
        Self { target_mb_per_sec }
    }

    pub fn execute_churn(&self, buffer: &mut [u8], iterations: u32) -> Result<(), CoreError> {
        if buffer.is_empty() {
            return Ok(());
        }

        for it in 0..iterations {
            let mut acc: u8 = (it & 0xFF) as u8;
            for byte in buffer.iter_mut() {
                acc = byte.wrapping_add(acc).wrapping_mul(31);
                *byte = acc;
            }
        }
        Ok(())
    }
}
