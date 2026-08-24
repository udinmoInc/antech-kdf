//! Candidate 006: Family F — Anti-Cache Strided Access.
//! Non-contiguous strided access pattern across memory pages to defeat CPU L1/L2/L3 cache locality.

use super::{ExperimentalKdf, ExperimentalParams};
use sha2::{Digest, Sha256};

pub struct Candidate006;

impl ExperimentalKdf for Candidate006 {
    fn name(&self) -> &'static str {
        "candidate-006"
    }

    fn family(&self) -> &'static str {
        "Family F — Anti-Cache Strided Access"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String> {
        let size = params.working_set_bytes.max(64 * 1024);
        let mut buffer = vec![0u8; size];
        let stride = 4096 + 64; // Strided access across 4 KiB page boundaries

        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        let mut ptr = 0usize;
        let passes = (params.rounds * 1000).max(5000);

        for step in 0..passes {
            let chunk_end = (ptr + 64).min(size);
            if chunk_end - ptr == 64 {
                let mut step_hasher = Sha256::new();
                step_hasher.update(&buffer[ptr..ptr + 64]);
                step_hasher.update(&(step as u64).to_le_bytes());
                let digest = step_hasher.finalize();

                for b in 0..32 {
                    buffer[ptr + b] ^= digest[b];
                }
            }

            ptr = (ptr + stride) % (size - 64);
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(&buffer[0..64.min(size)]);
        final_hasher.update(&buffer[size.saturating_sub(64)..size]);
        Ok(final_hasher.finalize().to_vec())
    }
}
