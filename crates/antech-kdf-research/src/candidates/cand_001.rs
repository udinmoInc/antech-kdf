//! Candidate 001: Family A — Low-Capacity Memory Churn.
//! Small working set (4..32 MiB) + high repeated memory movement.

use super::{ExperimentalKdf, ExperimentalParams};
use sha2::{Digest, Sha256};

pub struct Candidate001;

impl ExperimentalKdf for Candidate001 {
    fn name(&self) -> &'static str {
        "candidate-001"
    }

    fn family(&self) -> &'static str {
        "Family A — Low-Capacity Memory Churn"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String> {
        let size = params.working_set_bytes.max(1024);
        let mut buffer = vec![0u8; size];

        // Seed buffer
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        // Memory churn loop
        for r in 0..params.rounds {
            for chunk_idx in 0..(size / 64) {
                let offset = chunk_idx * 64;
                let mut chunk_hasher = Sha256::new();
                chunk_hasher.update(&buffer[offset..offset + 64]);
                chunk_hasher.update(&(r as u64).to_le_bytes());
                let digest = chunk_hasher.finalize();

                for b in 0..32 {
                    buffer[offset + b] ^= digest[b];
                }
            }
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(&buffer[0..64.min(size)]);
        final_hasher.update(&buffer[size.saturating_sub(64)..size]);
        Ok(final_hasher.finalize().to_vec())
    }
}
