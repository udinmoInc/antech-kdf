//! Candidate 004: Family D — Dependency + Memory Churn.
//! Small working set + high-frequency churn + deep sequential dependency + password-dependent addressing.

use super::{ExperimentalKdf, ExperimentalParams};
use sha2::{Digest, Sha256};

pub struct Candidate004;

impl ExperimentalKdf for Candidate004 {
    fn name(&self) -> &'static str {
        "candidate-004"
    }

    fn family(&self) -> &'static str {
        "Family D — Dependency + Memory Churn"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String> {
        let size = params.working_set_bytes.max(1024);
        let mut buffer = vec![0u8; size];
        let num_blocks = size / 64;

        // Seed buffer
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        let mut state = seed.to_vec();

        // Churn loop with sequential state chain & state-dependent addressing
        for step in 0..params.dependency_depth.max(500) {
            let addr_val = u64::from_le_bytes(state[0..8].try_into().unwrap());
            let block_idx = (addr_val as usize) % num_blocks;
            let offset = block_idx * 64;

            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(&buffer[offset..offset + 64]);
            step_hasher.update(&step.to_le_bytes());
            let digest = step_hasher.finalize();

            // Mutate buffer & evolve state sequentially
            for b in 0..32 {
                buffer[offset + b] ^= digest[b];
                state[b] = digest[b];
            }
        }

        Ok(state)
    }
}
