//! Candidate 007: Family G — Password-Dependent Access.
//! Dynamic memory access pattern selected by evolving password-derived state.

use super::{ExperimentalKdf, ExperimentalParams};
use sha2::{Digest, Sha256};

pub struct Candidate007;

impl ExperimentalKdf for Candidate007 {
    fn name(&self) -> &'static str {
        "candidate-007"
    }

    fn family(&self) -> &'static str {
        "Family G — Password-Dependent Access"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String> {
        let size = params.working_set_bytes.max(1024);
        let num_blocks = (size / 64).max(1);
        let mut buffer = vec![0u8; size];

        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let mut state = hasher.finalize().to_vec();

        for i in 0..size {
            buffer[i] = state[i % 32] ^ (i as u8);
        }

        // Password-dependent memory indexing
        let steps = (params.rounds * 500).max(2000);
        for step in 0..steps {
            let addr_a = (u32::from_le_bytes(state[0..4].try_into().unwrap()) as usize) % num_blocks;
            let addr_b = (u32::from_le_bytes(state[4..8].try_into().unwrap()) as usize) % num_blocks;

            let off_a = addr_a * 64;
            let off_b = addr_b * 64;

            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(&buffer[off_a..off_a + 64]);
            step_hasher.update(&buffer[off_b..off_b + 64]);
            step_hasher.update(&(step as u64).to_le_bytes());
            let digest = step_hasher.finalize();

            for b in 0..32 {
                buffer[off_a + b] ^= digest[b];
                state[b] = digest[b];
            }
        }

        Ok(state)
    }
}
