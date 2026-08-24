//! Candidate 004 Opt-003: Depth & Chain Tuning.
//! Reduces dependency depth by 50% (depth = D/2) to measure latency vs TMTO recomputation penalty.

use super::{Candidate004Variant, OptParams};
use sha2::{Digest, Sha256};

pub struct Candidate004Opt003;

impl Candidate004Variant for Candidate004Opt003 {
    fn variant_id(&self) -> &'static str {
        "candidate-004-opt-003"
    }

    fn description(&self) -> &'static str {
        "Tuned dependency depth (depth = D/2 = 100 rounds) to reduce latency while auditing TMTO penalty"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &OptParams,
    ) -> Result<Vec<u8>, String> {
        let size = params.working_set_bytes.max(1024);
        let mut buffer = vec![0u8; size];
        let num_blocks = size / 64;

        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        let mut state = [0u8; 32];
        state.copy_from_slice(&seed);

        // Half depth (D/2 = 100 steps)
        let depth = (params.dependency_depth / 2).max(100);

        for step in 0..depth {
            let addr_val = u64::from_le_bytes(state[0..8].try_into().unwrap());
            let block_idx = (addr_val as usize) % num_blocks;
            let offset = block_idx * 64;

            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(&buffer[offset..offset + 64]);
            step_hasher.update(&step.to_le_bytes());
            let digest = step_hasher.finalize();

            for b in 0..32 {
                buffer[offset + b] ^= digest[b];
                state[b] = digest[b];
            }
        }

        Ok(state.to_vec())
    }
}
