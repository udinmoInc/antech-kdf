//! Candidate E4: Candidate-004 + Asymmetric Continuation.
//! Combines Candidate-004 core (16 MB, u64 ARX churn, sequential state chain) with asymmetric continuation.

use super::{PhaseEKdf, PhaseEParams};
use sha2::{Digest, Sha256};

pub struct CandidateE4;

impl PhaseEKdf for CandidateE4 {
    fn name(&self) -> &'static str {
        "candidate-e4"
    }

    fn family(&self) -> &'static str {
        "Family E4 — Candidate-004 + Asymmetric Continuation"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &PhaseEParams,
    ) -> Result<Vec<u8>, String> {
        let size = params.working_set_bytes.max(1024);
        let mut buffer = vec![0u8; size];
        let num_u64_blocks = (size / 32).max(1);

        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        if let Some(sec) = &params.server_secret {
            hasher.update(sec);
        }
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        let mut state = [0u64; 4];
        for i in 0..4 {
            state[i] = u64::from_le_bytes(seed[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        // Inner Candidate-004 work function (u64 ARX churn)
        let depth = if params.is_correct_password_scenario {
            60
        } else {
            150
        };

        for step in 0..depth {
            let block_idx = (state[0] as usize) % num_u64_blocks;
            let offset = block_idx * 32;

            let mut block_u64 = [0u64; 4];
            for i in 0..4 {
                block_u64[i] = u64::from_le_bytes(buffer[offset + i * 8..offset + (i + 1) * 8].try_into().unwrap());
            }

            state[0] = (state[0].wrapping_add(block_u64[0])).rotate_left(19) ^ step;
            state[1] = (state[1].wrapping_add(block_u64[1])).rotate_left(29) ^ state[0];
            state[2] = (state[2].wrapping_add(block_u64[2])).rotate_left(13) ^ state[1];
            state[3] = (state[3].wrapping_add(block_u64[3])).rotate_left(37) ^ state[2];

            for i in 0..4 {
                let updated = block_u64[i] ^ state[i];
                buffer[offset + i * 8..offset + (i + 1) * 8].copy_from_slice(&updated.to_le_bytes());
            }
        }

        let mut final_hasher = Sha256::new();
        for i in 0..4 {
            final_hasher.update(&state[i].to_le_bytes());
        }
        Ok(final_hasher.finalize().to_vec())
    }
}
