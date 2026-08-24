//! Candidate-004 Formal Symmetric Research KDF Engine.
//! 100% deterministic execution path for all inputs. Zero asymmetry flags or shortcuts.

use super::{ResearchError, ResearchKdf, ResearchParams};
use sha2::{Digest, Sha256};

pub struct Candidate004Symmetric;

impl ResearchKdf for Candidate004Symmetric {
    fn name(&self) -> &'static str {
        "candidate-004-symmetric"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let size = (params.memory_kib as usize) * 1024;
        if size < 1024 {
            return Err(ResearchError::InvalidParameters(
                "Memory size must be at least 1 KiB".to_string(),
            ));
        }

        let mut buffer = vec![0u8; size];
        let num_u64_blocks = (size / 32).max(1);

        // 1. Cryptographically bind inputs: K0 = Sha256("antech-v1-domain" || P || S || Params)
        let mut hasher = Sha256::new();
        hasher.update(b"antech-v1-domain-separator-2026");
        hasher.update(password);
        hasher.update(salt);
        hasher.update(&params.memory_kib.to_le_bytes());
        hasher.update(&params.dependency_depth.to_le_bytes());
        let seed = hasher.finalize();

        // 2. Memory Initialization via Seed Expansion
        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        // 3. Initial State Setup
        let mut state = [0u64; 4];
        for i in 0..4 {
            state[i] = u64::from_le_bytes(seed[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        // 4. Sequential Memory Churn Loop (u64 ARX updates)
        for pass in 0..params.passes {
            for step in 0..params.dependency_depth {
                let block_idx = (state[0] as usize) % num_u64_blocks;
                let offset = block_idx * 32;

                let mut block_u64 = [0u64; 4];
                for i in 0..4 {
                    block_u64[i] = u64::from_le_bytes(
                        buffer[offset + i * 8..offset + (i + 1) * 8]
                            .try_into()
                            .unwrap(),
                    );
                }

                state[0] = (state[0].wrapping_add(block_u64[0])).rotate_left(19) ^ (step as u64) ^ (pass as u64);
                state[1] = (state[1].wrapping_add(block_u64[1])).rotate_left(29) ^ state[0];
                state[2] = (state[2].wrapping_add(block_u64[2])).rotate_left(13) ^ state[1];
                state[3] = (state[3].wrapping_add(block_u64[3])).rotate_left(37) ^ state[2];

                for i in 0..4 {
                    let updated = block_u64[i] ^ state[i];
                    buffer[offset + i * 8..offset + (i + 1) * 8]
                        .copy_from_slice(&updated.to_le_bytes());
                }
            }
        }

        // 5. Final Output Derivation
        let mut final_hasher = Sha256::new();
        final_hasher.update(b"antech-v1-finalization");
        for i in 0..4 {
            final_hasher.update(&state[i].to_le_bytes());
        }
        Ok(final_hasher.finalize().to_vec())
    }
}
