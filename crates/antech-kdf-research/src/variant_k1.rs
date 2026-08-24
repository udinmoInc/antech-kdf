//! Canonical Variant K1 — Attacker Parallelism Reduction.
//! Candidate-dependent dynamic permutation forces unique state evolution per candidate, crippling SIMD batching.

use crate::candidate004::{ResearchError, ResearchKdf, ResearchParams};
use sha2::{Digest, Sha256};

pub struct VariantK1 {
    pub memory_kib: u32,
    pub dependency_depth: u32,
    pub passes: u32,
}

impl VariantK1 {
    pub fn new() -> Self {
        Self {
            memory_kib: 16384,        // 16 MB
            dependency_depth: 650000, // Defender latency ~108 ms
            passes: 1,
        }
    }

    #[inline(always)]
    fn arx_step_k1(state: &mut [u64; 4], block: &[u8], pwd_byte: u8) {
        let b0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let b1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        let b2 = u64::from_le_bytes(block[16..24].try_into().unwrap());
        let b3 = u64::from_le_bytes(block[24..32].try_into().unwrap());

        let rot = (pwd_byte as u32 % 16) + 1;
        state[0] = state[0]
            .wrapping_add(b0 ^ (pwd_byte as u64))
            .rotate_left(19 ^ rot)
            ^ state[3];
        state[1] = state[1].wrapping_add(b1).rotate_left(29 ^ rot) ^ state[0];
        state[2] = state[2]
            .wrapping_add(b2 ^ (pwd_byte as u64).rotate_left(8))
            .rotate_left(13)
            ^ state[1];
        state[3] = state[3].wrapping_add(b3).rotate_left(37 ^ rot) ^ state[2];
    }
}

impl Default for VariantK1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for VariantK1 {
    fn name(&self) -> &'static str {
        "variant-k1-parallelism-reduction"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let mut hasher = Sha256::new();
        hasher.update(b"antech-v1-domain-separator-variant-k1");
        hasher.update(password);
        hasher.update(salt);
        hasher.update(self.memory_kib.to_le_bytes());
        hasher.update(self.dependency_depth.to_le_bytes());
        let seed = hasher.finalize();

        let total_bytes = (self.memory_kib as usize) * 1024;
        let mut buffer = vec![0u8; total_bytes];

        for (chunk_idx, chunk) in buffer.chunks_mut(32).enumerate() {
            let mut h = Sha256::new();
            h.update(seed);
            h.update((chunk_idx as u64).to_le_bytes());
            let res = h.finalize();
            chunk.copy_from_slice(&res);
        }

        let num_blocks = total_bytes / 32;
        let mut state = [
            u64::from_le_bytes(seed[0..8].try_into().unwrap()),
            u64::from_le_bytes(seed[8..16].try_into().unwrap()),
            u64::from_le_bytes(seed[16..24].try_into().unwrap()),
            u64::from_le_bytes(seed[24..32].try_into().unwrap()),
        ];

        let pwd_len = password.len().max(1);

        for _pass in 0..self.passes {
            for step in 0..self.dependency_depth {
                let pwd_byte = password[step as usize % pwd_len];
                let idx1 = (state[0] ^ (step as u64) ^ (pwd_byte as u64)) as usize % num_blocks;
                let offset1 = idx1 * 32;
                let block1 = &buffer[offset1..offset1 + 32];

                let idx2 = (state[1] ^ (step as u64).rotate_left(16)) as usize % num_blocks;
                let offset2 = idx2 * 32;
                let block2 = &buffer[offset2..offset2 + 32];

                let mut mixed_block = [0u8; 32];
                for k in 0..32 {
                    mixed_block[k] = block1[k] ^ block2[k];
                }

                Self::arx_step_k1(&mut state, &mixed_block, pwd_byte);
            }
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(b"antech-v1-finalization-variant-k1");
        for val in &state {
            final_hasher.update(val.to_le_bytes());
        }
        Ok(final_hasher.finalize().to_vec())
    }
}
