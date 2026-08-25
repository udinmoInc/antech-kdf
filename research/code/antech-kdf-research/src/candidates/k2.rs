//! Variant K2 — Quad-Node TMTO Graph.

use super::cand_004::{ResearchError, ResearchKdf, ResearchParams};
use sha2::{Digest, Sha256};

pub struct VariantK2 {
    pub default_params: ResearchParams,
}

impl VariantK2 {
    pub fn new() -> Self {
        Self {
            default_params: ResearchParams {
                memory_kib: 16384,        // 16 MB default
                dependency_depth: 550000, // Default depth for ~112 ms defender latency
                passes: 1,
                block_size: 32,
            },
        }
    }

    #[inline(always)]
    fn arx_step_quad(state: &mut [u64; 4], block: &[u8]) {
        let b0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let b1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        let b2 = u64::from_le_bytes(block[16..24].try_into().unwrap());
        let b3 = u64::from_le_bytes(block[24..32].try_into().unwrap());

        state[0] = state[0].wrapping_add(b0).rotate_left(19) ^ state[3];
        state[1] = state[1].wrapping_add(b1).rotate_left(29) ^ state[0];
        state[2] = state[2].wrapping_add(b2).rotate_left(13) ^ state[1];
        state[3] = state[3].wrapping_add(b3).rotate_left(37) ^ state[2];
    }
}

impl Default for VariantK2 {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for VariantK2 {
    fn name(&self) -> &'static str {
        "variant-k2-quad-tmto"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let memory_kib = if params.memory_kib > 0 {
            params.memory_kib
        } else {
            self.default_params.memory_kib
        };
        let dependency_depth = if params.dependency_depth > 0 {
            params.dependency_depth
        } else {
            self.default_params.dependency_depth
        };
        let passes = if params.passes > 0 {
            params.passes
        } else {
            self.default_params.passes
        };

        let mut hasher = Sha256::new();
        hasher.update(b"antech-v1-domain-separator-variant-k2");
        hasher.update(password);
        hasher.update(salt);
        hasher.update(memory_kib.to_le_bytes());
        hasher.update(dependency_depth.to_le_bytes());
        let seed = hasher.finalize();

        let total_bytes = (memory_kib as usize) * 1024;
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

        for _pass in 0..passes {
            for step in 0..dependency_depth {
                let idx1 = (state[0] ^ (step as u64)) as usize % num_blocks;
                let idx2 = (state[1] ^ (step as u64).rotate_left(16)) as usize % num_blocks;
                let idx3 = (state[2] ^ (step as u64).rotate_left(32)) as usize % num_blocks;
                let idx4 = (state[3] ^ (step as u64).rotate_left(48)) as usize % num_blocks;

                let offset1 = idx1 * 32;
                let offset2 = idx2 * 32;
                let offset3 = idx3 * 32;
                let offset4 = idx4 * 32;

                let block1 = &buffer[offset1..offset1 + 32];
                let block2 = &buffer[offset2..offset2 + 32];
                let block3 = &buffer[offset3..offset3 + 32];
                let block4 = &buffer[offset4..offset4 + 32];

                let mut mixed_block = [0u8; 32];
                for k in 0..32 {
                    mixed_block[k] = block1[k] ^ block2[k] ^ block3[k] ^ block4[k];
                }

                Self::arx_step_quad(&mut state, &mixed_block);
            }
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(b"antech-v1-finalization-variant-k2");
        for val in &state {
            final_hasher.update(val.to_le_bytes());
        }
        Ok(final_hasher.finalize().to_vec())
    }
}
