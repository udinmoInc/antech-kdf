//! Variant C — GPU-Unfriendly Dependency.
//! Unpredictable branchless memory strides induce GPU warp divergence & cache misses.

use crate::phase_f::{ResearchError, ResearchKdf, ResearchParams};
use sha2::{Digest, Sha256};

pub struct VariantC {
    pub memory_kib: u32,
    pub dependency_depth: u32,
    pub passes: u32,
}

impl VariantC {
    pub fn new() -> Self {
        Self {
            memory_kib: 16384,     // 16 MB
            dependency_depth: 450000, // Fast defender latency (~102 ms)
            passes: 1,
        }
    }

    #[inline(always)]
    fn arx_step_stride(state: &mut [u64; 4], block: &[u8]) {
        let b0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let b1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        let b2 = u64::from_le_bytes(block[16..24].try_into().unwrap());
        let b3 = u64::from_le_bytes(block[24..32].try_into().unwrap());

        state[0] = state[0].wrapping_add(b0).rotate_left(23) ^ state[2];
        state[1] = state[1].wrapping_add(b1).rotate_left(31) ^ state[3];
        state[2] = state[2].wrapping_add(b2).rotate_left(17) ^ state[0];
        state[3] = state[3].wrapping_add(b3).rotate_left(41) ^ state[1];
    }
}

impl ResearchKdf for VariantC {
    fn name(&self) -> &'static str {
        "variant-c-gpu-unfriendly"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let mut hasher = Sha256::new();
        hasher.update(b"antech-v1-domain-separator-variant-c");
        hasher.update(password);
        hasher.update(salt);
        hasher.update(&self.memory_kib.to_le_bytes());
        hasher.update(&self.dependency_depth.to_le_bytes());
        let seed = hasher.finalize();

        let total_bytes = (self.memory_kib as usize) * 1024;
        let mut buffer = vec![0u8; total_bytes];

        for (chunk_idx, chunk) in buffer.chunks_mut(32).enumerate() {
            let mut h = Sha256::new();
            h.update(&seed);
            h.update(&(chunk_idx as u64).to_le_bytes());
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

        // Non-linear stride memory lookup pattern
        for _pass in 0..self.passes {
            for step in 0..self.dependency_depth {
                let stride = (state[3] & 0x0F) as usize + 1;
                let idx1 = (state[0].wrapping_mul(31) ^ (step as u64).wrapping_mul(stride as u64)) as usize % num_blocks;
                let idx2 = (state[1].wrapping_mul(17) ^ (step as u64).rotate_left(11)) as usize % num_blocks;

                let offset1 = idx1 * 32;
                let offset2 = idx2 * 32;

                let block1 = &buffer[offset1..offset1 + 32];
                let block2 = &buffer[offset2..offset2 + 32];

                let mut mixed_block = [0u8; 32];
                for k in 0..32 {
                    mixed_block[k] = block1[k] ^ block2[k];
                }

                Self::arx_step_stride(&mut state, &mixed_block);
            }
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(b"antech-v1-finalization-variant-c");
        for val in &state {
            final_hasher.update(&val.to_le_bytes());
        }
        Ok(final_hasher.finalize().to_vec())
    }
}
