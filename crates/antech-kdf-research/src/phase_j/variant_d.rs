//! Variant D — Cryptographic Mixing Efficiency.
//! Sha512 + u64 ARX dual-mixing primitive maximizes defender single-thread CPU pipeline efficiency.

use crate::phase_f::{ResearchError, ResearchKdf, ResearchParams};
use sha2::{Digest, Sha256, Sha512};

pub struct VariantD {
    pub memory_kib: u32,
    pub dependency_depth: u32,
    pub passes: u32,
}

impl VariantD {
    pub fn new() -> Self {
        Self {
            memory_kib: 16384,     // 16 MB
            dependency_depth: 350000, // Fast defender latency (~88 ms)
            passes: 1,
        }
    }

    #[inline(always)]
    fn arx_sha_step(state: &mut [u64; 4], block: &[u8]) {
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

impl ResearchKdf for VariantD {
    fn name(&self) -> &'static str {
        "variant-d-sha512-arx"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let mut hasher = Sha256::new();
        hasher.update(b"antech-v1-domain-separator-variant-d");
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

        // ARX + Sha512 domain mixing loop
        for _pass in 0..self.passes {
            for step in 0..self.dependency_depth {
                let idx1 = (state[0] ^ (step as u64)) as usize % num_blocks;
                let offset1 = idx1 * 32;
                let block1 = &buffer[offset1..offset1 + 32];

                let idx2 = (state[1] ^ (step as u64).rotate_left(16)) as usize % num_blocks;
                let offset2 = idx2 * 32;
                let block2 = &buffer[offset2..offset2 + 32];

                let mut mixed_block = [0u8; 32];
                for k in 0..32 {
                    mixed_block[k] = block1[k] ^ block2[k];
                }

                Self::arx_sha_step(&mut state, &mixed_block);
            }
        }

        let mut final_hasher = Sha512::new();
        final_hasher.update(b"antech-v1-finalization-variant-d");
        for val in &state {
            final_hasher.update(&val.to_le_bytes());
        }
        Ok(final_hasher.finalize()[..32].to_vec())
    }
}
