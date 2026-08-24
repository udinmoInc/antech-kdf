//! Phase I Candidate-004 variants (Variants A through E).

use crate::phase_f::{ResearchError, ResearchKdf, ResearchParams};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct VariantConfig {
    pub label: &'static str,
    pub memory_kib: u32,
    pub passes: u32,
    pub dependency_depth: u32,
    pub block_size: u32,
    pub enable_dual_node: bool,
    pub enable_state_addr: bool,
}

impl VariantConfig {
    pub fn variant_a_graph() -> Self {
        Self {
            label: "var-a-graph",
            memory_kib: 16384,
            passes: 1,
            dependency_depth: 350000,
            block_size: 32,
            enable_dual_node: true,
            enable_state_addr: false,
        }
    }

    pub fn variant_b_addr() -> Self {
        Self {
            label: "var-b-addr",
            memory_kib: 16384,
            passes: 1,
            dependency_depth: 400000,
            block_size: 32,
            enable_dual_node: false,
            enable_state_addr: true,
        }
    }

    pub fn variant_c_mix() -> Self {
        Self {
            label: "var-c-mix",
            memory_kib: 16384,
            passes: 1,
            dependency_depth: 450000,
            block_size: 32,
            enable_dual_node: true,
            enable_state_addr: true,
        }
    }

    pub fn variant_d_tmto() -> Self {
        Self {
            label: "var-d-tmto",
            memory_kib: 16384,
            passes: 2,
            dependency_depth: 300000,
            block_size: 32,
            enable_dual_node: true,
            enable_state_addr: true,
        }
    }

    pub fn variant_e_combined() -> Self {
        Self {
            label: "var-e-combined",
            memory_kib: 16384,
            passes: 1,
            dependency_depth: 700000,
            block_size: 32,
            enable_dual_node: true,
            enable_state_addr: true,
        }
    }
}

pub struct Candidate004PhaseIVariant {
    pub config: VariantConfig,
}

impl Candidate004PhaseIVariant {
    pub fn new(config: VariantConfig) -> Self {
        Self { config }
    }

    #[inline(always)]
    fn arx_step(state: &mut [u64; 4], block: &[u8]) {
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

impl ResearchKdf for Candidate004PhaseIVariant {
    fn name(&self) -> &'static str {
        self.config.label
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let mut hasher = Sha256::new();
        hasher.update(b"antech-v1-domain-separator-phase-i");
        hasher.update(password);
        hasher.update(salt);
        hasher.update(&self.config.memory_kib.to_le_bytes());
        hasher.update(&self.config.dependency_depth.to_le_bytes());
        let seed = hasher.finalize();

        let total_bytes = (self.config.memory_kib as usize) * 1024;
        let mut buffer = vec![0u8; total_bytes];

        // Seed expansion
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

        // Dual-node DAG and state-dependent addressing loop
        for _pass in 0..self.config.passes {
            for step in 0..self.config.dependency_depth {
                let idx1 = if self.config.enable_state_addr {
                    (state[0] ^ (step as u64)) as usize % num_blocks
                } else {
                    state[0] as usize % num_blocks
                };

                let offset1 = idx1 * 32;
                let block1 = &buffer[offset1..offset1 + 32];

                if self.config.enable_dual_node {
                    let idx2 = (state[1] ^ (step as u64).rotate_left(16)) as usize % num_blocks;
                    let offset2 = idx2 * 32;
                    let block2 = &buffer[offset2..offset2 + 32];

                    let mut mixed_block = [0u8; 32];
                    for k in 0..32 {
                        mixed_block[k] = block1[k] ^ block2[k];
                    }
                    Self::arx_step(&mut state, &mixed_block);
                } else {
                    Self::arx_step(&mut state, block1);
                }
            }
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(b"antech-v1-finalization-phase-i");
        for val in &state {
            final_hasher.update(&val.to_le_bytes());
        }
        Ok(final_hasher.finalize().to_vec())
    }
}
