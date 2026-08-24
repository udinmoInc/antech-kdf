//! Candidate-004 symmetric research KDF core.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResearchParams {
    pub memory_kib: u32,
    pub passes: u32,
    pub dependency_depth: u32,
    pub block_size: u32,
}

impl Default for ResearchParams {
    fn default() -> Self {
        Self {
            memory_kib: 16384, // 16 MiB
            passes: 1,
            dependency_depth: 120,
            block_size: 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResearchError {
    InvalidParameters(String),
    EncodingError(String),
    DerivationError(String),
}

impl fmt::Display for ResearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResearchError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            ResearchError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            ResearchError::DerivationError(msg) => write!(f, "Derivation error: {}", msg),
        }
    }
}

impl std::error::Error for ResearchError {}

pub trait ResearchKdf: Sync + Send {
    fn name(&self) -> &'static str;
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError>;
}

pub struct Candidate004 {
    pub memory_kib: u32,
    pub dependency_depth: u32,
    pub passes: u32,
}

impl Candidate004 {
    pub fn new() -> Self {
        Self {
            memory_kib: 16384, // 16 MB
            dependency_depth: 120,
            passes: 1,
        }
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

impl Default for Candidate004 {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchKdf for Candidate004 {
    fn name(&self) -> &'static str {
        "candidate-004"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &ResearchParams,
    ) -> Result<Vec<u8>, ResearchError> {
        let mut hasher = Sha256::new();
        hasher.update(b"antech-v1-domain-separator-cand-004");
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

                Self::arx_step(&mut state, &mixed_block);
            }
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(b"antech-v1-finalization-cand-004");
        for val in &state {
            final_hasher.update(val.to_le_bytes());
        }
        Ok(final_hasher.finalize().to_vec())
    }
}
