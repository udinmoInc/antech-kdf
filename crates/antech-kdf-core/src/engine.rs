//! Canonical Candidate-004 KDF engine implementation.

use crate::traits::KdfEngine;
use antech_kdf_types::{Algorithm, AntechConfig, KdfError};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Candidate-004 Core Engine implementing `KdfEngine`.
#[derive(Debug, Clone, Default)]
pub struct Candidate004Engine;

impl Candidate004Engine {
    pub fn new() -> Self {
        Self
    }
}

impl KdfEngine for Candidate004Engine {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Antech
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        config: &AntechConfig,
    ) -> Result<Vec<u8>, KdfError> {
        config.validate()?;

        // 1. Domain-separated seed expansion
        let mut hasher = Sha256::new();
        hasher.update(b"antech-v1-domain-separator");
        hasher.update((config.memory.as_kib() as u32).to_le_bytes());
        hasher.update(config.dependency_depth.get().to_le_bytes());
        hasher.update(config.passes.get().to_le_bytes());
        hasher.update((salt.len() as u32).to_le_bytes());
        hasher.update(salt);
        hasher.update((password.len() as u32).to_le_bytes());
        hasher.update(password);
        let seed = hasher.finalize();

        // 2. Allocate working memory buffer
        let total_blocks = config.memory.as_bytes() / config.block_size.as_bytes();
        let mut buffer = vec![0u8; config.memory.as_bytes()];

        // Fill memory buffer deterministically from seed
        for chunk_idx in 0..total_blocks {
            let mut chunk_hasher = Sha256::new();
            chunk_hasher.update(seed);
            chunk_hasher.update((chunk_idx as u32).to_le_bytes());
            let chunk = chunk_hasher.finalize();
            let start = chunk_idx * 32;
            let end = (start + 32).min(buffer.len());
            buffer[start..end].copy_from_slice(&chunk[..end - start]);
        }

        // 3. Register state evolution across sequential passes
        let mut state = [0u64; 4];
        state[0] = u64::from_le_bytes(seed[0..8].try_into().unwrap());
        state[1] = u64::from_le_bytes(seed[8..16].try_into().unwrap());
        state[2] = u64::from_le_bytes(seed[16..24].try_into().unwrap());
        state[3] = u64::from_le_bytes(seed[24..32].try_into().unwrap());

        let depth = config.dependency_depth.get() as usize;

        for _pass in 0..config.passes.get() {
            for step in 0..depth {
                let addr_idx = (state[0] as usize ^ step) % total_blocks;
                let block_start = addr_idx * 32;

                let b0 = u64::from_le_bytes(buffer[block_start..block_start + 8].try_into().unwrap());
                let b1 = u64::from_le_bytes(buffer[block_start + 8..block_start + 16].try_into().unwrap());

                // ARX mixing step
                state[0] = state[0].wrapping_add(b0).rotate_left(13) ^ state[3];
                state[1] = state[1].wrapping_add(b1).rotate_left(17) ^ state[0];
                state[2] = state[2].wrapping_add(state[0]).rotate_left(19) ^ state[1];
                state[3] = state[3].wrapping_add(state[1]).rotate_left(23) ^ state[2];

                // Write-back to memory
                buffer[block_start..block_start + 8].copy_from_slice(&state[0].to_le_bytes());
            }
        }

        // 4. Final digest extraction
        let mut final_hasher = Sha256::new();
        final_hasher.update(seed);
        final_hasher.update(state[0].to_le_bytes());
        final_hasher.update(state[1].to_le_bytes());
        final_hasher.update(state[2].to_le_bytes());
        final_hasher.update(state[3].to_le_bytes());
        let digest = final_hasher.finalize();

        let out_len = config.output_length.as_bytes();
        let mut result = vec![0u8; out_len];
        let copy_len = out_len.min(32);
        result[..copy_len].copy_from_slice(&digest[..copy_len]);

        Ok(result)
    }
}

/// Provider factory selecting `KdfEngine` implementation.
pub struct KdfProvider;

impl KdfProvider {
    pub fn get_engine(algo: Algorithm) -> Result<Arc<dyn KdfEngine>, KdfError> {
        match algo {
            Algorithm::Antech => Ok(Arc::new(Candidate004Engine::new())),
            #[cfg(feature = "k1")]
            Algorithm::K1 => {
                Err(KdfError::Derivation("K1 engine requires research feature enable".to_string()))
            }
            #[cfg(feature = "k2")]
            Algorithm::K2 => {
                Err(KdfError::Derivation("K2 engine requires research feature enable".to_string()))
            }
            _ => Ok(Arc::new(Candidate004Engine::new())),
        }
    }
}
