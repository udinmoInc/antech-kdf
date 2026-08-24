//! Candidate 008: Family H — Control Group / Deliberately Bad Low-Memory.
//! 1 MiB RAM, zero churn, minimal dependency (Demonstrates why H1 fails without bandwidth churn/dependency).

use super::{ExperimentalKdf, ExperimentalParams};
use sha2::{Digest, Sha256};

pub struct Candidate008;

impl ExperimentalKdf for Candidate008 {
    fn name(&self) -> &'static str {
        "candidate-008"
    }

    fn family(&self) -> &'static str {
        "Family H — Control Group (Deliberately Bad Low-Memory)"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        _params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String> {
        // Deliberately small 1 MiB buffer, 1 pass, zero churn, zero dependency
        let size = 1024 * 1024;
        let mut buffer = vec![0u8; size];

        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(&buffer[0..64]);
        final_hasher.update(&buffer[size - 64..size]);
        Ok(final_hasher.finalize().to_vec())
    }
}
