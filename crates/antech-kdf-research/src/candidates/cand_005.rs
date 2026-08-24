//! Candidate 005: Family E — Bandwidth Target.
//! Small working set + long duration generating large sustained memory movement.

use super::{ExperimentalKdf, ExperimentalParams};
use sha2::{Digest, Sha256};

pub struct Candidate005;

impl ExperimentalKdf for Candidate005 {
    fn name(&self) -> &'static str {
        "candidate-005"
    }

    fn family(&self) -> &'static str {
        "Family E — Bandwidth Target"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String> {
        let size = params.working_set_bytes.max(1024);
        let mut buffer = vec![0u8; size];

        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        // Heavy bandwidth target loop (e.g., 50 rounds over memory buffer)
        let iterations = params.churn_factor.max(20) * (params.rounds.max(1));
        for pass in 0..iterations {
            let mut acc: u64 = pass;
            for i in (0..size).step_by(8) {
                let val = u64::from_le_bytes(buffer[i..i + 8].try_into().unwrap());
                acc = acc.wrapping_add(val).rotate_left(13);
                let new_bytes = acc.to_le_bytes();
                buffer[i..i + 8].copy_from_slice(&new_bytes);
            }
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(&buffer[0..64.min(size)]);
        final_hasher.update(&buffer[size.saturating_sub(64)..size]);
        Ok(final_hasher.finalize().to_vec())
    }
}
