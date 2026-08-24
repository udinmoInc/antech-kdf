//! Candidate 002: Family B — Rotating Working Set.
//! Small memory region continuously rewritten & rotated (Region A -> Region B -> Region C -> reuse).

use super::{ExperimentalKdf, ExperimentalParams};
use sha2::{Digest, Sha256};

pub struct Candidate002;

impl ExperimentalKdf for Candidate002 {
    fn name(&self) -> &'static str {
        "candidate-002"
    }

    fn family(&self) -> &'static str {
        "Family B — Rotating Working Set"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String> {
        let region_size = (params.working_set_bytes / 3).max(1024);
        let mut reg_a = vec![0u8; region_size];
        let mut reg_b = vec![0u8; region_size];
        let mut reg_c = vec![0u8; region_size];

        // Seed region A
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let seed = hasher.finalize();

        for i in 0..region_size {
            reg_a[i] = seed[i % 32] ^ (i as u8);
        }

        // Rotation steps
        for step in 0..params.rounds {
            // A -> B transform
            for i in 0..region_size {
                reg_b[i] = reg_a[i].wrapping_add((step as u8).wrapping_mul(i as u8));
            }
            // B -> C transform
            for i in 0..region_size {
                reg_c[i] = reg_b[i] ^ reg_a[region_size - 1 - i];
            }
            // C -> A overwrite/rotate
            for i in 0..region_size {
                reg_a[i] = reg_c[i].rotate_left(3);
            }
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(&reg_a[0..32.min(region_size)]);
        final_hasher.update(&reg_b[0..32.min(region_size)]);
        final_hasher.update(&reg_c[0..32.min(region_size)]);
        Ok(final_hasher.finalize().to_vec())
    }
}
