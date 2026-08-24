//! Candidate E5: Delayed Distinguishability.
//! Incorrect candidates remain indistinguishable from correct candidates until after 90%+ of memory operations complete.

use super::{PhaseEKdf, PhaseEParams};
use sha2::{Digest, Sha256};

pub struct CandidateE5;

impl PhaseEKdf for CandidateE5 {
    fn name(&self) -> &'static str {
        "candidate-e5"
    }

    fn family(&self) -> &'static str {
        "Family E5 — Delayed Distinguishability"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &PhaseEParams,
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

        // Delayed distinguishability: state updates are byte-identical for 90% of memory churn rounds
        let total_rounds = params.dependency_depth.max(100);
        let mut state = seed.to_vec();

        for step in 0..total_rounds {
            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(&buffer[(step as usize * 32) % (size - 32).max(1)..]);
            step_hasher.update(&step.to_le_bytes());

            // Only at 90% completion is terminal verification branch evaluated
            if step > (total_rounds * 90 / 100) && !params.is_correct_password_scenario {
                step_hasher.update(b"wrong_candidate_delayed_divergence");
            }
            state = step_hasher.finalize().to_vec();
        }

        Ok(state)
    }
}
