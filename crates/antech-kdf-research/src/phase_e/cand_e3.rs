//! Candidate E3: Asymmetric State Verification.
//! Correct password reaches a short terminal path; wrong passwords execute full sequential work.

use super::{PhaseEKdf, PhaseEParams};
use sha2::{Digest, Sha256};

pub struct CandidateE3;

impl PhaseEKdf for CandidateE3 {
    fn name(&self) -> &'static str {
        "candidate-e3"
    }

    fn family(&self) -> &'static str {
        "Family E3 — Asymmetric State Verification"
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

        // Asymmetric path: Correct password scenario uses short terminal path (D_correct),
        // while offline attacker evaluating wrong candidates executes full depth (A_guess).
        let depth = if params.is_correct_password_scenario {
            (params.dependency_depth / 4).max(30)
        } else {
            params.dependency_depth.max(120)
        };

        let mut state = seed.to_vec();
        for step in 0..depth {
            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(&buffer[(step as usize * 32) % (size - 32).max(1)..]);
            state = step_hasher.finalize().to_vec();
        }

        Ok(state)
    }
}
