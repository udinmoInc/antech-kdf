//! Candidate E1: Hidden Continuation.
//! Sequence where expensive continuation cannot be skipped based on public information.

use super::{PhaseEKdf, PhaseEParams};
use sha2::{Digest, Sha256};

pub struct CandidateE1;

impl PhaseEKdf for CandidateE1 {
    fn name(&self) -> &'static str {
        "candidate-e1"
    }

    fn family(&self) -> &'static str {
        "Family E1 — Hidden Continuation"
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
        if let Some(sec) = &params.server_secret {
            hasher.update(sec);
        }
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        // Hidden continuation: state evolution requires completing full depth regardless of correctness
        let mut state = seed.to_vec();
        for step in 0..params.dependency_depth {
            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(&buffer[(step as usize * 64) % (size - 64).max(1)..]);
            step_hasher.update(&step.to_le_bytes());
            state = step_hasher.finalize().to_vec();
        }

        Ok(state)
    }
}
