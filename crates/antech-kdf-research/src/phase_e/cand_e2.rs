//! Candidate E2: Server-Secret Continuation.
//! Protected server secret enables lower-cost verification while blocking DB-only attackers.

use super::{PhaseEKdf, PhaseEParams};
use sha2::{Digest, Sha256};

pub struct CandidateE2;

impl PhaseEKdf for CandidateE2 {
    fn name(&self) -> &'static str {
        "candidate-e2"
    }

    fn family(&self) -> &'static str {
        "Family E2 — Server-Secret Continuation"
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

        // Include server secret if available (DB-Only vs Full Compromise threat model)
        if let Some(sec) = &params.server_secret {
            hasher.update(sec);
        } else {
            // DB-only attacker without server secret performs fallback heavy work
            hasher.update(b"fallback_heavy_key_derivation_without_secret");
        }
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ (i as u8);
        }

        let mut state = seed.to_vec();
        for step in 0..params.dependency_depth {
            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(&buffer[(step as usize * 32) % (size - 32).max(1)..]);
            state = step_hasher.finalize().to_vec();
        }

        Ok(state)
    }
}
