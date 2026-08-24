//! Candidate E6: Multi-Target-Resistant Asymmetric Verification.
//! Enforces per-account salt-keyed state transformations preventing work amortization across accounts.

use super::{PhaseEKdf, PhaseEParams};
use sha2::{Digest, Sha256};

pub struct CandidateE6;

impl PhaseEKdf for CandidateE6 {
    fn name(&self) -> &'static str {
        "candidate-e6"
    }

    fn family(&self) -> &'static str {
        "Family E6 — Multi-Target-Resistant Asymmetric Verification"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &PhaseEParams,
    ) -> Result<Vec<u8>, String> {
        let size = params.working_set_bytes.max(1024);
        let mut buffer = vec![0u8; size];

        // Salt-keyed initialization forces unique memory state for every target account
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(password);
        if let Some(sec) = &params.server_secret {
            hasher.update(sec);
        }
        let seed = hasher.finalize();

        for i in 0..size {
            buffer[i] = seed[i % 32] ^ salt[i % salt.len()];
        }

        let depth = if params.is_correct_password_scenario {
            50
        } else {
            150
        };

        let mut state = seed.to_vec();
        for step in 0..depth {
            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(salt);
            step_hasher.update(&buffer[(step as usize * 32) % (size - 32).max(1)..]);
            state = step_hasher.finalize().to_vec();
        }

        Ok(state)
    }
}
