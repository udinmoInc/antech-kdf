//! Candidate 003: Family C — Sequential Dependency Chain.
//! Deep state dependency chain (state0 -> state1 -> ... -> stateN) preventing parallel execution.

use super::{ExperimentalKdf, ExperimentalParams};
use sha2::{Digest, Sha256};

pub struct Candidate003;

impl ExperimentalKdf for Candidate003 {
    fn name(&self) -> &'static str {
        "candidate-003"
    }

    fn family(&self) -> &'static str {
        "Family C — Sequential Dependency Chain"
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        params: &ExperimentalParams,
    ) -> Result<Vec<u8>, String> {
        let depth = params.dependency_depth.max(1000);
        let mut state = [0u8; 32];

        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        state.copy_from_slice(&hasher.finalize());

        // Strict sequential dependency chain: S_{i+1} = H(S_i || i)
        for i in 0..depth {
            let mut step_hasher = Sha256::new();
            step_hasher.update(&state);
            step_hasher.update(&i.to_le_bytes());
            state.copy_from_slice(&step_hasher.finalize());
        }

        Ok(state.to_vec())
    }
}
