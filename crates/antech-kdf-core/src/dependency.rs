//! Sequential dependency chain research model.
//!
//! Research focus: Enforcing strict sequential dependency logic to prevent parallel cracking shortcut attacks.

use crate::error::CoreError;

/// Evaluates sequential dependency transformations across memory state.
pub fn apply_sequential_dependencies(buffer: &mut [u8]) -> Result<(), CoreError> {
    if buffer.len() < 2 {
        return Ok(());
    }

    // Strict sequential dependency chain: element i depends on element i-1
    for i in 1..buffer.len() {
        let prev = buffer[i - 1];
        buffer[i] = buffer[i].rotate_left(3) ^ prev;
    }

    Ok(())
}
