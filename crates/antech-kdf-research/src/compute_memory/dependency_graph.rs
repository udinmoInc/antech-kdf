//! Sequential dependency graph: each step's addresses are derived from prior state.

/// Parent / destination addresses for one state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphAddresses {
    pub parent1: usize,
    pub parent2: usize,
    pub dest: usize,
}

/// Pebble-style dual-parent graph with a logarithmic back-reference.
///
/// Both parents and the destination depend on the current state, so an attacker
/// cannot schedule independent steps or drop memory without recomputation.
pub fn addresses(state: &[u64; 4], step: u32, pass: u32, num_blocks: usize) -> GraphAddresses {
    debug_assert!(num_blocks > 0);
    let n = num_blocks;

    let parent1 = ((state[0] ^ (step as u64).wrapping_mul(0x9E3779B97F4A7C15)) as usize) % n;

    // Logarithmic back-pointer distance — forces pebbling / recomputation under TMTO.
    let log_span = ((n as u64).next_power_of_two().trailing_zeros().max(1)) as u64;
    let back = (((state[1] >> 3) % log_span) + 1) << ((state[2] as usize) % (log_span as usize).max(1));
    let back = (back as usize % (n / 2).max(1)) + 1;
    let parent2 = (parent1 + n - back) % n;

    let dest = ((state[3] ^ ((pass as u64) << 32) ^ (step as u64).rotate_left(11)) as usize) % n;

    // Ensure dest is not identical to both parents when n is large enough.
    let dest = if dest == parent1 || dest == parent2 {
        (dest + 1 + ((state[0] as usize) % 3)) % n
    } else {
        dest
    };

    GraphAddresses {
        parent1,
        parent2,
        dest,
    }
}
