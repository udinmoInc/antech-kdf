//! Version management and rehash migration rules.

use crate::params::InternalParams;
use antech_kdf_types::{AlgorithmVersion, RawHashComponents};

/// Determines whether a parsed hash requires rehashing due to version or parameter mismatch.
pub fn check_needs_rehash(components: &RawHashComponents) -> bool {
    let current_version = AlgorithmVersion::V1;
    if components.version != current_version {
        return true;
    }

    let recommended = InternalParams::recommended_parameters();
    components.memory_kib != recommended.memory_kib
        || components.time_cost != recommended.time_cost
        || components.parallelism != recommended.parallelism
        || components.bandwidth_target != recommended.bandwidth_target
}
