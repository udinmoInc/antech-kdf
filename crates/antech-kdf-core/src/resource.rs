//! Host resource policy and memory admission scheduler.

use crate::traits::{ResourcePermit, ResourceScheduler};
use antech_kdf_types::KdfError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Server-wide resource ceilings (independent of per-hash KDF config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicy {
    pub max_memory_kib: usize,
    pub max_active_jobs: usize,
    pub queue_limit: usize,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            max_memory_kib: 131_072, // 128 MiB global ceiling
            max_active_jobs: 64,
            queue_limit: 256,
        }
    }
}

/// Thread-safe admission controller.
#[derive(Debug)]
pub struct BoundedResourceScheduler {
    policy: ResourcePolicy,
    allocated_kib: Arc<AtomicUsize>,
    active_jobs: Arc<AtomicUsize>,
}

impl BoundedResourceScheduler {
    pub fn new(policy: ResourcePolicy) -> Self {
        Self {
            policy,
            allocated_kib: Arc::new(AtomicUsize::new(0)),
            active_jobs: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn default_scheduler() -> Self {
        Self::new(ResourcePolicy::default())
    }
}

impl ResourceScheduler for BoundedResourceScheduler {
    fn acquire(&self, memory_kib: usize) -> Result<ResourcePermit, KdfError> {
        let current_jobs = self.active_jobs.fetch_add(1, Ordering::SeqCst);
        if current_jobs >= self.policy.max_active_jobs {
            self.active_jobs.fetch_sub(1, Ordering::SeqCst);
            return Err(KdfError::ResourceExhausted(format!(
                "active job count {current_jobs} exceeds limit {}",
                self.policy.max_active_jobs
            )));
        }

        let current_mem = self.allocated_kib.fetch_add(memory_kib, Ordering::SeqCst);
        if current_mem + memory_kib > self.policy.max_memory_kib {
            self.allocated_kib.fetch_sub(memory_kib, Ordering::SeqCst);
            self.active_jobs.fetch_sub(1, Ordering::SeqCst);
            return Err(KdfError::ResourceExhausted(format!(
                "requested memory {memory_kib} KiB exceeds global ceiling {} KiB",
                self.policy.max_memory_kib
            )));
        }

        Ok(ResourcePermit { memory_kib })
    }

    fn release(&self, permit: ResourcePermit) {
        self.allocated_kib
            .fetch_sub(permit.memory_kib, Ordering::SeqCst);
        self.active_jobs.fetch_sub(1, Ordering::SeqCst);
    }
}
