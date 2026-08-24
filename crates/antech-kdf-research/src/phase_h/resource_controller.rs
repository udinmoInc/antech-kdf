//! Resource-bounded KDF scheduler and admission controller for tiny servers.

use super::ServerBudgetProfile;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct AllocationGuard {
    controller: Arc<ResourceController>,
    kib: usize,
}

impl Drop for AllocationGuard {
    fn drop(&mut self) {
        self.controller.release(self.kib);
    }
}

pub struct ResourceController {
    profile: ServerBudgetProfile,
    active_memory_bytes: Mutex<usize>,
    active_slots: Mutex<usize>,
}

impl ResourceController {
    pub fn new(profile: ServerBudgetProfile) -> Arc<Self> {
        Arc::new(Self {
            profile,
            active_memory_bytes: Mutex::new(0),
            active_slots: Mutex::new(0),
        })
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        requested_kib: usize,
        timeout: Duration,
    ) -> Result<AllocationGuard, String> {
        let requested_bytes = requested_kib * 1024;
        let max_bytes = self.profile.max_kdf_memory_budget_mb * 1024 * 1024;
        let start = Instant::now();

        loop {
            {
                let mut mem = self.active_memory_bytes.lock().unwrap();
                let mut slots = self.active_slots.lock().unwrap();

                if *mem + requested_bytes <= max_bytes
                    && *slots < self.profile.max_active_slots
                {
                    *mem += requested_bytes;
                    *slots += 1;
                    return Ok(AllocationGuard {
                        controller: Arc::clone(self),
                        kib: requested_kib,
                    });
                }
            }

            if start.elapsed() >= timeout {
                return Err("Resource controller admission timeout / backpressure queue full".to_string());
            }

            std::thread::sleep(Duration::from_micros(500));
        }
    }

    fn release(&self, kib: usize) {
        let bytes = kib * 1024;
        let mut mem = self.active_memory_bytes.lock().unwrap();
        let mut slots = self.active_slots.lock().unwrap();

        *mem = mem.saturating_sub(bytes);
        *slots = slots.saturating_sub(1);
    }

    pub fn current_stats(&self) -> (usize, usize) {
        let mem = *self.active_memory_bytes.lock().unwrap();
        let slots = *self.active_slots.lock().unwrap();
        (mem / (1024 * 1024), slots)
    }
}
