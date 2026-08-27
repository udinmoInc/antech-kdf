//! Host resource policy and memory admission scheduler.

use crate::traits::{ResourcePermit, ResourceScheduler};
use antech_kdf_types::KdfError;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Condvar, Mutex};

thread_local! {
    /// Permits held by this thread, keyed by scheduler identity (`*const Self`).
    /// Prevents Condvar deadlock on nested acquire-while-holding on the same scheduler.
    static HELD_BY_SCHEDULER: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
}

/// Server-wide resource ceilings (independent of per-hash KDF config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicy {
    pub max_memory_kib: usize,
    pub max_active_jobs: usize,
    /// Maximum threads blocked waiting for admission. `0` = fail immediately when full.
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

#[derive(Debug, Default)]
struct SchedulerState {
    allocated_kib: usize,
    active_jobs: usize,
    waiting_jobs: usize,
}

/// Snapshot for tests and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerStats {
    pub allocated_kib: usize,
    pub active_jobs: usize,
    pub waiting_jobs: usize,
}

/// Thread-safe admission controller with optional blocking queue.
#[derive(Debug)]
pub struct BoundedResourceScheduler {
    policy: ResourcePolicy,
    state: Mutex<SchedulerState>,
    available: Condvar,
}

impl BoundedResourceScheduler {
    pub fn new(policy: ResourcePolicy) -> Self {
        Self {
            policy,
            state: Mutex::new(SchedulerState::default()),
            available: Condvar::new(),
        }
    }

    pub fn default_scheduler() -> Self {
        Self::new(ResourcePolicy::default())
    }

    pub fn stats(&self) -> SchedulerStats {
        let state = self.state.lock().expect("scheduler mutex poisoned");
        SchedulerStats {
            allocated_kib: state.allocated_kib,
            active_jobs: state.active_jobs,
            waiting_jobs: state.waiting_jobs,
        }
    }

    fn can_admit(state: &SchedulerState, policy: &ResourcePolicy, memory_kib: usize) -> bool {
        state.active_jobs < policy.max_active_jobs
            && state.allocated_kib.saturating_add(memory_kib) <= policy.max_memory_kib
    }
}

impl ResourceScheduler for BoundedResourceScheduler {
    fn acquire(&self, memory_kib: usize) -> Result<ResourcePermit, KdfError> {
        // A single job larger than the host ceiling can never admit — fail fast
        // instead of parking forever on the wait queue.
        if memory_kib > self.policy.max_memory_kib {
            return Err(KdfError::ResourceExhausted(format!(
                "requested {memory_kib} KiB exceeds host memory ceiling {} KiB",
                self.policy.max_memory_kib
            )));
        }

        let self_key = self as *const Self as usize;
        let mut state = self
            .state
            .lock()
            .map_err(|_| KdfError::ResourceExhausted("scheduler lock poisoned".into()))?;

        loop {
            if Self::can_admit(&state, &self.policy, memory_kib) {
                state.active_jobs += 1;
                state.allocated_kib = state.allocated_kib.saturating_add(memory_kib);
                HELD_BY_SCHEDULER.with(|m| {
                    *m.borrow_mut().entry(self_key).or_insert(0) += 1;
                });
                return Ok(ResourcePermit { memory_kib });
            }

            if self.policy.queue_limit == 0 {
                return Err(KdfError::ResourceExhausted(format!(
                    "resource limits reached (active {}, mem {} KiB / {} KiB); queue disabled",
                    state.active_jobs, state.allocated_kib, self.policy.max_memory_kib
                )));
            }

            // Holding permits on this thread and then waiting for more capacity can never
            // make progress (those permits cannot be released while blocked). Fail fast.
            let held = HELD_BY_SCHEDULER.with(|m| m.borrow().get(&self_key).copied().unwrap_or(0));
            if held > 0 {
                return Err(KdfError::ResourceExhausted(
                    "nested acquire while holding permits would deadlock; release first".into(),
                ));
            }

            if state.waiting_jobs >= self.policy.queue_limit {
                return Err(KdfError::ResourceExhausted(format!(
                    "admission queue full ({}/{})",
                    state.waiting_jobs, self.policy.queue_limit
                )));
            }

            state.waiting_jobs += 1;
            state = self
                .available
                .wait(state)
                .map_err(|_| KdfError::ResourceExhausted("scheduler lock poisoned".into()))?;
            state.waiting_jobs = state.waiting_jobs.saturating_sub(1);
        }
    }

    fn release(&self, permit: ResourcePermit) {
        let self_key = self as *const Self as usize;
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        state.allocated_kib = state.allocated_kib.saturating_sub(permit.memory_kib);
        state.active_jobs = state.active_jobs.saturating_sub(1);
        HELD_BY_SCHEDULER.with(|m| {
            let mut map = m.borrow_mut();
            if let Some(n) = map.get_mut(&self_key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&self_key);
                }
            }
        });
        self.available.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn nested_acquire_while_holding_fails_instead_of_deadlock() {
        // Fuzz finding R15: same-thread acquire while holding + queue_limit > 0
        // previously parked forever on Condvar (nobody can release).
        let sched = BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 16 * 1024,
            max_active_jobs: 1,
            queue_limit: 4,
        });
        let p1 = sched.acquire(16 * 1024).unwrap();
        let start = Instant::now();
        let err = sched.acquire(16 * 1024).expect_err("must not block");
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(matches!(err, KdfError::ResourceExhausted(_)));
        assert!(
            format!("{err}").contains("nested acquire") || format!("{err}").contains("deadlock")
        );
        sched.release(p1);
        assert_eq!(sched.stats().active_jobs, 0);
        assert_eq!(sched.stats().waiting_jobs, 0);
    }

    #[test]
    fn request_exceeding_ceiling_fails_immediately() {
        let sched = BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 64 * 1024,
            max_active_jobs: 8,
            queue_limit: 32,
        });
        // Must not block forever waiting for an impossible admission.
        let err = sched.acquire(65 * 1024).expect_err("oversize");
        assert!(matches!(err, KdfError::ResourceExhausted(_)));
        assert_eq!(sched.stats().active_jobs, 0);
        assert_eq!(sched.stats().waiting_jobs, 0);
    }

    #[test]
    fn enforces_memory_ceiling() {
        let sched = BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 32 * 1024,
            max_active_jobs: 4,
            queue_limit: 0,
        });
        let p1 = sched.acquire(16 * 1024).unwrap();
        let p2 = sched.acquire(16 * 1024).unwrap();
        assert!(sched.acquire(16 * 1024).is_err());
        sched.release(p1);
        let p3 = sched.acquire(16 * 1024).unwrap();
        sched.release(p2);
        sched.release(p3);
        assert_eq!(sched.stats().active_jobs, 0);
    }

    #[test]
    fn enforces_active_job_limit() {
        let sched = BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 1024 * 1024,
            max_active_jobs: 1,
            queue_limit: 0,
        });
        let p1 = sched.acquire(16).unwrap();
        assert!(sched.acquire(16).is_err());
        sched.release(p1);
        assert!(sched.acquire(16).is_ok());
    }

    #[test]
    fn queue_limit_zero_fails_immediately() {
        let sched = Arc::new(BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 16 * 1024,
            max_active_jobs: 1,
            queue_limit: 0,
        }));
        let p1 = sched.acquire(16 * 1024).unwrap();
        assert!(sched.acquire(16 * 1024).is_err());
        sched.release(p1);
    }

    #[test]
    fn queue_below_limit_blocks_then_admits() {
        let sched = Arc::new(BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 16 * 1024,
            max_active_jobs: 1,
            queue_limit: 4,
        }));
        let p1 = sched.acquire(16 * 1024).unwrap();
        let sched2 = Arc::clone(&sched);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            b1.wait();
            let start = Instant::now();
            let p2 = sched2.acquire(16 * 1024).unwrap();
            (start.elapsed(), p2)
        });
        barrier.wait();
        let deadline = Instant::now() + Duration::from_secs(2);
        while sched.stats().waiting_jobs == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(sched.stats().waiting_jobs, 1);
        sched.release(p1);
        let (_, p2) = handle.join().unwrap();
        sched.release(p2);
        assert_eq!(sched.stats().waiting_jobs, 0);
    }

    #[test]
    fn queue_at_limit_rejects_additional_waiters() {
        let sched = Arc::new(BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 16 * 1024,
            max_active_jobs: 1,
            queue_limit: 1,
        }));
        let p1 = sched.acquire(16 * 1024).unwrap();
        let sched2 = Arc::clone(&sched);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let waiter = thread::spawn(move || {
            b1.wait();
            sched2.acquire(16 * 1024)
        });
        barrier.wait();
        thread::sleep(Duration::from_millis(20));
        assert_eq!(sched.stats().waiting_jobs, 1);
        assert!(sched.acquire(16 * 1024).is_err());
        sched.release(p1);
        assert!(waiter.join().unwrap().is_ok());
    }

    #[test]
    fn queue_recovers_after_release() {
        let sched = Arc::new(BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 16 * 1024,
            max_active_jobs: 1,
            queue_limit: 2,
        }));
        let p1 = sched.acquire(16 * 1024).unwrap();
        let s2 = Arc::clone(&sched);
        let h1 = thread::spawn(move || s2.acquire(16 * 1024));
        thread::sleep(Duration::from_millis(20));
        sched.release(p1);
        let p2 = h1.join().unwrap().unwrap();
        sched.release(p2);
        assert!(sched.acquire(16 * 1024).is_ok());
    }

    #[test]
    fn release_restores_capacity() {
        let sched = BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 32 * 1024,
            max_active_jobs: 2,
            queue_limit: 0,
        });
        let p = sched.acquire(16 * 1024).unwrap();
        assert_eq!(sched.stats().active_jobs, 1);
        sched.release(p);
        assert_eq!(sched.stats().active_jobs, 0);
        assert_eq!(sched.stats().allocated_kib, 0);
    }

    #[test]
    fn nested_acquire_then_release_allows_retry() {
        let sched = BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 16 * 1024,
            max_active_jobs: 1,
            queue_limit: 4,
        });
        let p1 = sched.acquire(16 * 1024).unwrap();
        assert!(sched.acquire(16 * 1024).is_err());
        sched.release(p1);
        let p2 = sched.acquire(16 * 1024).unwrap();
        sched.release(p2);
        assert_eq!(sched.stats().active_jobs, 0);
    }

    #[test]
    fn double_release_semantics_via_separate_permits() {
        // ResourcePermit is Copy-free owned token; releasing each once restores budget.
        let sched = BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 32 * 1024,
            max_active_jobs: 2,
            queue_limit: 0,
        });
        let p1 = sched.acquire(16 * 1024).unwrap();
        let p2 = sched.acquire(16 * 1024).unwrap();
        sched.release(p1);
        sched.release(p2);
        assert_eq!(sched.stats().active_jobs, 0);
        assert_eq!(sched.stats().allocated_kib, 0);
        let p3 = sched.acquire(32 * 1024).unwrap();
        sched.release(p3);
    }

    #[test]
    fn concurrent_admission_respects_global_budget() {
        let sched = Arc::new(BoundedResourceScheduler::new(ResourcePolicy {
            max_memory_kib: 64 * 1024,
            max_active_jobs: 8,
            queue_limit: 32,
        }));
        let mut handles = Vec::new();
        for _ in 0..50 {
            let s = Arc::clone(&sched);
            handles.push(thread::spawn(move || {
                let mut permits = Vec::new();
                for _ in 0..3 {
                    match s.acquire(16 * 1024) {
                        Ok(p) => permits.push(p),
                        Err(_) => break,
                    }
                }
                for p in permits {
                    s.release(p);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let st = sched.stats();
        assert_eq!(st.active_jobs, 0);
        assert_eq!(st.waiting_jobs, 0);
        assert!(st.allocated_kib <= 64 * 1024);
    }
}
