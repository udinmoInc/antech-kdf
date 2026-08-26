#![no_main]
//! Fuzz BoundedResourceScheduler admission / queue / oversize / release.

use antech_kdf_core::{BoundedResourceScheduler, ResourcePolicy, ResourceScheduler};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let max_mem = 1 + (u16::from_le_bytes([data[0], data[1]]) as usize);
    let max_jobs = 1 + (data[2] % 16) as usize;
    let queue = (data[3] % 32) as usize;
    let req = u16::from_le_bytes([data[4], data[5]]) as usize;
    let ops = 1 + (data[6] % 32) as usize;
    let hold = data[7] % 2 == 0;

    let sched = BoundedResourceScheduler::new(ResourcePolicy {
        max_memory_kib: max_mem.max(1),
        max_active_jobs: max_jobs.max(1),
        queue_limit: queue,
    });

    let mut permits = Vec::new();
    for i in 0..ops {
        let m = if data.len() > 8 + i {
            1 + data[8 + i] as usize
        } else {
            req.max(1)
        };
        match sched.acquire(m) {
            Ok(p) => {
                if hold && permits.len() < max_jobs {
                    permits.push(p);
                } else {
                    sched.release(p);
                }
            }
            Err(_) => {}
        }
        let st = sched.stats();
        assert!(st.allocated_kib <= max_mem.max(1) || st.active_jobs == 0);
        assert!(st.waiting_jobs <= queue || queue == 0);
    }
    for p in permits {
        sched.release(p);
    }
    let st = sched.stats();
    assert_eq!(st.active_jobs, 0);
    assert_eq!(st.waiting_jobs, 0);
    assert_eq!(st.allocated_kib, 0);
});
