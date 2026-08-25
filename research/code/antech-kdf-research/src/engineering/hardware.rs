//! Hardware metadata for portable benchmarks.

use super::HardwareMeta;
use std::process::Command;

pub fn collect_hardware_meta() -> HardwareMeta {
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let cpu_brand = {
        #[cfg(target_arch = "x86_64")]
        {
            // Best-effort; empty if unavailable.
            String::from("x86_64")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            std::env::consts::ARCH.to_string()
        }
    };
    let (cuda_available, gpu_name) = probe_cuda();
    let host = hostname_hash();
    HardwareMeta {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_brand,
        logical_cpus: logical,
        hostname_hash: host,
        cuda_available,
        gpu_name,
        notes: "Collected by antech-kdf-research::engineering::hardware".into(),
    }
}

fn hostname_hash() -> String {
    let h = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into());
    format!("{:x}", simple_hash(h.as_bytes()))
}

fn simple_hash(b: &[u8]) -> u64 {
    let mut x = 0xcbf29ce484222325u64;
    for &c in b {
        x ^= c as u64;
        x = x.wrapping_mul(0x100000001b3);
    }
    x
}

fn probe_cuda() -> (bool, Option<String>) {
    let out = Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if name.is_empty() {
                (false, None)
            } else {
                (true, Some(name.lines().next().unwrap_or(&name).to_string()))
            }
        }
        _ => (false, None),
    }
}
