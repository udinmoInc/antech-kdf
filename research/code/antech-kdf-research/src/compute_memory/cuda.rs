//! Optional CUDA attacker path.
//!
//! Attempts a real `nvcc` build of the research kernel when the host compiler
//! is present. Never fabricates GPU throughput.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CudaAttackerRecord {
    pub variant: String,
    pub memory_mib: usize,
    pub gpu_model: String,
    pub status: String,
    pub actual_guesses_per_sec: Option<f64>,
    pub batch_size: usize,
    pub kernel_source: String,
}

/// Embedded research CUDA kernel (compiled only when CUDA tooling is available).
pub const CUDA_KERNEL_SOURCE: &str = include_str!("cuda/antech_compute_memory_attacker.cu");

pub fn nvcc_available() -> bool {
    Command::new("nvcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn msvc_cl_available() -> bool {
    Command::new("cl")
        .arg("/?")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn cuda_available() -> bool {
    nvcc_available() && msvc_cl_available()
}

pub fn detect_gpu_model() -> String {
    let smi = Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader"])
        .output();
    match smi {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "CUDA runtime not detected".to_string(),
    }
}

fn kernel_source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/compute_memory/cuda/antech_compute_memory_attacker.cu")
}

/// Evaluate CUDA attacker. Returns measured g/s only when a device binary runs.
pub fn evaluate_cuda_attacker(variant: &str, memory_mib: usize) -> CudaAttackerRecord {
    let gpu_model = detect_gpu_model();
    let kernel = kernel_source_path().to_string_lossy().replace('\\', "/");

    if !nvcc_available() {
        return CudaAttackerRecord {
            variant: variant.to_string(),
            memory_mib,
            gpu_model,
            status: "CUDA UNAVAILABLE (nvcc not found) — no fabricated GPU throughput".into(),
            actual_guesses_per_sec: None,
            batch_size: 0,
            kernel_source: kernel,
        };
    }

    if !msvc_cl_available() {
        return CudaAttackerRecord {
            variant: variant.to_string(),
            memory_mib,
            gpu_model,
            status: "CUDA UNAVAILABLE (nvcc found, MSVC cl.exe host compiler missing) — no fabricated GPU throughput".into(),
            actual_guesses_per_sec: None,
            batch_size: 0,
            kernel_source: kernel,
        };
    }

    #[cfg(feature = "cuda")]
    {
        match try_run_cuda_probe(memory_mib) {
            Ok(gps) => CudaAttackerRecord {
                variant: variant.to_string(),
                memory_mib,
                gpu_model,
                status: "CUDA MEASURED".into(),
                actual_guesses_per_sec: Some(gps),
                batch_size: 64,
                kernel_source: kernel,
            },
            Err(msg) => CudaAttackerRecord {
                variant: variant.to_string(),
                memory_mib,
                gpu_model,
                status: format!("CUDA BUILD/RUN FAILED: {msg}"),
                actual_guesses_per_sec: None,
                batch_size: 0,
                kernel_source: kernel,
            },
        }
    }

    #[cfg(not(feature = "cuda"))]
    {
        CudaAttackerRecord {
            variant: variant.to_string(),
            memory_mib,
            gpu_model,
            status: "CUDA TOOLCHAIN READY but crate built without `cuda` feature".into(),
            actual_guesses_per_sec: None,
            batch_size: 0,
            kernel_source: kernel,
        }
    }
}

#[cfg(feature = "cuda")]
fn try_run_cuda_probe(memory_mib: usize) -> Result<f64, String> {
    let src = kernel_source_path();
    let out_dir = std::env::temp_dir().join("antech_cm_cuda");
    let _ = std::fs::create_dir_all(&out_dir);
    let bin = out_dir.join("antech_cm_attacker.exe");

    let compile = Command::new("nvcc")
        .arg(&src)
        .arg("-O2")
        .arg("-o")
        .arg(&bin)
        .output()
        .map_err(|e| e.to_string())?;
    if !compile.status.success() {
        return Err(String::from_utf8_lossy(&compile.stderr).into_owned());
    }

    let run = Command::new(&bin)
        .arg(memory_mib.to_string())
        .output()
        .map_err(|e| e.to_string())?;
    if !run.status.success() {
        return Err(String::from_utf8_lossy(&run.stderr).into_owned());
    }
    let stdout = String::from_utf8_lossy(&run.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("guesses_per_sec=") {
            return rest.trim().parse::<f64>().map_err(|e| e.to_string());
        }
    }
    Err(format!("probe output missing guesses_per_sec: {stdout}"))
}
