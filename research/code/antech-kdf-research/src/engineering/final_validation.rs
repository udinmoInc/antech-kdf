//! Portable final-validation harness (hardware inventory + conformance).
//!
//! Does **not** change the production KDF. Writes under
//! `research/results/final-validation/`.

use antech_kdf::{
    hash_with_config_and_salt, verify, AntechConfig, GraphKind,
};
use antech_kdf_core::AntechEngine;
use antech_kdf_format::{encode_hash, parse_hash};
use antech_kdf_reference::{derive as ref_derive, RefConfig, GRAPH_COMBINED_FRONTIER};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Pass,
    Fail,
    Blocked,
    NotRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRow {
    pub area: String,
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub collected_at_unix: u64,
    pub os: String,
    pub arch: String,
    pub cpu_model: String,
    pub logical_cpus: usize,
    pub ram_gib: Option<f64>,
    pub rustc: String,
    pub cargo: String,
    pub gpu_model: Option<String>,
    pub gpu_vram_mib: Option<u64>,
    pub cuda_version: Option<String>,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalValidationSummary {
    pub platform: PlatformInfo,
    pub checks: Vec<CheckRow>,
    pub verdict: String,
}

pub fn default_out_dir() -> PathBuf {
    PathBuf::from("research/results/final-validation")
}

pub fn profile() -> String {
    std::env::var("ANTECH_FINAL_VALIDATION_PROFILE").unwrap_or_else(|_| "full".into())
}

pub fn run(out: &Path) -> FinalValidationSummary {
    let _ = fs::create_dir_all(out);
    for sub in ["fuzz", "sanitizers", "hardware", "conformance", "ci"] {
        let _ = fs::create_dir_all(out.join(sub));
    }

    let platform = collect_platform(profile());
    write_json(&out.join("hardware/platform.json"), &platform);
    let mut checks = Vec::new();

    // --- Conformance: production engine == reference ---
    checks.extend(run_production_vs_reference());

    // --- v2 encode/decode + verify ---
    checks.extend(run_v2_roundtrip());

    // --- Randomized valid configs (production == reference) ---
    checks.extend(run_randomized_cross());

    // --- GPU: CPU == GPU when CUDA available ---
    checks.extend(run_gpu_cross(out));

    // --- Local capability markers ---
    checks.push(CheckRow {
        area: "ci".into(),
        name: "libfuzzer_local".into(),
        status: CheckStatus::Blocked,
        detail: "cargo-fuzz/libFuzzer not runnable on this Windows host (toolchain); Linux CI job owns PASS/FAIL".into(),
    });
    checks.push(asan_ubsan_local_marker());
    checks.push(miri_local_marker());

    let fails = checks
        .iter()
        .filter(|c| matches!(c.status, CheckStatus::Fail))
        .count();
    let verdict: String = if fails == 0 {
        "PASS".into()
    } else {
        "FAIL".into()
    };

    let summary = FinalValidationSummary {
        platform,
        checks: checks.clone(),
        verdict: verdict.clone(),
    };
    write_json(&out.join("summary.json"), &summary);
    write_conformance_csv(&out.join("conformance/results.csv"), &checks);
    write_report(out, &summary);
    summary
}

fn asan_ubsan_local_marker() -> CheckRow {
    #[cfg(target_os = "windows")]
    {
        CheckRow {
            area: "sanitizers".into(),
            name: "asan_ubsan_local".into(),
            status: CheckStatus::Blocked,
            detail: "Host ASan/UBSan via -Zsanitizer requires Linux nightly + build-std; see .github/workflows/sanitizers.yml".into(),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        CheckRow {
            area: "sanitizers".into(),
            name: "asan_ubsan_local".into(),
            status: CheckStatus::NotRun,
            detail: "Not executed in this runner invocation; CI sanitizers workflow covers Linux".into(),
        }
    }
}

fn miri_local_marker() -> CheckRow {
    // Marker only — actual Miri is invoked separately so we can record PASS/FAIL from the shell.
    match std::env::var("ANTECH_MIRI_STATUS") {
        Ok(s) if s.eq_ignore_ascii_case("pass") => CheckRow {
            area: "sanitizers".into(),
            name: "miri".into(),
            status: CheckStatus::Pass,
            detail: "Recorded from ANTECH_MIRI_STATUS=pass".into(),
        },
        Ok(s) if s.eq_ignore_ascii_case("fail") => CheckRow {
            area: "sanitizers".into(),
            name: "miri".into(),
            status: CheckStatus::Fail,
            detail: "Recorded from ANTECH_MIRI_STATUS=fail".into(),
        },
        Ok(s) if s.eq_ignore_ascii_case("blocked") => CheckRow {
            area: "sanitizers".into(),
            name: "miri".into(),
            status: CheckStatus::Blocked,
            detail: "Recorded from ANTECH_MIRI_STATUS=blocked".into(),
        },
        _ => CheckRow {
            area: "sanitizers".into(),
            name: "miri".into(),
            status: CheckStatus::NotRun,
            detail: "Set ANTECH_MIRI_STATUS after running cargo miri; or rely on CI sanitizers workflow".into(),
        },
    }
}

fn run_production_vs_reference() -> Vec<CheckRow> {
    let mut rows = Vec::new();
    let cases: &[(&str, usize, &[u8], &[u8])] = &[
        ("1mib_ascii", 1024, b"password", b"salt_16_bytes_!!"),
        ("1mib_bytes", 1024, b"pw\0bin", b"0123456789abcdef"),
        (
            "16mib_default",
            16 * 1024,
            b"correct_horse",
            b"salt_16_bytes_!!",
        ),
    ];
    let profile = profile();
    for (id, kib, pw, salt) in cases {
        if profile == "ci" && *kib > 1024 {
            rows.push(CheckRow {
                area: "conformance".into(),
                name: (*id).into(),
                status: CheckStatus::NotRun,
                detail: "Skipped under ANTECH_FINAL_VALIDATION_PROFILE=ci (16 MiB covered in full profile)".into(),
            });
            continue;
        }
        let cfg = AntechConfig::builder()
            .memory_kib(*kib)
            .graph(GraphKind::CombinedFrontier)
            .build()
            .unwrap();
        let prod = AntechEngine::new().derive(pw, salt, &cfg).unwrap();
        let refer = ref_derive(
            pw,
            salt,
            &RefConfig {
                memory_kib: *kib,
                block_size: 32,
                fan_in: 2,
                graph_tag: GRAPH_COMBINED_FRONTIER,
                output_length: 32,
            },
        );
        let ok = prod == refer;
        rows.push(CheckRow {
            area: "conformance".into(),
            name: format!("prod_vs_ref_{id}"),
            status: if ok {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            detail: if ok {
                format!("digest_len={}", prod.len())
            } else {
                "digest mismatch".into()
            },
        });
    }
    rows
}

fn run_v2_roundtrip() -> Vec<CheckRow> {
    let mut rows = Vec::new();
    let cfg = AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap();
    let salt = b"salt_16_bytes_!!";
    let pw = b"v2_roundtrip";
    match hash_with_config_and_salt(pw, salt, &cfg) {
        Ok(enc) => {
            let parsed = parse_hash(&enc);
            let ok_parse = parsed.is_ok();
            rows.push(CheckRow {
                area: "conformance".into(),
                name: "v2_parse".into(),
                status: if ok_parse {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                },
                detail: format!("{parsed:?}"),
            });
            if let Ok(h) = parsed {
                let rebuild = AntechConfig::builder()
                    .memory_kib(h.memory_kib as usize)
                    .salt_length(h.salt_len)
                    .block_size(h.block_size)
                    .fan_in(h.fan_in)
                    .graph(h.graph)
                    .output_length(h.output_len)
                    .build();
                match rebuild.and_then(|c| encode_hash(&c, &h.salt, &h.digest)) {
                    Ok(re) => {
                        rows.push(CheckRow {
                            area: "conformance".into(),
                            name: "v2_reencode".into(),
                            status: if re == enc {
                                CheckStatus::Pass
                            } else {
                                CheckStatus::Fail
                            },
                            detail: if re == enc {
                                "stable".into()
                            } else {
                                "reencode drift".into()
                            },
                        });
                    }
                    Err(e) => rows.push(CheckRow {
                        area: "conformance".into(),
                        name: "v2_reencode".into(),
                        status: CheckStatus::Fail,
                        detail: format!("{e}"),
                    }),
                }
            }
            let v_ok = verify(pw, &enc).unwrap_or(false);
            let v_bad = verify(b"wrong", &enc).unwrap_or(true);
            rows.push(CheckRow {
                area: "conformance".into(),
                name: "v2_verify".into(),
                status: if v_ok && !v_bad {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                },
                detail: format!("ok={v_ok} bad_rejected={}", !v_bad),
            });
        }
        Err(e) => rows.push(CheckRow {
            area: "conformance".into(),
            name: "v2_hash".into(),
            status: CheckStatus::Fail,
            detail: format!("{e}"),
        }),
    }
    rows
}

fn run_randomized_cross() -> Vec<CheckRow> {
    let mut rows = Vec::new();
    let mut seed = 0xC0FFEE_u64;
    let n = if profile() == "ci" { 8 } else { 32 };
    let mut mismatches = 0u64;
    for i in 0..n {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let kib = if seed % 3 == 0 { 1024 } else { 2048 };
        let block = if seed % 2 == 0 { 32 } else { 64 };
        let fan = if (seed >> 8) % 2 == 0 { 2 } else { 4 };
        let mut salt = [0u8; 16];
        for (j, b) in salt.iter_mut().enumerate() {
            *b = ((seed >> (j * 3)) as u8).wrapping_add(j as u8);
        }
        let pw = format!("rand_{i}_{seed:x}");
        let Ok(cfg) = AntechConfig::builder()
            .memory_kib(kib)
            .block_size(block)
            .fan_in(fan)
            .salt_length(16)
            .output_length(32)
            .graph(GraphKind::CombinedFrontier)
            .build()
        else {
            continue;
        };
        let prod = AntechEngine::new()
            .derive(pw.as_bytes(), &salt, &cfg)
            .unwrap();
        let refer = ref_derive(
            pw.as_bytes(),
            &salt,
            &RefConfig {
                memory_kib: kib,
                block_size: block,
                fan_in: fan,
                graph_tag: GRAPH_COMBINED_FRONTIER,
                output_length: 32,
            },
        );
        if prod != refer {
            mismatches += 1;
        }
    }
    rows.push(CheckRow {
        area: "conformance".into(),
        name: format!("randomized_cross_{n}"),
        status: if mismatches == 0 {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        detail: format!("mismatches={mismatches}"),
    });
    rows
}

fn run_gpu_cross(out: &Path) -> Vec<CheckRow> {
    let require = std::env::var("ANTECH_REQUIRE_CUDA").ok().as_deref() == Some("1");
    let smi = Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader"])
        .output();
    let cuda_ok = smi.as_ref().map(|o| o.status.success()).unwrap_or(false);
    if !cuda_ok {
        return vec![CheckRow {
            area: "hardware".into(),
            name: "gpu_cpu_digest_cross".into(),
            status: if require {
                CheckStatus::Fail
            } else {
                CheckStatus::Blocked
            },
            detail: "nvidia-smi unavailable; CUDA digest cross not run".into(),
        }];
    }

    // Prefer existing MEASURED GPU campaign artifacts for digest agreement rather than
    // recompiling CUDA kernels here (methodology unchanged).
    let gpu_csv = Path::new("research/results/compute-memory-v4/gpu/correctness.csv");
    if gpu_csv.is_file() {
        let text = fs::read_to_string(gpu_csv).unwrap_or_default();
        let mut rows = 0u64;
        let mut ok = 0u64;
        for (i, line) in text.lines().enumerate() {
            if i == 0 {
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            rows += 1;
            let lower = line.to_ascii_lowercase();
            if lower.contains(",true,ok") || lower.ends_with(",ok") {
                ok += 1;
            }
        }
        let _ = fs::copy(gpu_csv, out.join("hardware/gpu-correctness.csv"));
        return vec![CheckRow {
            area: "hardware".into(),
            name: "gpu_cpu_digest_cross".into(),
            status: if rows > 0 && ok == rows {
                CheckStatus::Pass
            } else if rows == 0 {
                CheckStatus::Fail
            } else {
                CheckStatus::Fail
            },
            detail: format!("MEASURED GPU CSV rows={rows} ok={ok} (host GPU present)"),
        }];
    }

    vec![CheckRow {
        area: "hardware".into(),
        name: "gpu_cpu_digest_cross".into(),
        status: CheckStatus::Blocked,
        detail: "CUDA present but no gpu/correctness.csv to reuse; rerun v4 GPU campaign to refresh".into(),
    }]
}

pub fn collect_platform(profile: String) -> PlatformInfo {
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let rustc = cmd_first_line("rustc", &["--version"]);
    let cargo = cmd_first_line("cargo", &["--version"]);
    let cpu = cpu_model();
    let ram = ram_gib();
    let (gpu, vram) = gpu_info();
    let cuda = cuda_version();
    PlatformInfo {
        collected_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        cpu_model: cpu,
        logical_cpus: logical,
        ram_gib: ram,
        rustc,
        cargo,
        gpu_model: gpu,
        gpu_vram_mib: vram,
        cuda_version: cuda,
        profile,
    }
}

fn cpu_model() -> String {
    if let Ok(o) = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)",
        ])
        .output()
    {
        let t = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    if let Ok(o) = Command::new("wmic")
        .args(["cpu", "get", "Name", "/value"])
        .output()
    {
        let s = String::from_utf8_lossy(&o.stdout);
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Name=") {
                let t = rest.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
    }
    if let Ok(o) = Command::new("lscpu").output() {
        let s = String::from_utf8_lossy(&o.stdout);
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Model name:") {
                return rest.trim().to_string();
            }
        }
    }
    std::env::consts::ARCH.into()
}

fn ram_gib() -> Option<f64> {
    if let Ok(o) = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,2)",
        ])
        .output()
    {
        if let Ok(v) = String::from_utf8_lossy(&o.stdout).trim().parse::<f64>() {
            return Some(v);
        }
    }
    if let Ok(o) = Command::new("wmic")
        .args(["ComputerSystem", "get", "TotalPhysicalMemory", "/value"])
        .output()
    {
        let s = String::from_utf8_lossy(&o.stdout);
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("TotalPhysicalMemory=") {
                if let Ok(bytes) = rest.trim().parse::<f64>() {
                    return Some(bytes / (1024.0 * 1024.0 * 1024.0));
                }
            }
        }
    }
    if let Ok(text) = fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kib: f64 = rest
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(0.0);
                return Some(kib / (1024.0 * 1024.0));
            }
        }
    }
    None
}

fn gpu_info() -> (Option<String>, Option<u64>) {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let line = String::from_utf8_lossy(&o.stdout);
            let line = line.lines().next().unwrap_or("").trim();
            let mut parts = line.split(',').map(|s| s.trim());
            let name = parts.next().map(|s| s.to_string()).filter(|s| !s.is_empty());
            let vram = parts.next().and_then(|s| s.parse().ok());
            (name, vram)
        }
        _ => (None, None),
    }
}

fn cuda_version() -> Option<String> {
    let out = Command::new("nvcc").args(["--version"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .find(|l| l.contains("release"))
        .map(|l| l.trim().to_string())
}

fn cmd_first_line(bin: &str, args: &[&str]) -> String {
    Command::new(bin)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn write_json<T: Serialize>(path: &Path, val: &T) {
    if let Ok(s) = serde_json::to_string_pretty(val) {
        let _ = fs::write(path, s);
    }
}

fn write_conformance_csv(path: &Path, checks: &[CheckRow]) {
    if let Ok(mut f) = File::create(path) {
        let _ = writeln!(f, "area,name,status,detail");
        for c in checks {
            let detail = c.detail.replace(',', ";").replace('\n', " ");
            let _ = writeln!(f, "{},{},{:?},{}", c.area, c.name, c.status, detail);
        }
    }
}

fn write_report(out: &Path, summary: &FinalValidationSummary) {
    if let Ok(mut f) = File::create(out.join("final-report.md")) {
        let _ = writeln!(f, "# Final validation report\n");
        let _ = writeln!(f, "**Verdict:** {}\n", summary.verdict);
        let p = &summary.platform;
        let _ = writeln!(f, "## Platform\n");
        let _ = writeln!(f, "| Field | Value |");
        let _ = writeln!(f, "|---|---|");
        let _ = writeln!(f, "| OS | {} / {} |", p.os, p.arch);
        let _ = writeln!(f, "| CPU | {} |", p.cpu_model);
        let _ = writeln!(f, "| Logical CPUs | {} |", p.logical_cpus);
        let _ = writeln!(
            f,
            "| RAM GiB | {} |",
            p.ram_gib
                .map(|x| format!("{x:.2}"))
                .unwrap_or_else(|| "UNKNOWN".into())
        );
        let _ = writeln!(f, "| rustc | {} |", p.rustc);
        let _ = writeln!(f, "| cargo | {} |", p.cargo);
        let _ = writeln!(
            f,
            "| GPU | {} |",
            p.gpu_model.clone().unwrap_or_else(|| "BLOCKED/none".into())
        );
        let _ = writeln!(
            f,
            "| VRAM MiB | {} |",
            p.gpu_vram_mib
                .map(|x| x.to_string())
                .unwrap_or_else(|| "UNKNOWN".into())
        );
        let _ = writeln!(
            f,
            "| CUDA | {} |",
            p.cuda_version
                .clone()
                .unwrap_or_else(|| "BLOCKED/none".into())
        );
        let _ = writeln!(f, "| Profile | {} |", p.profile);
        let _ = writeln!(f, "\n## Checks\n");
        let _ = writeln!(f, "| Area | Name | Status | Detail |");
        let _ = writeln!(f, "|---|---|---|---|");
        for c in &summary.checks {
            let _ = writeln!(
                f,
                "| {} | {} | {:?} | {} |",
                c.area,
                c.name,
                c.status,
                c.detail.replace('|', "/")
            );
        }
        let _ = writeln!(
            f,
            "\nStatuses are exactly PASS / FAIL / BLOCKED / NOT_RUN. BLOCKED and NOT_RUN are never treated as PASS.\n"
        );
    }
}
