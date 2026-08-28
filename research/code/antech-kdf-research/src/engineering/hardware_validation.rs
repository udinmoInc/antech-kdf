//! Cross-platform hardware / toolchain validation for frozen Antech v5 production.
//!
//! Orchestrates existing correctness, stress, attacker, conformance, and SDK
//! infrastructure. Does **not** change the KDF algorithm, public API, v2 format,
//! or canonical parameters. Writes under `research/results/hardware-validation/`.

use crate::engineering::cpu_attacker::{run_cpu_attacker_campaign, CpuAttackerRow};
use crate::engineering::final_validation::{self, CheckStatus, PlatformInfo};
use crate::engineering::production_correctness::{self, CampaignSummary as CorrectnessSummary};
use crate::engineering::production_stress::{
    run_malformed_scenario, run_mixed_scenario, StressScenarioRow,
};
use antech_kdf::{hash_with_config_and_salt, verify, AntechConfig, GraphKind};
use antech_kdf_core::AntechEngine;
use antech_kdf_reference::{RefConfig, GRAPH_COMBINED_FRONTIER};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HwStatus {
    Pass,
    Fail,
    Blocked,
    NotRun,
    NotApplicable,
}

impl HwStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Blocked => "BLOCKED",
            Self::NotRun => "NOT RUN",
            Self::NotApplicable => "NOT APPLICABLE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareValidationSummary {
    pub platform_id: String,
    pub platform: PlatformInfo,
    pub build_profile: String,
    pub optimization: String,
    pub verdict: String,
    pub correctness_verdict: String,
    pub stress_verdict: String,
    pub sdk_verdict: String,
    pub gpu_verdict: String,
    pub regressions: u64,
}

pub fn default_out_dir() -> PathBuf {
    PathBuf::from("research/results/hardware-validation")
}

pub fn profile() -> String {
    std::env::var("ANTECH_HARDWARE_VALIDATION_PROFILE").unwrap_or_else(|_| "ci".into())
}

pub fn build_profile() -> String {
    if cfg!(debug_assertions) {
        "debug".into()
    } else {
        "release".into()
    }
}

pub fn platform_id(platform: &PlatformInfo, build_profile: &str) -> String {
    format!(
        "{}-{}-{}",
        platform.os, platform.arch, build_profile
    )
}

pub fn run_campaign(out: &Path) -> HardwareValidationSummary {
    let _ = fs::create_dir_all(out);
    let prof = profile();
    let bprof = build_profile();
    let platform = final_validation::collect_platform(prof.clone());
    let pid = platform_id(&platform, &bprof);
    let opt = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release-opt"
    };

    println!("=== Hardware validation ({pid}) profile={prof} build={bprof} ===");

    write_environment_csv(out, &pid, &platform, &bprof, opt);
    write_platform_matrix_row(out, &pid, &platform, &bprof, opt);

    // --- Correctness (reuse production_correctness campaign) ---
    let correctness_dir = out.join("_scratch/correctness");
    let _ = fs::create_dir_all(&correctness_dir);
    if prof == "ci" {
        std::env::set_var("ANTECH_CORRECTNESS_PROFILE", "ci");
    }
    let correctness = production_correctness::run_campaign(&correctness_dir);
    write_correctness_csv(out, &pid, &correctness_dir, &correctness);

    // --- Final-validation conformance subset (reference vs production, v2, GPU cross) ---
    let fv_dir = out.join("_scratch/final-validation");
    let fv = final_validation::run(&fv_dir);
    append_final_validation_correctness(out, &pid, &fv.checks);

    // --- Build-profile identity digest (canonical 1 MiB vector) ---
    let identity = run_identity_digest();
    append_identity_correctness(out, &pid, &bprof, &identity);

    // --- Stress smoke ---
    let stress_rows = run_stress_smoke(&prof);
    let stress_verdict = write_stress_csv(out, &pid, &stress_rows);

    // --- CPU attacker / defender throughput ---
    let cpu_duration = if prof == "ci" {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(5)
    };
    let cpu_rows = run_cpu_attacker_campaign(cpu_duration);
    write_cpu_csv(out, &pid, &platform, &bprof, cpu_duration, &cpu_rows);

    // --- GPU ---
    let gpu_verdict = run_gpu_phase(out, &pid, &platform);

    // --- SDK / FFI conformance ---
    let sdk_rows = run_sdk_phase(&prof);
    let sdk_verdict = write_sdk_csv(out, &pid, &sdk_rows);

    // --- Sanitizer markers ---
    write_sanitizer_rows(out, &pid);

    write_regressions_csv(out, &correctness_dir, &fv.checks, &sdk_rows, &stress_rows, &gpu_verdict, &pid);
    let regressions = count_regressions(out);

    let correctness_verdict = if correctness.verdict.starts_with("PASS") {
        "PASS".to_string()
    } else {
        "FAIL".to_string()
    };
    let verdict = if correctness_verdict != "PASS"
        || stress_verdict != "PASS"
        || sdk_verdict == "FAIL"
        || gpu_verdict == "FAIL"
        || identity.status == HwStatus::Fail
    {
        "FAIL"
    } else {
        "PASS"
    }
    .to_string();

    let summary = HardwareValidationSummary {
        platform_id: pid.clone(),
        platform: platform.clone(),
        build_profile: bprof.clone(),
        optimization: opt.into(),
        verdict: verdict.clone(),
        correctness_verdict: correctness_verdict.clone(),
        stress_verdict: stress_verdict.clone(),
        sdk_verdict: sdk_verdict.clone(),
        gpu_verdict: gpu_verdict.clone(),
        regressions,
    };

    write_report(out, &summary, &cpu_rows, &stress_rows);
    update_platform_matrix_status(out, &pid, &summary.verdict);
    summary
}

#[derive(Debug, Clone)]
struct IdentityDigest {
    digest_hex: String,
    ref_hex: String,
    status: HwStatus,
    detail: String,
}

fn run_identity_digest() -> IdentityDigest {
    let cfg = AntechConfig::builder()
        .memory_kib(1024)
        .graph(GraphKind::CombinedFrontier)
        .build()
        .unwrap();
    let pw = b"password";
    let salt = b"salt_16_bytes_!!";
    let prod = AntechEngine::new().derive(pw, salt, &cfg).unwrap();
    let reference = antech_kdf_reference::derive(
        pw,
        salt,
        &RefConfig {
            memory_kib: 1024,
            block_size: 32,
            fan_in: 2,
            graph_tag: GRAPH_COMBINED_FRONTIER,
            output_length: 32,
        },
    );
    let enc = hash_with_config_and_salt(pw, salt, &cfg).expect("identity hash");
    let ok_prod_ref = prod.as_slice() == reference.as_slice();
    let ok_verify = verify(pw, &enc).unwrap_or(false);
    let digest_hex = hex32(prod.as_slice());
    let ref_hex = hex32(reference.as_slice());
    let status = if ok_prod_ref && ok_verify {
        HwStatus::Pass
    } else {
        HwStatus::Fail
    };
    IdentityDigest {
        digest_hex,
        ref_hex,
        status,
        detail: format!("prod==ref={ok_prod_ref} verify={ok_verify}"),
    }
}

fn run_stress_smoke(prof: &str) -> Vec<StressScenarioRow> {
    let (secs, concs): (u64, Vec<usize>) = if prof == "ci" {
        (10, vec![1, 4, 8])
    } else {
        (30, vec![1, 10, 32])
    };
    let mut rows = Vec::new();
    for &conc in &concs {
        println!("stress mixed {secs}s × {conc} …");
        rows.push(run_mixed_scenario(secs, conc));
    }
    if prof == "ci" {
        println!("stress malformed 10s × 32 …");
        rows.push(run_malformed_scenario(10, 32));
    }
    rows
}

fn run_sdk_phase(prof: &str) -> Vec<SdkRow> {
    stage_native_artifacts();
    let mut rows = Vec::new();
    rows.push(run_cargo_test_row(
        "rust_conformance",
        "antech-kdf",
        "conformance",
    ));
    rows.push(run_cargo_test_row("ffi", "antech-kdf-ffi", ""));
    rows.push(run_cargo_test_row_research("reference", "antech-kdf-reference"));

    rows.push(run_python_conformance());
    rows.push(run_go_conformance());

    if prof == "full" {
        rows.push(run_tool_check("node_build", "node", &["--version"]));
        rows.push(run_tool_check("dotnet_build", "dotnet", &["--version"]));
    } else {
        rows.push(SdkRow {
            sdk: "node".into(),
            test: "conformance".into(),
            status: HwStatus::NotRun,
            detail: "Node conformance harness not in repo; build-only in sdk.yml".into(),
        });
        rows.push(SdkRow {
            sdk: "dotnet".into(),
            test: "conformance".into(),
            status: HwStatus::NotRun,
            detail: "Dotnet conformance not automated in CI".into(),
        });
    }

    rows.push(SdkRow {
        sdk: "java".into(),
        test: "conformance".into(),
        status: HwStatus::Blocked,
        detail: "Java/Kotlin bindings not in hardware-validation CI matrix".into(),
    });
    rows.push(SdkRow {
        sdk: "kotlin".into(),
        test: "conformance".into(),
        status: HwStatus::Blocked,
        detail: "Java/Kotlin bindings not in hardware-validation CI matrix".into(),
    });
    rows
}

#[derive(Debug, Clone)]
struct SdkRow {
    sdk: String,
    test: String,
    status: HwStatus,
    detail: String,
}

fn stage_native_artifacts() {
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-File", "sdk/scripts/build-native.ps1"])
            .status();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("bash")
            .args(["sdk/scripts/build-native.sh"])
            .status();
    }
}

fn run_cargo_test_row(name: &str, pkg: &str, filter: &str) -> SdkRow {
    let mut cmd = Command::new("cargo");
    cmd.args(["test", "-p", pkg, "--release"]);
    if !filter.is_empty() {
        cmd.args([filter, "--", "--nocapture"]);
    } else {
        cmd.args(["--", "--nocapture"]);
    }
    run_cargo_output_row(name, &mut cmd)
}

fn run_cargo_test_row_research(name: &str, pkg: &str) -> SdkRow {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "test",
        "--manifest-path",
        "research/code/Cargo.toml",
        "-p",
        pkg,
        "--release",
        "--",
        "--nocapture",
    ]);
    run_cargo_output_row(name, &mut cmd)
}

fn run_cargo_output_row(name: &str, cmd: &mut Command) -> SdkRow {
    match cmd.output() {
        Ok(o) if o.status.success() => SdkRow {
            sdk: "rust".into(),
            test: name.into(),
            status: HwStatus::Pass,
            detail: format!("exit=0 stdout_bytes={}", o.stdout.len()),
        },
        Ok(o) => SdkRow {
            sdk: "rust".into(),
            test: name.into(),
            status: HwStatus::Fail,
            detail: truncate_stderr(&o.stderr, 400),
        },
        Err(e) => SdkRow {
            sdk: "rust".into(),
            test: name.into(),
            status: HwStatus::Blocked,
            detail: format!("spawn failed: {e}"),
        },
    }
}

fn run_python_conformance() -> SdkRow {
    if !Command::new("python")
        .args(["--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return SdkRow {
            sdk: "python".into(),
            test: "conformance".into(),
            status: HwStatus::Blocked,
            detail: "python not on PATH".into(),
        };
    }
    if let Ok(o) = Command::new("python")
        .arg("sdk/conformance/run_python.py")
        .output()
    {
        if o.status.success() {
            return SdkRow {
                sdk: "python".into(),
                test: "conformance".into(),
                status: HwStatus::Pass,
                detail: "run_python.py ok (preinstalled)".into(),
            };
        }
    }
    match Command::new("python")
        .args([
            "-m",
            "pip",
            "install",
            "-q",
            "--user",
            "-e",
            "bindings/python",
        ])
        .output()
    {
        Ok(inst) if inst.status.success() => {}
        Ok(inst) => {
            return SdkRow {
                sdk: "python".into(),
                test: "conformance".into(),
                status: HwStatus::Blocked,
                detail: truncate_stderr(&inst.stderr, 300),
            };
        }
        Err(e) => {
            return SdkRow {
                sdk: "python".into(),
                test: "conformance".into(),
                status: HwStatus::Blocked,
                detail: format!("pip install failed: {e}"),
            };
        }
    }
    match Command::new("python")
        .arg("sdk/conformance/run_python.py")
        .output()
    {
        Ok(o) if o.status.success() => SdkRow {
            sdk: "python".into(),
            test: "conformance".into(),
            status: HwStatus::Pass,
            detail: "run_python.py ok".into(),
        },
        Ok(o) => SdkRow {
            sdk: "python".into(),
            test: "conformance".into(),
            status: HwStatus::Fail,
            detail: truncate_stderr(&o.stderr, 400),
        },
        Err(e) => SdkRow {
            sdk: "python".into(),
            test: "conformance".into(),
            status: HwStatus::Blocked,
            detail: format!("python run failed: {e}"),
        },
    }
}

fn run_go_conformance() -> SdkRow {
    if !Command::new("go")
        .args(["version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return SdkRow {
            sdk: "go".into(),
            test: "conformance".into(),
            status: HwStatus::Blocked,
            detail: "go not on PATH".into(),
        };
    }
    let mut cmd = Command::new("go");
    cmd.args(["test", "-v", "./..."])
        .current_dir("bindings/go")
        .env("CGO_ENABLED", "1");
    #[cfg(target_os = "windows")]
    {
        let native = std::env::current_dir()
            .ok()
            .map(|p| p.join("sdk/native"))
            .filter(|p| p.exists());
        if let Some(n) = native {
            let path = std::env::var("PATH").unwrap_or_default();
            cmd.env("PATH", format!("{};{}", n.display(), path));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        cmd.env(
            "LD_LIBRARY_PATH",
            format!(
                "{}:{}",
                std::env::current_dir()
                    .map(|p| p.join("sdk/native").display().to_string())
                    .unwrap_or_else(|_| "sdk/native".into()),
                std::env::var("LD_LIBRARY_PATH").unwrap_or_default()
            ),
        );
    }
    match cmd.output()
    {
        Ok(o) => SdkRow {
            sdk: "go".into(),
            test: "conformance".into(),
            status: if o.status.success() {
                HwStatus::Pass
            } else if String::from_utf8_lossy(&o.stderr).contains("gcc")
                || String::from_utf8_lossy(&o.stderr).contains("build constraints exclude")
            {
                HwStatus::Blocked
            } else {
                HwStatus::Fail
            },
            detail: if o.status.success() {
                "go test ./... ok".into()
            } else {
                truncate_stderr(&o.stderr, 400)
            },
        },
        Err(e) => SdkRow {
            sdk: "go".into(),
            test: "conformance".into(),
            status: HwStatus::Blocked,
            detail: format!("go test failed: {e}"),
        },
    }
}

fn run_tool_check(name: &str, bin: &str, args: &[&str]) -> SdkRow {
    match Command::new(bin).args(args).output() {
        Ok(o) if o.status.success() => SdkRow {
            sdk: name.into(),
            test: "toolchain".into(),
            status: HwStatus::Pass,
            detail: String::from_utf8_lossy(&o.stdout).trim().to_string(),
        },
        Ok(o) => SdkRow {
            sdk: name.into(),
            test: "toolchain".into(),
            status: HwStatus::Blocked,
            detail: truncate_stderr(&o.stderr, 200),
        },
        Err(e) => SdkRow {
            sdk: name.into(),
            test: "toolchain".into(),
            status: HwStatus::Blocked,
            detail: format!("{bin} missing: {e}"),
        },
    }
}

fn run_gpu_phase(out: &Path, pid: &str, platform: &PlatformInfo) -> String {
    let mut rows: Vec<String> = Vec::new();
    let cuda_present = platform.cuda_version.is_some()
        || platform.gpu_model.as_ref().is_some_and(|g| !g.is_empty());

    if !cuda_present {
        write_gpu_blocked(out, pid, "no CUDA GPU detected on host");
        return "BLOCKED".into();
    }

    if let Err(e) = compile_cuda_attacker() {
        write_gpu_blocked(out, pid, &format!("nvcc rebuild failed: {e}"));
        return "BLOCKED".into();
    }

    // Live research CUDA attacker correctness + bench (not production crate).
    let status = Command::new("cargo")
        .args([
            "run",
            "--manifest-path",
            "research/code/Cargo.toml",
            "--release",
            "-p",
            "antech-kdf-research",
            "--example",
            "v4_gpu_runner",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            // Copy measured rows from v4 gpu results if present.
            let src = PathBuf::from("research/results/compute-memory-v4/gpu/optimization-results.csv");
            if src.exists() {
                if let Ok(content) = fs::read_to_string(&src) {
                    for (i, line) in content.lines().enumerate() {
                        if i == 0 {
                            continue;
                        }
                        rows.push(line.to_string());
                    }
                }
            }
            write_gpu_csv(out, pid, &rows, "PASS", "live v4_gpu_runner");
            "PASS".into()
        }
        Ok(s) => {
            write_gpu_blocked(
                out,
                pid,
                &format!("v4_gpu_runner exit={} (production CPU vs CUDA mismatch)", s.code().unwrap_or(-1)),
            );
            "FAIL".into()
        }
        Err(e) => {
            write_gpu_blocked(out, pid, &format!("v4_gpu_runner spawn: {e}"));
            "BLOCKED".into()
        }
    }
}

fn write_environment_csv(
    out: &Path,
    pid: &str,
    p: &PlatformInfo,
    build_profile: &str,
    optimization: &str,
) {
    let path = out.join("environment.csv");
    let new_file = !path.exists();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("environment.csv");
    if new_file {
        writeln!(
            f,
            "platform_id,collected_at_unix,os,arch,cpu_model,logical_cpus,physical_cpus,ram_gib,rustc,cargo,build_profile,optimization,gpu_model,gpu_vram_mib,cuda_version,driver_version,profile"
        )
        .unwrap();
    }
    let phys = physical_cpus();
    let driver = gpu_driver_version();
    writeln!(
        f,
        "{pid},{},{},{},{},{},{},{},{},{},{build_profile},{optimization},{},{},{},{driver},{}",
        p.collected_at_unix,
        p.os,
        p.arch,
        csv_escape(&p.cpu_model),
        p.logical_cpus,
        phys,
        p.ram_gib.map(|r| format!("{r:.2}")).unwrap_or_default(),
        csv_escape(&p.rustc),
        csv_escape(&p.cargo),
        p.gpu_model.as_deref().unwrap_or(""),
        p.gpu_vram_mib.map(|v| v.to_string()).unwrap_or_default(),
        p.cuda_version.as_deref().unwrap_or(""),
        p.profile,
    )
    .unwrap();
}

fn write_platform_matrix_row(
    out: &Path,
    pid: &str,
    p: &PlatformInfo,
    build_profile: &str,
    optimization: &str,
) {
    let path = out.join("platform-matrix.csv");
    let new_file = !path.exists();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("platform-matrix.csv");
    if new_file {
        writeln!(
            f,
            "platform_id,os,arch,cpu_model,logical_cpus,physical_cpus,ram_gib,build_profile,optimization,rustc,gpu_model,cuda_version,validation_profile,status"
        )
        .unwrap();
    }
    writeln!(
        f,
        "{pid},{},{},{},{},{},{},{build_profile},{optimization},{},{},{},{},RUNNING",
        p.os,
        p.arch,
        csv_escape(&p.cpu_model),
        p.logical_cpus,
        physical_cpus(),
        p.ram_gib.map(|r| format!("{r:.2}")).unwrap_or_default(),
        csv_escape(&p.rustc),
        p.gpu_model.as_deref().unwrap_or(""),
        p.cuda_version.as_deref().unwrap_or(""),
        p.profile,
    )
    .unwrap();
}

fn write_correctness_csv(
    out: &Path,
    pid: &str,
    scratch: &Path,
    summary: &CorrectnessSummary,
) {
    let path = out.join("correctness.csv");
    let new_file = !path.exists();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("correctness.csv");
    if new_file {
        writeln!(
            f,
            "platform_id,suite,case_id,status,detail"
        )
        .unwrap();
    }
    let all = scratch.join("all-cases.csv");
    if all.exists() {
        if let Ok(content) = fs::read_to_string(&all) {
            for (i, line) in content.lines().enumerate() {
                if i == 0 {
                    continue;
                }
                writeln!(f, "{pid},{line}").unwrap();
            }
        }
    }
    writeln!(
        f,
        "{pid},_summary,campaign,{},\"cases={} pass={} fail={} blocked={} panics={}\"",
        summary.verdict,
        summary.totals.cases,
        summary.totals.pass,
        summary.totals.fail,
        summary.totals.blocked,
        summary.totals.panics_caught,
    )
    .unwrap();
}

fn append_final_validation_correctness(
    out: &Path,
    pid: &str,
    checks: &[final_validation::CheckRow],
) {
    let path = out.join("correctness.csv");
    let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
    for c in checks {
        let st = match c.status {
            CheckStatus::Pass => "Pass",
            CheckStatus::Fail => "Fail",
            CheckStatus::Blocked => "Blocked",
            CheckStatus::NotRun => "NotRun",
        };
        writeln!(
            f,
            "{pid},final_validation,{},{} ,\"{}\"",
            c.name,
            st,
            csv_escape(&c.detail)
        )
        .unwrap();
    }
}

fn append_identity_correctness(out: &Path, pid: &str, bprof: &str, id: &IdentityDigest) {
    let path = out.join("correctness.csv");
    let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(
        f,
        "{pid},identity,{bprof},{},{},\"digest={} ref={}\"",
        id.status.as_str(),
        csv_escape(&id.detail),
        id.digest_hex,
        id.ref_hex,
    )
    .unwrap();
    let identity_path = out.join("identity-digests.txt");
    let mut idf = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(identity_path)
        .unwrap();
    writeln!(idf, "{pid}\t{bprof}\t{}", id.digest_hex).unwrap();
}

fn write_stress_csv(out: &Path, pid: &str, rows: &[StressScenarioRow]) -> String {
    let path = out.join("stress.csv");
    let new_file = !path.exists();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("stress.csv");
    if new_file {
        writeln!(
            f,
            "platform_id,scenario,duration_secs,concurrency,ops_total,throughput_ops_per_sec,p50_ms,p95_ms,p99_ms,unexpected_errors,panics,scheduler_idle,budget_ok,queue_limit_ok,verdict"
        )
        .unwrap();
    }
    let mut verdict = "PASS".to_string();
    for r in rows {
        if r.unexpected_errors > 0 || r.panics > 0 || !r.scheduler_idle {
            verdict = "FAIL".into();
        }
        let row_verdict = if r.unexpected_errors == 0 && r.panics == 0 && r.scheduler_idle {
            "PASS"
        } else {
            "FAIL"
        };
        writeln!(
            f,
            "{pid},{},{},{},{},{},{:.3},{:.3},{:.3},{},{},{},{},{},{}",
            r.scenario,
            r.duration_secs,
            r.concurrency,
            r.ops_total,
            r.throughput_ops_per_sec,
            r.latency.p50_ms,
            r.latency.p95_ms,
            r.latency.p99_ms,
            r.unexpected_errors,
            r.panics,
            r.scheduler_idle,
            r.budget_ok,
            r.queue_limit_ok,
            row_verdict,
        )
        .unwrap();
    }
    verdict
}

fn write_cpu_csv(
    out: &Path,
    pid: &str,
    platform: &PlatformInfo,
    bprof: &str,
    duration: Duration,
    rows: &[CpuAttackerRow],
) {
    let path = out.join("cpu.csv");
    let new_file = !path.exists();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("cpu.csv");
    if new_file {
        writeln!(
            f,
            "platform_id,os,arch,cpu_model,build_profile,strategy,memory_mib,threads,guesses_per_sec,correct,measure_secs,warmup_secs,kind,notes"
        )
        .unwrap();
    }
    let measure_secs = duration.as_secs_f64();
    for r in rows {
        writeln!(
            f,
            "{pid},{},{},{},{bprof},{},{},{},{:.2},{},{measure_secs},0,{},{},",
            platform.os,
            platform.arch,
            csv_escape(&platform.cpu_model),
            r.strategy,
            r.memory_mib,
            r.threads,
            r.gps,
            r.correct,
            r.kind,
            csv_escape(&r.notes),
        )
        .unwrap();
    }
}

fn write_gpu_csv(out: &Path, pid: &str, data_lines: &[String], verdict: &str, notes: &str) {
    let path = out.join("gpu.csv");
    let new_file = !path.exists();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("gpu.csv");
    if new_file {
        writeln!(
            f,
            "platform_id,mode,guesses_per_sec,kernel_p50_ms,kernel_p95_ms,kernel_p99_ms,status,notes"
        )
        .unwrap();
    }
    if data_lines.is_empty() {
        writeln!(f, "{pid},,,,,,{verdict},\"{notes}\"").unwrap();
    } else {
        for line in data_lines {
            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() >= 5 {
                writeln!(
                    f,
                    "{pid},{},{},{},{},{},MEASURED,live v4_gpu_runner",
                    cols[0], cols[1], cols[2], cols[3], cols[4]
                )
                .unwrap();
            }
        }
    }
}

fn write_gpu_blocked(out: &Path, pid: &str, reason: &str) {
    write_gpu_csv(out, pid, &[], "BLOCKED", reason);
}

fn write_sdk_csv(out: &Path, pid: &str, rows: &[SdkRow]) -> String {
    let path = out.join("sdk-conformance.csv");
    let new_file = !path.exists();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("sdk-conformance.csv");
    if new_file {
        writeln!(f, "platform_id,sdk,test,status,detail").unwrap();
    }
    let mut any_fail = false;
    for r in rows {
        if r.status == HwStatus::Fail {
            any_fail = true;
        }
        writeln!(
            f,
            "{pid},{},{},{},{},",
            r.sdk,
            r.test,
            r.status.as_str(),
            csv_escape(&r.detail),
        )
        .unwrap();
    }
    if any_fail {
        "FAIL".into()
    } else {
        "PASS".into()
    }
}

fn write_sanitizer_rows(out: &Path, pid: &str) {
    let path = out.join("correctness.csv");
    let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
    let markers = [
        ("asan", "ANTECH_SANITIZER_ASAN_STATUS"),
        ("ubsan", "ANTECH_SANITIZER_UBSAN_STATUS"),
        ("miri", "ANTECH_MIRI_STATUS"),
    ];
    for (name, var) in markers {
        let (st, detail) = match std::env::var(var) {
            Ok(s) if s.eq_ignore_ascii_case("pass") => ("PASS", format!("{var}=pass")),
            Ok(s) if s.eq_ignore_ascii_case("fail") => ("FAIL", format!("{var}=fail")),
            Ok(s) if s.eq_ignore_ascii_case("blocked") => ("BLOCKED", format!("{var}=blocked")),
            Ok(s) => ("NOT RUN", format!("{var}={s}")),
            Err(_) => {
                #[cfg(target_os = "linux")]
                {
                    ("NOT RUN", format!("{var} unset; see sanitizers.yml"))
                }
                #[cfg(target_os = "windows")]
                {
                    ("BLOCKED", format!("{var} unset; ASan/Miri blocked on Windows MSVC host"))
                }
                #[cfg(target_os = "macos")]
                {
                    ("BLOCKED", format!("{var} unset; sanitizers not run on macOS GHA"))
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
                {
                    ("NOT RUN", format!("{var} unset"))
                }
            }
        };
        writeln!(
            f,
            "{pid},sanitizer,{name},{st},\"{detail}\""
        )
        .unwrap();
    }
}

fn write_regressions_csv(
    out: &Path,
    correctness_scratch: &Path,
    fv_checks: &[final_validation::CheckRow],
    sdk: &[SdkRow],
    stress: &[StressScenarioRow],
    gpu_verdict: &str,
    pid: &str,
) {
    let path = out.join("regressions.csv");
    let mut f = File::create(&path).expect("regressions.csv");
    writeln!(f, "area,id,status,detail").unwrap();

    let reg = correctness_scratch.join("regressions.csv");
    if reg.exists() {
        if let Ok(s) = fs::read_to_string(&reg) {
            for (i, line) in s.lines().enumerate() {
                if i == 0 {
                    continue;
                }
                writeln!(f, "correctness,{line}").unwrap();
            }
        }
    }
    for c in fv_checks {
        if matches!(c.status, CheckStatus::Fail) {
            writeln!(
                f,
                "final_validation,{},FAIL,\"{}\"",
                c.name,
                csv_escape(&c.detail)
            )
            .unwrap();
        }
    }
    for r in sdk {
        if r.status == HwStatus::Fail {
            writeln!(
                f,
                "sdk,{}_{},FAIL,\"{}\"",
                r.sdk,
                r.test,
                csv_escape(&r.detail)
            )
            .unwrap();
        }
    }
    for r in stress {
        if r.unexpected_errors > 0 || r.panics > 0 {
            writeln!(
                f,
                "stress,{}_{}c,FAIL,\"unexpected={} panics={}\"",
                r.scenario,
                r.concurrency,
                r.unexpected_errors,
                r.panics
            )
            .unwrap();
        }
    }
    if gpu_verdict == "FAIL" {
        writeln!(
            f,
            "gpu,{pid}_live_cuda,FAIL,\"production AntechEngine CPU digests != live CUDA attacker (v4c_gpu_attacker)\""
        )
        .unwrap();
    }
}

fn count_regressions(out: &Path) -> u64 {
    let path = out.join("regressions.csv");
    if !path.exists() {
        return 0;
    }
    fs::read_to_string(&path)
        .map(|s| s.lines().skip(1).count() as u64)
        .unwrap_or(0)
}

fn write_report(
    out: &Path,
    summary: &HardwareValidationSummary,
    cpu_rows: &[CpuAttackerRow],
    stress_rows: &[StressScenarioRow],
) {
    let p = &summary.platform;
    let strongest = crate::engineering::cpu_attacker::strongest_row(cpu_rows);
    let mut f = File::create(out.join("report.md")).expect("report.md");
    writeln!(f, "# Hardware validation report\n").unwrap();
    writeln!(f, "| Field | Value |").unwrap();
    writeln!(f, "|-------|-------|").unwrap();
    writeln!(f, "| Platform ID | {} |", summary.platform_id).unwrap();
    writeln!(f, "| Verdict | **{}** |", summary.verdict).unwrap();
    writeln!(f, "| OS / arch | {} / {} |", p.os, p.arch).unwrap();
    writeln!(f, "| CPU | {} ({} logical) |", p.cpu_model, p.logical_cpus).unwrap();
    writeln!(f, "| RAM (GiB) | {:?} |", p.ram_gib).unwrap();
    writeln!(f, "| Rust | {} |", p.rustc).unwrap();
    writeln!(f, "| Build | {} ({}) |", summary.build_profile, summary.optimization).unwrap();
    writeln!(f, "| GPU | {:?} |", p.gpu_model).unwrap();
    writeln!(f, "| CUDA | {:?} |", p.cuda_version).unwrap();
    writeln!(f).unwrap();

    writeln!(f, "## Sub-campaign verdicts\n").unwrap();
    writeln!(f, "| Area | Verdict |").unwrap();
    writeln!(f, "|------|---------|").unwrap();
    writeln!(f, "| Correctness | {} |", summary.correctness_verdict).unwrap();
    writeln!(f, "| Stress / concurrency | {} |", summary.stress_verdict).unwrap();
    writeln!(f, "| SDK / FFI | {} |", summary.sdk_verdict).unwrap();
    writeln!(f, "| GPU (live CUDA) | {} |", summary.gpu_verdict).unwrap();
    writeln!(f, "| Regressions | {} |", summary.regressions).unwrap();
    writeln!(f).unwrap();

    if let Some(s) = strongest {
        writeln!(f, "## CPU throughput (this host only)\n").unwrap();
        writeln!(
            f,
            "Strongest measured row: `{}` @ {} threads → {:.1} guesses/s (16 MiB). \
             **Do not treat as cross-hardware algorithmic ranking.**\n",
            s.strategy, s.threads, s.gps
        )
        .unwrap();
    }

    if !stress_rows.is_empty() {
        let r = &stress_rows[0];
        writeln!(f, "## Defender latency (production path, this host)\n").unwrap();
        writeln!(
            f,
            "Mixed scenario {}s × {} workers: p50={:.1}ms p95={:.1}ms p99={:.1}ms\n",
            r.duration_secs, r.concurrency, r.latency.p50_ms, r.latency.p95_ms, r.latency.p99_ms
        )
        .unwrap();
    }

    writeln!(f, "## Status legend\n").unwrap();
    writeln!(f, "- **PASS** — executed; criteria met").unwrap();
    writeln!(f, "- **FAIL** — executed; mismatch or crash").unwrap();
    writeln!(f, "- **BLOCKED** — tool/GPU/OS limitation; not a crypto pass").unwrap();
    writeln!(f, "- **NOT RUN** — skipped in this profile").unwrap();
    writeln!(f, "- **NOT APPLICABLE** — does not apply on platform").unwrap();
    writeln!(f).unwrap();
    writeln!(
        f,
        "Artifacts: `platform-matrix.csv`, `environment.csv`, `correctness.csv`, \
         `cpu.csv`, `gpu.csv`, `sdk-conformance.csv`, `stress.csv`, `regressions.csv`."
    )
    .unwrap();
}

fn update_platform_matrix_status(out: &Path, pid: &str, verdict: &str) {
    let path = out.join("platform-matrix.csv");
    if !path.exists() {
        return;
    }
    let content = fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    for line in lines.iter_mut().skip(1) {
        if line.starts_with(pid) {
            if let Some(idx) = line.rfind(',') {
                *line = format!("{},{}", &line[..idx], verdict);
            }
        }
    }
    let _ = fs::write(path, lines.join("\n") + "\n");
}

fn physical_cpus() -> usize {
    if let Ok(o) = Command::new("lscpu").output() {
        let s = String::from_utf8_lossy(&o.stdout);
        let mut sockets = 1usize;
        let mut cores_per = 1usize;
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("Socket(s):") {
                sockets = v.trim().parse().unwrap_or(1);
            }
            if let Some(v) = line.strip_prefix("Core(s) per socket:") {
                cores_per = v.trim().parse().unwrap_or(1);
            }
        }
        if sockets > 1 || cores_per > 1 {
            return sockets * cores_per;
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn compile_cuda_attacker() -> Result<(), String> {
    let cu = PathBuf::from(
        "research/code/antech-kdf-research/src/compute_memory_v4/cuda/v4c_gpu_attacker.cu",
    );
    if !cu.exists() {
        return Err("v4c_gpu_attacker.cu missing".into());
    }
    let out_dir = cu.parent().expect("cuda parent");
    let bin = if cfg!(windows) {
        out_dir.join("v4c_gpu_attacker.exe")
    } else {
        out_dir.join("v4c_gpu_attacker")
    };
    let status = Command::new("nvcc")
        .args(["-O3", "-std=c++17", "-o"])
        .arg(&bin)
        .arg(&cu)
        .status()
        .map_err(|e| format!("nvcc spawn: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("nvcc exit={}", status.code().unwrap_or(-1)))
    }
}

fn gpu_driver_version() -> String {
    if let Ok(o) = Command::new("nvidia-smi")
        .args(["--query-gpu=driver_version", "--format=csv,noheader"])
        .output()
    {
        let t = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !t.is_empty() {
            return t;
        }
    }
    String::new()
}

fn hex32(d: &[u8]) -> String {
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn csv_escape(s: &str) -> String {
    s.replace('"', "'").replace(',', ";")
}

fn truncate_stderr(stderr: &[u8], max: usize) -> String {
    let t = String::from_utf8_lossy(stderr);
    if t.len() <= max {
        t.into_owned()
    } else {
        format!("{}…", &t[..max])
    }
}
