//! Shared fuzz surface logic (no libFuzzer dependency).
//! libFuzzer targets and the Windows/CI fallback campaign both call these runners.

use antech_kdf::{
    hash_with_config, hash_with_config_and_salt, verify, AntechConfig, GraphKind,
};
use antech_kdf_core::{BoundedResourceScheduler, ResourcePolicy, ResourceScheduler};
use antech_kdf_format::parse_hash;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Default, Clone, Debug)]
pub struct TargetStats {
    pub name: String,
    pub executions: u64,
    pub panics: u64,
    pub assertion_fails: u64,
    pub corpus_seeds: u64,
    pub elapsed_secs: f64,
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn fill(seed: &mut u64, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    for b in &mut v {
        *b = (xorshift(seed) & 0xff) as u8;
    }
    v
}

pub fn run_parser(data: &[u8]) -> Result<(), String> {
    const SEED: &str = "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee";
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() <= 16_384 {
            let parsed = parse_hash(s);
            let shaped = s.len() >= 8
                && s.as_bytes().first() == Some(&b'$')
                && s.to_ascii_lowercase().starts_with("$antech$");
            if !shaped && parsed.is_ok() {
                return Err("garbage accepted as hash".into());
            }
        }
    }
    if !data.is_empty() {
        let mut bytes = SEED.as_bytes().to_vec();
        let n = (data[0] as usize % 8) + 1;
        for i in 0..n {
            let idx = data.get(i + 1).copied().unwrap_or(0) as usize % bytes.len();
            let xor = data.get(i + 9).copied().unwrap_or(0x5a);
            bytes[idx] ^= xor;
        }
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = parse_hash(s);
        }
    }
    Ok(())
}

pub fn run_config(data: &[u8]) -> Result<(), String> {
    if data.len() < 12 {
        return Ok(());
    }
    let memory = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let salt = u16::from_le_bytes(data[4..6].try_into().unwrap()) as usize;
    let block = u16::from_le_bytes(data[6..8].try_into().unwrap()) as usize;
    let fan = u32::from(data[8]);
    let graph_tag = u32::from(data[9]);
    let out_len = u16::from_le_bytes(data[10..12].try_into().unwrap()) as usize;
    let mut b = AntechConfig::builder()
        .memory_kib(memory)
        .salt_length(salt)
        .block_size(block)
        .fan_in(fan)
        .output_length(out_len);
    if let Some(g) = GraphKind::from_tag(graph_tag) {
        b = b.graph(g);
    }
    if let Ok(cfg) = b.build() {
        if cfg.block_size.as_bytes() > 64 {
            return Err("accepted block_size > 64".into());
        }
        if cfg.num_blocks() < 64 {
            return Err("accepted <64 blocks".into());
        }
        if !(2..=8).contains(&cfg.fan_in.get()) {
            return Err("accepted fan_in out of 2..=8".into());
        }
    }
    Ok(())
}

pub fn run_hash_verify(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        let _ = verify(b"", "");
        return Ok(());
    }
    let mid = data.len() / 2;
    let pass = &data[..mid];
    let rest = &data[mid..];
    if let Ok(encoded) = std::str::from_utf8(rest) {
        match parse_hash(encoded) {
            Ok(_) => {
                let _ = verify(pass, encoded);
            }
            Err(_) => {
                if verify(pass, encoded).is_ok() {
                    return Err("malformed hash verified".into());
                }
            }
        }
    }
    if data.len() >= 20 && data[0] == 0xA5 {
        if let Ok(cfg) = AntechConfig::builder()
            .memory_kib(1024)
            .salt_length(16)
            .block_size(32)
            .fan_in(2)
            .output_length(32)
            .build()
        {
            let salt = &data[1..17];
            let pw = &data[17..];
            if let Ok(enc) = hash_with_config_and_salt(pw, salt, &cfg) {
                let _ = verify(pw, &enc);
                let _ = verify(b"wrong", &enc);
            }
            let _ = hash_with_config(pw, &cfg);
        }
    }
    Ok(())
}

pub fn run_malformed_v2(data: &[u8]) -> Result<(), String> {
    let hex: String = data.iter().take(64).map(|b| format!("{b:02x}")).collect();
    let m = 1024usize.saturating_add(data.first().copied().unwrap_or(0) as usize);
    let templates = [
        format!("$antech$v2$m={m},s=16,b=32,f=2,g=3,l=32${hex}${hex}"),
        format!("$antech$v1$m={m},s=16,b=32,f=2,g=3,l=32${hex}${hex}"),
        format!("$antech$v2$m={m},s=16,b=32,f=2,g=3,l=32,m=2048${hex}${hex}"),
        format!("$antech$v2$m=-1,s=16,b=32,f=2,g=3,l=32${hex}${hex}"),
        format!("$antech$v2$m={m},s=16,b=128,f=2,g=3,l=32${hex}${hex}"),
        format!("$bogus$v2$m={m},s=16,b=32,f=2,g=3,l=32${hex}${hex}"),
    ];
    for s in &templates {
        let p = parse_hash(s);
        let v = verify(b"fuzz", s);
        if p.is_err() && v.is_ok() {
            return Err("verify Ok on unparsable".into());
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() <= 8192 {
            let _ = parse_hash(s);
        }
    }
    Ok(())
}

pub fn run_scheduler(data: &[u8]) -> Result<(), String> {
    if data.len() < 8 {
        return Ok(());
    }
    let max_mem = 1 + (u16::from_le_bytes([data[0], data[1]]) as usize);
    let max_jobs = 1 + (data[2] % 16) as usize;
    let queue = (data[3] % 32) as usize;
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
            1 + (u16::from_le_bytes([data[4], data[5]]) as usize)
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
        if st.waiting_jobs > queue && queue > 0 {
            return Err(format!("waiting_jobs {} > queue_limit {queue}", st.waiting_jobs));
        }
    }
    for p in permits {
        sched.release(p);
    }
    let st = sched.stats();
    if st.active_jobs != 0 || st.waiting_jobs != 0 || st.allocated_kib != 0 {
        return Err(format!("scheduler leak {st:?}"));
    }
    Ok(())
}

pub fn run_ffi(data: &[u8]) -> Result<(), String> {
    use antech_kdf_ffi::{
        antech_config_default, antech_free, antech_hash_bytes, antech_hash_with_config_and_salt,
        antech_verify_bytes, antech_version, AntechConfigC, AntechStatus,
        ANTECH_GRAPH_COMBINED_FRONTIER,
    };
    use std::os::raw::c_char;
    use std::ptr;

    unsafe {
        let _ = antech_version();
        if antech_config_default(ptr::null_mut()) != AntechStatus::InvalidInput {
            return Err("null config_default accepted".into());
        }
        let mut cfg = std::mem::zeroed::<AntechConfigC>();
        let _ = antech_config_default(&mut cfg);

        let mut out: *mut c_char = ptr::null_mut();
        if antech_hash_bytes(ptr::null(), 1, &mut out) != AntechStatus::InvalidInput {
            return Err("null password accepted".into());
        }
        if antech_hash_bytes(data.as_ptr(), data.len(), ptr::null_mut()) != AntechStatus::InvalidInput
        {
            return Err("null out accepted".into());
        }

        let tiny = AntechConfigC {
            memory_kib: 1024,
            salt_length: 16,
            block_size: 32,
            fan_in: 2,
            graph: ANTECH_GRAPH_COMBINED_FRONTIER,
            output_length: 32,
        };
        if data.len() >= 16 {
            let salt = &data[..16];
            let pw = &data[16..];
            out = ptr::null_mut();
            let st = antech_hash_with_config_and_salt(
                pw.as_ptr(),
                pw.len(),
                salt.as_ptr(),
                salt.len(),
                &tiny,
                &mut out,
            );
            if st == AntechStatus::Ok && !out.is_null() {
                let _ = antech_verify_bytes(pw.as_ptr(), pw.len(), out);
                let _ = antech_verify_bytes(b"x".as_ptr(), 1, out);
                antech_free(out);
            }
        }
        if let Ok(s) = std::str::from_utf8(data) {
            let s = if s.len() > 4096 { &s[..4096] } else { s };
            if let Ok(c) = std::ffi::CString::new(s) {
                let _ = antech_verify_bytes(b"pw".as_ptr(), 2, c.as_ptr());
            }
        }
        antech_free(ptr::null_mut());
    }
    Ok(())
}

type TargetFn = fn(&[u8]) -> Result<(), String>;

fn load_corpus(dir: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Ok(bytes) = std::fs::read(e.path()) {
                out.push(bytes);
            }
        }
    }
    out
}

fn record_failure(crash_dir: &Path, label: &str, data: &[u8], msg: Option<&str>) {
    let _ = std::fs::create_dir_all(crash_dir);
    let path = crash_dir.join(label);
    let _ = std::fs::write(&path, data);
    if let Some(msg) = msg {
        let _ = std::fs::write(path.with_extension("msg"), msg.as_bytes());
    }
}

fn execute_once(
    f: TargetFn,
    data: &[u8],
    stats: &mut TargetStats,
    crash_dir: &Path,
    label: String,
) {
    stats.executions += 1;
    match catch_unwind(AssertUnwindSafe(|| f(data))) {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => {
            stats.assertion_fails += 1;
            if stats.assertion_fails <= 20 {
                record_failure(crash_dir, &label, data, Some(&msg));
            }
        }
        Err(_) => {
            stats.panics += 1;
            if stats.panics <= 20 {
                record_failure(crash_dir, &label, data, None);
            }
        }
    }
}

pub fn campaign(
    name: &str,
    f: TargetFn,
    corpus_dir: &Path,
    duration: Duration,
    crash_dir: &Path,
) -> TargetStats {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut stats = TargetStats {
        name: name.into(),
        ..Default::default()
    };
    let corpus = load_corpus(corpus_dir);
    stats.corpus_seeds = corpus.len() as u64;
    let t0 = Instant::now();
    let mut seed = 0xF00D_CAFEu64 ^ (name.len() as u64);

    for (i, item) in corpus.iter().enumerate() {
        execute_once(
            f,
            item,
            &mut stats,
            crash_dir,
            format!("{name}_corpus_{i}"),
        );
    }

    while t0.elapsed() < duration {
        let len = 1 + (xorshift(&mut seed) % 512) as usize;
        let mut data = fill(&mut seed, len);
        if !corpus.is_empty() && (xorshift(&mut seed) % 4 == 0) {
            let base = &corpus[(xorshift(&mut seed) as usize) % corpus.len()];
            data = base.clone();
            if !data.is_empty() {
                let idx = (xorshift(&mut seed) as usize) % data.len();
                data[idx] ^= (xorshift(&mut seed) & 0xff) as u8;
            }
        }
        let label = if stats.assertion_fails + stats.panics > 0 {
            format!(
                "{name}_mut_{}",
                stats.assertion_fails + stats.panics
            )
        } else {
            format!("{name}_mut")
        };
        execute_once(f, &data, &mut stats, crash_dir, label);
    }

    stats.elapsed_secs = t0.elapsed().as_secs_f64();
    std::panic::set_hook(prev);
    stats
}

/// Canonical target list for the fallback campaign (corpus path relative to repo root).
pub fn campaign_targets() -> &'static [(&'static str, &'static str, TargetFn)] {
    &[
        ("parser", "fuzz/corpus/hash_parser", run_parser),
        ("config", "fuzz/corpus/config_builder", run_config),
        ("hash_verify", "fuzz/corpus/hash_verify", run_hash_verify),
        ("malformed_v2", "fuzz/corpus/malformed_v2", run_malformed_v2),
        ("ffi", "fuzz/corpus/ffi_api", run_ffi),
        ("scheduler", "fuzz/corpus/scheduler", run_scheduler),
    ]
}

pub fn csv_name(target: &str) -> PathBuf {
    match target {
        "malformed_v2" => PathBuf::from("parser_malformed_v2.csv"),
        other => PathBuf::from(format!("{other}.csv")),
    }
}
