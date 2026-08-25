#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Construct near-v2 strings with mutated fields.
    let hex: String = data
        .iter()
        .take(64)
        .map(|b| format!("{:02x}", b))
        .collect();
    let m = 1024 + (data.first().copied().unwrap_or(0) as usize);
    let s = format!(
        "$antech$v2$m={m},s=16,b=32,f=2,g=3,l=32${hex}${hex}"
    );
    let _ = antech_kdf_format::parse_hash(&s);
    let _ = antech_kdf::verify(b"fuzz", &s);
});
