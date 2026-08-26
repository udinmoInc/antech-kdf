#![no_main]
//! Structured malformed v2 strings near the real grammar.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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
        let p = antech_kdf_format::parse_hash(s);
        let v = antech_kdf::verify(b"fuzz", s);
        if p.is_err() {
            assert!(v.is_err(), "verify Ok on unparsable hash");
        }
    }

    // Raw splice
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() <= 8192 {
            let _ = antech_kdf_format::parse_hash(s);
        }
    }
});
