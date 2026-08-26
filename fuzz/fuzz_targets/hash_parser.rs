#![no_main]
//! Fuzz the v2 hash parser with arbitrary UTF-8 and structured mutations.

use libfuzzer_sys::fuzz_target;

const SEED: &str = "$antech$v2$m=1024,s=16,b=32,f=2,g=3,l=32$0011223344556677889900aabbccddee$0011223344556677889900aabbccddee0011223344556677889900aabbccddee";

fuzz_target!(|data: &[u8]| {
    // Path A: raw bytes as UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        // Guard: parser itself must reject oversized before alloc
        if s.len() <= 16_384 {
            let parsed = antech_kdf_format::parse_hash(s);
            let shaped = s.len() >= 8
                && s.as_bytes().first() == Some(&b'$')
                && s.to_ascii_lowercase().starts_with("$antech$");
            if !shaped {
                assert!(parsed.is_err(), "garbage accepted as hash");
            }
            let _ = parsed;
        }
    }

    // Path B: mutate around a valid seed hash (bit flips / splices)
    if !data.is_empty() {
        let mut bytes = SEED.as_bytes().to_vec();
        let n = (data[0] as usize % 8) + 1;
        for i in 0..n {
            let idx = data.get(i + 1).copied().unwrap_or(0) as usize % bytes.len();
            let xor = data.get(i + 9).copied().unwrap_or(0x5a);
            bytes[idx] ^= xor;
        }
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = antech_kdf_format::parse_hash(s);
        }
    }
});
