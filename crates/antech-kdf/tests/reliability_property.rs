//! Property-style tests: parser and verify must not panic on arbitrary input.

use antech_kdf::verify;
use antech_kdf_format::parse_hash;
use rand::RngCore;

#[test]
fn parse_never_panics_on_random_utf8() {
    let mut rng = rand::thread_rng();
    for _ in 0..512 {
        let len = (rng.next_u32() % 4096) as usize;
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        // Restrict to UTF-8-ish printable + some binary edge cases
        for b in &mut bytes {
            if *b == 0 {
                *b = b'a';
            }
        }
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = parse_hash(s);
        }
    }
}

#[test]
fn verify_never_panics_on_arbitrary_bytes() {
    let mut rng = rand::thread_rng();
    for _ in 0..512 {
        let pass_len = (rng.next_u32() % 512) as usize;
        let tail_len = (rng.next_u32() % 512) as usize;
        let mut pass = vec![0u8; pass_len];
        let mut tail = vec![0u8; tail_len];
        rng.fill_bytes(&mut pass);
        rng.fill_bytes(&mut tail);
        if let Ok(hash_str) = std::str::from_utf8(&tail) {
            let _ = verify(&pass, hash_str);
        }
    }
}
