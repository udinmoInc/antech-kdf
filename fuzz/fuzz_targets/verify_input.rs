#![no_main]
//! Legacy alias target — password/hash split verify fuzzing.

use antech_kdf_format::parse_hash;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mid = data.len() / 2;
    let pass = &data[..mid];
    if let Ok(encoded_hash) = std::str::from_utf8(&data[mid..]) {
        if encoded_hash.len() > 8192 {
            return;
        }
        match parse_hash(encoded_hash) {
            Ok(c) if c.memory_kib > 1024 => {
                let _ = antech_kdf::verify(pass, encoded_hash);
            }
            Ok(_) => {
                let _ = antech_kdf::verify(pass, encoded_hash);
            }
            Err(_) => {
                assert!(
                    antech_kdf::verify(pass, encoded_hash).is_err(),
                    "malformed must not verify"
                );
            }
        }
    }
});
