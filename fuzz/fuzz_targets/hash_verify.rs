#![no_main]
//! Fuzz hash/verify input handling. Full derives limited to tiny configs to avoid hangs.

use antech_kdf::{hash_with_config, hash_with_config_and_salt, verify, AntechConfig};
use antech_kdf_format::parse_hash;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        let _ = verify(b"", "");
        return;
    }

    let mid = data.len() / 2;
    let pass = &data[..mid];
    let rest = &data[mid..];

    if let Ok(encoded) = std::str::from_utf8(rest) {
        // Always exercise parse + verify error paths; gate expensive derives.
        match parse_hash(encoded) {
            Ok(c) if c.memory_kib <= 1024 => {
                let _ = verify(pass, encoded);
            }
            Ok(_) => {
                // Large declared memory: verify should fail-fast (admission) or err — must not hang.
                let _ = verify(pass, encoded);
            }
            Err(_) => {
                let v = verify(pass, encoded);
                assert!(v.is_err(), "malformed hash must not verify Ok");
            }
        }
    }

    // Occasional tiny hash when fuzzer provides enough entropy
    if data.len() >= 20 && data[0] == 0xA5 {
        let cfg = AntechConfig::builder()
            .memory_kib(1024)
            .salt_length(16)
            .block_size(32)
            .fan_in(2)
            .output_length(32)
            .build();
        if let Ok(cfg) = cfg {
            let salt = &data[1..17];
            let pw = &data[17..];
            if let Ok(enc) = hash_with_config_and_salt(pw, salt, &cfg) {
                let _ = verify(pw, &enc);
                let _ = verify(b"wrong", &enc);
            }
            let _ = hash_with_config(pw, &cfg);
        }
    }
});
