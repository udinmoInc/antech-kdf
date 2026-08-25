#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mid = data.len() / 2;
    let pass = &data[..mid];
    if let Ok(encoded_hash) = std::str::from_utf8(&data[mid..]) {
        let _ = antech_kdf::verify(pass, encoded_hash);
    }
});