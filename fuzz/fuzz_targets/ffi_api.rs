#![no_main]
//! Fuzz FFI entry points for panic containment and null/length handling.
//! Avoids default 16 MiB hashes; uses tiny config + bytes APIs.

use antech_kdf_ffi::{
    antech_config_default, antech_free, antech_hash_bytes, antech_hash_with_config_and_salt,
    antech_verify_bytes, antech_version, AntechConfigC, AntechStatus,
    ANTECH_GRAPH_COMBINED_FRONTIER,
};
use libfuzzer_sys::fuzz_target;
use std::os::raw::c_char;
use std::ptr;

fuzz_target!(|data: &[u8]| {
    unsafe {
        // Null / default config paths
        let _ = antech_version();
        assert_eq!(
            antech_config_default(ptr::null_mut()),
            AntechStatus::InvalidInput
        );
        let mut cfg = AntechConfigC {
            memory_kib: 0,
            salt_length: 0,
            block_size: 0,
            fan_in: 0,
            graph: 0,
            output_length: 0,
        };
        let _ = antech_config_default(&mut cfg);

        // Null password / out
        let mut out: *mut c_char = ptr::null_mut();
        assert_eq!(
            antech_hash_bytes(ptr::null(), 1, &mut out),
            AntechStatus::InvalidInput
        );
        assert_eq!(
            antech_hash_bytes(data.as_ptr(), data.len(), ptr::null_mut()),
            AntechStatus::InvalidInput
        );

        // Tiny config hash when possible
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
            let pw = &data[16.min(data.len())..];
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

        // Malformed hash verify
        if let Ok(s) = std::str::from_utf8(data) {
            // Cap to avoid huge CString attempts
            let s = if s.len() > 4096 { &s[..4096] } else { s };
            if let Ok(c) = std::ffi::CString::new(s) {
                let _ = antech_verify_bytes(b"pw".as_ptr(), 2, c.as_ptr());
            }
        }

        antech_free(ptr::null_mut());
    }
});
