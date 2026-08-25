//! C ABI for Antech KDF — thin FFI over the canonical Rust implementation.
//!
//! # Ownership
//! - Strings returned by hash helpers are heap-allocated; free with [`antech_free`].
//! - Config / policy structs are owned by the caller (plain POD).
//!
//! # Thread safety
//! All entry points are thread-safe and stateless (global scheduler is internal).
//!
//! # Passwords
//! Prefer the `*_bytes` entry points for arbitrary binary passwords. NUL-terminated
//! helpers stop at the first embedded NUL.
//!
//! # Safety
//! All `unsafe extern "C"` entry points require non-null pointers where documented in
//! `bindings/c/antech_kdf.h`, valid UTF-8 for encoded hashes, and that password/salt
//! buffers remain readable for `len` bytes for the duration of the call.

#![allow(clippy::missing_safety_doc)]

use libc::{c_char, c_int, size_t};
use std::ffi::{CStr, CString};
use std::slice;

use antech_kdf::{
    hash_with_config, hash_with_config_and_salt, needs_rehash_with_policy, verify, AntechConfig,
    FanIn, GraphKind, MemorySize, OutputLength, RehashPolicy,
};

/// Status codes returned by C ABI functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntechStatus {
    Ok = 0,
    VerificationFailed = 1,
    InvalidInput = -1,
    InvalidHash = -2,
    InternalError = -3,
    InvalidConfig = -4,
}

/// Graph kind tags (match encoded `g=` parameter).
pub const ANTECH_GRAPH_REDUCED_CRITICAL_PATH: u32 = 1;
pub const ANTECH_GRAPH_CACHE_LOCALITY: u32 = 2;
pub const ANTECH_GRAPH_COMBINED_FRONTIER: u32 = 3;

/// Configuration POD matching production [`AntechConfig`] fields.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AntechConfigC {
    pub memory_kib: u32,
    pub salt_length: u32,
    pub block_size: u32,
    pub fan_in: u32,
    pub graph: u32,
    pub output_length: u32,
}

/// Rehash policy POD matching production [`RehashPolicy`] fields.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AntechRehashPolicyC {
    pub minimum_memory_kib: u32,
    pub preferred_memory_kib: u32,
    pub preferred_fan_in: u32,
    pub preferred_output_length: u32,
}

fn map_err(err: antech_kdf::Error) -> AntechStatus {
    match err {
        antech_kdf::Error::Config(_) => AntechStatus::InvalidConfig,
        antech_kdf::Error::Encoding(_) => AntechStatus::InvalidHash,
        antech_kdf::Error::Derivation(_) | antech_kdf::Error::ResourceExhausted(_) => {
            AntechStatus::InternalError
        }
    }
}

fn graph_from_tag(tag: u32) -> Option<GraphKind> {
    GraphKind::from_tag(tag)
}

fn config_from_c(c: &AntechConfigC) -> Result<AntechConfig, AntechStatus> {
    let graph = graph_from_tag(c.graph).ok_or(AntechStatus::InvalidConfig)?;
    AntechConfig::builder()
        .memory_kib(c.memory_kib as usize)
        .salt_length(c.salt_length as usize)
        .block_size(c.block_size as usize)
        .fan_in(c.fan_in)
        .graph(graph)
        .output_length(c.output_length as usize)
        .build()
        .map_err(|_| AntechStatus::InvalidConfig)
}

fn policy_from_c(p: &AntechRehashPolicyC) -> RehashPolicy {
    RehashPolicy {
        minimum_memory: MemorySize::kib(p.minimum_memory_kib as usize),
        preferred_memory: MemorySize::kib(p.preferred_memory_kib as usize),
        preferred_fan_in: FanIn::new(p.preferred_fan_in),
        preferred_output_length: OutputLength::bytes(p.preferred_output_length as usize),
    }
}

fn give_string(s: String, out: *mut *mut c_char) -> AntechStatus {
    match CString::new(s) {
        Ok(c) => {
            unsafe {
                *out = c.into_raw();
            }
            AntechStatus::Ok
        }
        Err(_) => AntechStatus::InternalError,
    }
}

/// Library version string (NUL-terminated static).
#[no_mangle]
pub extern "C" fn antech_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

/// Fills `out` with production defaults (16 MiB, combined-frontier, …).
#[no_mangle]
pub unsafe extern "C" fn antech_config_default(out: *mut AntechConfigC) -> AntechStatus {
    if out.is_null() {
        return AntechStatus::InvalidInput;
    }
    let d = AntechConfig::default();
    *out = AntechConfigC {
        memory_kib: d.memory.as_kib() as u32,
        salt_length: d.salt_length.as_bytes() as u32,
        block_size: d.block_size.as_bytes() as u32,
        fan_in: d.fan_in.get(),
        graph: d.graph.tag(),
        output_length: d.output_length.as_bytes() as u32,
    };
    AntechStatus::Ok
}

/// Fills `out` with the default rehash policy.
#[no_mangle]
pub unsafe extern "C" fn antech_rehash_policy_default(
    out: *mut AntechRehashPolicyC,
) -> AntechStatus {
    if out.is_null() {
        return AntechStatus::InvalidInput;
    }
    let d = RehashPolicy::default();
    *out = AntechRehashPolicyC {
        minimum_memory_kib: d.minimum_memory.as_kib() as u32,
        preferred_memory_kib: d.preferred_memory.as_kib() as u32,
        preferred_fan_in: d.preferred_fan_in.get(),
        preferred_output_length: d.preferred_output_length.as_bytes() as u32,
    };
    AntechStatus::Ok
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash(
    password: *const c_char,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if password.is_null() || out_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let bytes = CStr::from_ptr(password).to_bytes();
        match hash_with_config(bytes, &AntechConfig::default()) {
            Ok(h) => give_string(h, out_hash),
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_bytes(
    password: *const u8,
    password_len: size_t,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        if password.is_null() && password_len != 0 {
            return AntechStatus::InvalidInput;
        }
        let bytes = if password_len == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(password, password_len)
        };
        match hash_with_config(bytes, &AntechConfig::default()) {
            Ok(h) => give_string(h, out_hash),
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_with_config(
    password: *const c_char,
    config: *const AntechConfigC,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if password.is_null() || config.is_null() || out_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let cfg = match config_from_c(&*config) {
            Ok(c) => c,
            Err(s) => return s,
        };
        let bytes = CStr::from_ptr(password).to_bytes();
        match hash_with_config(bytes, &cfg) {
            Ok(h) => give_string(h, out_hash),
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_with_config_bytes(
    password: *const u8,
    password_len: size_t,
    config: *const AntechConfigC,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if config.is_null() || out_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        if password.is_null() && password_len != 0 {
            return AntechStatus::InvalidInput;
        }
        let cfg = match config_from_c(&*config) {
            Ok(c) => c,
            Err(s) => return s,
        };
        let bytes = if password_len == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(password, password_len)
        };
        match hash_with_config(bytes, &cfg) {
            Ok(h) => give_string(h, out_hash),
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

/// Deterministic hash for KATs: password + salt + config → encoded `$antech$v2$…`.
#[no_mangle]
pub unsafe extern "C" fn antech_hash_with_config_and_salt(
    password: *const u8,
    password_len: size_t,
    salt: *const u8,
    salt_len: size_t,
    config: *const AntechConfigC,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if config.is_null() || out_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        if (password.is_null() && password_len != 0) || (salt.is_null() && salt_len != 0) {
            return AntechStatus::InvalidInput;
        }
        let cfg = match config_from_c(&*config) {
            Ok(c) => c,
            Err(s) => return s,
        };
        let pw = if password_len == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(password, password_len)
        };
        let salt_b = if salt_len == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(salt, salt_len)
        };
        match hash_with_config_and_salt(pw, salt_b, &cfg) {
            Ok(h) => give_string(h, out_hash),
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn antech_verify(
    password: *const c_char,
    encoded_hash: *const c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if password.is_null() || encoded_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let pw = CStr::from_ptr(password).to_bytes();
        let hash = match CStr::from_ptr(encoded_hash).to_str() {
            Ok(s) => s,
            Err(_) => return AntechStatus::InvalidInput,
        };
        match verify(pw, hash) {
            Ok(true) => AntechStatus::Ok,
            Ok(false) => AntechStatus::VerificationFailed,
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn antech_verify_bytes(
    password: *const u8,
    password_len: size_t,
    encoded_hash: *const c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if encoded_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        if password.is_null() && password_len != 0 {
            return AntechStatus::InvalidInput;
        }
        let pw = if password_len == 0 {
            &[][..]
        } else {
            slice::from_raw_parts(password, password_len)
        };
        let hash = match CStr::from_ptr(encoded_hash).to_str() {
            Ok(s) => s,
            Err(_) => return AntechStatus::InvalidInput,
        };
        match verify(pw, hash) {
            Ok(true) => AntechStatus::Ok,
            Ok(false) => AntechStatus::VerificationFailed,
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn antech_needs_rehash(
    encoded_hash: *const c_char,
    out_needs_rehash: *mut c_int,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if encoded_hash.is_null() || out_needs_rehash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let hash = match CStr::from_ptr(encoded_hash).to_str() {
            Ok(s) => s,
            Err(_) => return AntechStatus::InvalidInput,
        };
        match needs_rehash_with_policy(hash, &RehashPolicy::default()) {
            Ok(needed) => {
                *out_needs_rehash = if needed { 1 } else { 0 };
                AntechStatus::Ok
            }
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn antech_needs_rehash_with_policy(
    encoded_hash: *const c_char,
    policy: *const AntechRehashPolicyC,
    out_needs_rehash: *mut c_int,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if encoded_hash.is_null() || policy.is_null() || out_needs_rehash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let hash = match CStr::from_ptr(encoded_hash).to_str() {
            Ok(s) => s,
            Err(_) => return AntechStatus::InvalidInput,
        };
        let pol = policy_from_c(&*policy);
        match needs_rehash_with_policy(hash, &pol) {
            Ok(needed) => {
                *out_needs_rehash = if needed { 1 } else { 0 };
                AntechStatus::Ok
            }
            Err(e) => map_err(e),
        }
    })) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

#[no_mangle]
pub unsafe extern "C" fn antech_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[cfg(test)]
mod ffi_tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn null_pointers_rejected() {
        unsafe {
            assert_eq!(
                antech_hash(std::ptr::null(), std::ptr::null_mut()),
                AntechStatus::InvalidInput
            );
            assert_eq!(
                antech_verify(std::ptr::null(), std::ptr::null()),
                AntechStatus::InvalidInput
            );
        }
    }

    #[test]
    fn binary_password_roundtrip() {
        let c_pw = CString::new([0xFFu8, 0x42, 0xAB]).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        unsafe {
            assert_eq!(antech_hash(c_pw.as_ptr(), &mut out), AntechStatus::Ok);
            assert!(!out.is_null());
            let hash_cstr = CStr::from_ptr(out);
            assert_eq!(
                antech_verify(c_pw.as_ptr(), hash_cstr.as_ptr()),
                AntechStatus::Ok
            );
            antech_free(out);
        }
    }

    #[test]
    fn config_and_salt_kat_shape() {
        let cfg = AntechConfigC {
            memory_kib: 1024,
            salt_length: 16,
            block_size: 32,
            fan_in: 2,
            graph: ANTECH_GRAPH_COMBINED_FRONTIER,
            output_length: 32,
        };
        let pw = b"password";
        let salt = b"salt_16_bytes!!!";
        let mut out: *mut c_char = std::ptr::null_mut();
        unsafe {
            assert_eq!(
                antech_hash_with_config_and_salt(
                    pw.as_ptr(),
                    pw.len(),
                    salt.as_ptr(),
                    salt.len(),
                    &cfg,
                    &mut out
                ),
                AntechStatus::Ok
            );
            let s = CStr::from_ptr(out).to_str().unwrap();
            assert!(s.starts_with("$antech$v2$"));
            assert_eq!(
                antech_verify_bytes(pw.as_ptr(), pw.len(), out),
                AntechStatus::Ok
            );
            antech_free(out);
        }
    }

    #[test]
    fn malformed_hash_returns_invalid_hash() {
        let pw = CString::new("pw").unwrap();
        let bad = CString::new("not_a_hash").unwrap();
        unsafe {
            assert_eq!(
                antech_verify(pw.as_ptr(), bad.as_ptr()),
                AntechStatus::InvalidHash
            );
        }
    }

    #[test]
    fn free_null_is_noop() {
        unsafe {
            antech_free(std::ptr::null_mut());
        }
    }
}
