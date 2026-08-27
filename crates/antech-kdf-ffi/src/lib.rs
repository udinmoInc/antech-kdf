//! C ABI for Antech KDF — thin FFI over the canonical Rust implementation.
//!
//! Optional secret / associated-data pointer rules, ownership, and status codes
//! are documented in `bindings/c/antech_kdf.h`. This crate maps those ABI
//! conventions onto [`antech_kdf`] without reimplementing crypto or format logic.
//!
//! # Safety
//! All `unsafe extern "C"` entry points require non-null pointers where the header
//! documents them, valid UTF-8 for encoded hashes, and readable password/salt
//! buffers for `len` bytes for the duration of the call.

#![allow(clippy::missing_safety_doc)]

use libc::{c_char, c_int, size_t};
use std::ffi::{CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe, UnwindSafe};
use std::slice;

use antech_kdf::{
    hash_with_config, hash_with_config_and_salt, hash_with_inputs, hash_with_inputs_and_salt,
    needs_rehash_with_policy, verify, verify_with_inputs, AntechConfig, DeriveInputs, FanIn,
    GraphKind, MemorySize, OutputLength, RehashPolicy, SecretBytes,
};

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

pub const ANTECH_GRAPH_REDUCED_CRITICAL_PATH: u32 = 1;
pub const ANTECH_GRAPH_CACHE_LOCALITY: u32 = 2;
pub const ANTECH_GRAPH_COMBINED_FRONTIER: u32 = 3;

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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AntechRehashPolicyC {
    pub minimum_memory_kib: u32,
    pub preferred_memory_kib: u32,
    pub preferred_fan_in: u32,
    pub preferred_output_length: u32,
    pub preferred_secret_required: u32,
    pub preferred_associated_data: u32,
}

fn map_err(err: antech_kdf::Error) -> AntechStatus {
    match err {
        antech_kdf::Error::Config(_) => AntechStatus::InvalidConfig,
        antech_kdf::Error::Encoding(_) => AntechStatus::InvalidHash,
        antech_kdf::Error::MissingSecret
        | antech_kdf::Error::MissingAssociatedData
        | antech_kdf::Error::AssociatedDataLengthMismatch { .. } => AntechStatus::InvalidInput,
        antech_kdf::Error::Derivation(_) | antech_kdf::Error::ResourceExhausted(_) => {
            AntechStatus::InternalError
        }
    }
}

fn ffi_catch(f: impl FnOnce() -> AntechStatus + UnwindSafe) -> AntechStatus {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(_) => AntechStatus::InternalError,
    }
}

fn config_from_c(c: &AntechConfigC) -> Result<AntechConfig, AntechStatus> {
    let graph = GraphKind::from_tag(c.graph).ok_or(AntechStatus::InvalidConfig)?;
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
        preferred_secret_required: p.preferred_secret_required != 0,
        preferred_associated_data: p.preferred_associated_data != 0,
    }
}

/// NULL+0 = absent; non-null = present (len may be 0).
fn optional_slice<'a>(ptr: *const u8, len: size_t) -> Result<Option<&'a [u8]>, AntechStatus> {
    if ptr.is_null() {
        if len != 0 {
            return Err(AntechStatus::InvalidInput);
        }
        Ok(None)
    } else if len == 0 {
        Ok(Some(&[]))
    } else {
        Ok(Some(unsafe { slice::from_raw_parts(ptr, len) }))
    }
}

fn required_buf<'a>(ptr: *const u8, len: size_t) -> Result<&'a [u8], AntechStatus> {
    optional_slice(ptr, len).map(|o| o.unwrap_or(&[]))
}

fn read_encoded_hash<'a>(ptr: *const c_char) -> Result<&'a str, AntechStatus> {
    if ptr.is_null() {
        return Err(AntechStatus::InvalidInput);
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| AntechStatus::InvalidInput)
}

fn derive_inputs_from_c(
    secret: *const u8,
    secret_len: size_t,
    associated_data: *const u8,
    associated_data_len: size_t,
) -> Result<DeriveInputs, AntechStatus> {
    let mut inputs = DeriveInputs::default();
    if let Some(s) = optional_slice(secret, secret_len)? {
        inputs.secret = Some(SecretBytes::new(s).map_err(|_| AntechStatus::InvalidConfig)?);
    }
    if let Some(ad) = optional_slice(associated_data, associated_data_len)? {
        inputs = inputs
            .with_associated_data(ad)
            .map_err(|_| AntechStatus::InvalidConfig)?;
    }
    Ok(inputs)
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

fn status_from_verify(r: Result<bool, antech_kdf::Error>) -> AntechStatus {
    match r {
        Ok(true) => AntechStatus::Ok,
        Ok(false) => AntechStatus::VerificationFailed,
        Err(e) => map_err(e),
    }
}

fn hash_result(r: Result<String, antech_kdf::Error>, out: *mut *mut c_char) -> AntechStatus {
    match r {
        Ok(h) => give_string(h, out),
        Err(e) => map_err(e),
    }
}

fn require_cfg_out(
    config: *const AntechConfigC,
    out_hash: *mut *mut c_char,
) -> Result<AntechConfig, AntechStatus> {
    if config.is_null() || out_hash.is_null() {
        return Err(AntechStatus::InvalidInput);
    }
    config_from_c(unsafe { &*config })
}

fn write_needs_rehash(hash: &str, policy: &RehashPolicy, out: *mut c_int) -> AntechStatus {
    match needs_rehash_with_policy(hash, policy) {
        Ok(needed) => {
            unsafe {
                *out = i32::from(needed);
            }
            AntechStatus::Ok
        }
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub extern "C" fn antech_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

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
        preferred_secret_required: u32::from(d.preferred_secret_required),
        preferred_associated_data: u32::from(d.preferred_associated_data),
    };
    AntechStatus::Ok
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash(
    password: *const c_char,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    ffi_catch(|| {
        if password.is_null() || out_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let bytes = CStr::from_ptr(password).to_bytes();
        hash_result(hash_with_config(bytes, &AntechConfig::default()), out_hash)
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_bytes(
    password: *const u8,
    password_len: size_t,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    ffi_catch(|| {
        if out_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let pw = match required_buf(password, password_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        hash_result(hash_with_config(pw, &AntechConfig::default()), out_hash)
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_with_config(
    password: *const c_char,
    config: *const AntechConfigC,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    ffi_catch(|| {
        if password.is_null() || config.is_null() || out_hash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let cfg = match config_from_c(&*config) {
            Ok(c) => c,
            Err(s) => return s,
        };
        let bytes = CStr::from_ptr(password).to_bytes();
        hash_result(hash_with_config(bytes, &cfg), out_hash)
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_with_config_bytes(
    password: *const u8,
    password_len: size_t,
    config: *const AntechConfigC,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    ffi_catch(|| {
        let cfg = match require_cfg_out(config, out_hash) {
            Ok(c) => c,
            Err(s) => return s,
        };
        let pw = match required_buf(password, password_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        hash_result(hash_with_config(pw, &cfg), out_hash)
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_with_config_and_salt(
    password: *const u8,
    password_len: size_t,
    salt: *const u8,
    salt_len: size_t,
    config: *const AntechConfigC,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    ffi_catch(|| {
        let cfg = match require_cfg_out(config, out_hash) {
            Ok(c) => c,
            Err(s) => return s,
        };
        let pw = match required_buf(password, password_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        let salt_b = match required_buf(salt, salt_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        hash_result(hash_with_config_and_salt(pw, salt_b, &cfg), out_hash)
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_with_inputs_bytes(
    password: *const u8,
    password_len: size_t,
    config: *const AntechConfigC,
    secret: *const u8,
    secret_len: size_t,
    associated_data: *const u8,
    associated_data_len: size_t,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    ffi_catch(|| {
        let cfg = match require_cfg_out(config, out_hash) {
            Ok(c) => c,
            Err(s) => return s,
        };
        let inputs =
            match derive_inputs_from_c(secret, secret_len, associated_data, associated_data_len) {
                Ok(i) => i,
                Err(s) => return s,
            };
        let pw = match required_buf(password, password_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        hash_result(hash_with_inputs(pw, &cfg, &inputs), out_hash)
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_hash_with_inputs_and_salt(
    password: *const u8,
    password_len: size_t,
    salt: *const u8,
    salt_len: size_t,
    config: *const AntechConfigC,
    secret: *const u8,
    secret_len: size_t,
    associated_data: *const u8,
    associated_data_len: size_t,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    ffi_catch(|| {
        let cfg = match require_cfg_out(config, out_hash) {
            Ok(c) => c,
            Err(s) => return s,
        };
        let inputs =
            match derive_inputs_from_c(secret, secret_len, associated_data, associated_data_len) {
                Ok(i) => i,
                Err(s) => return s,
            };
        let pw = match required_buf(password, password_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        let salt_b = match required_buf(salt, salt_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        hash_result(
            hash_with_inputs_and_salt(pw, salt_b, &cfg, &inputs),
            out_hash,
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_verify(
    password: *const c_char,
    encoded_hash: *const c_char,
) -> AntechStatus {
    ffi_catch(|| {
        if password.is_null() {
            return AntechStatus::InvalidInput;
        }
        let hash = match read_encoded_hash(encoded_hash) {
            Ok(s) => s,
            Err(s) => return s,
        };
        let pw = CStr::from_ptr(password).to_bytes();
        status_from_verify(verify(pw, hash))
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_verify_bytes(
    password: *const u8,
    password_len: size_t,
    encoded_hash: *const c_char,
) -> AntechStatus {
    ffi_catch(|| {
        let hash = match read_encoded_hash(encoded_hash) {
            Ok(s) => s,
            Err(s) => return s,
        };
        let pw = match required_buf(password, password_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        status_from_verify(verify(pw, hash))
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_verify_with_inputs_bytes(
    password: *const u8,
    password_len: size_t,
    encoded_hash: *const c_char,
    secret: *const u8,
    secret_len: size_t,
    associated_data: *const u8,
    associated_data_len: size_t,
) -> AntechStatus {
    ffi_catch(|| {
        let hash = match read_encoded_hash(encoded_hash) {
            Ok(s) => s,
            Err(s) => return s,
        };
        let inputs =
            match derive_inputs_from_c(secret, secret_len, associated_data, associated_data_len) {
                Ok(i) => i,
                Err(s) => return s,
            };
        let pw = match required_buf(password, password_len) {
            Ok(b) => b,
            Err(s) => return s,
        };
        status_from_verify(verify_with_inputs(pw, hash, &inputs))
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_needs_rehash(
    encoded_hash: *const c_char,
    out_needs_rehash: *mut c_int,
) -> AntechStatus {
    ffi_catch(|| {
        if out_needs_rehash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let hash = match read_encoded_hash(encoded_hash) {
            Ok(s) => s,
            Err(s) => return s,
        };
        write_needs_rehash(hash, &RehashPolicy::default(), out_needs_rehash)
    })
}

#[no_mangle]
pub unsafe extern "C" fn antech_needs_rehash_with_policy(
    encoded_hash: *const c_char,
    policy: *const AntechRehashPolicyC,
    out_needs_rehash: *mut c_int,
) -> AntechStatus {
    ffi_catch(|| {
        if policy.is_null() || out_needs_rehash.is_null() {
            return AntechStatus::InvalidInput;
        }
        let hash = match read_encoded_hash(encoded_hash) {
            Ok(s) => s,
            Err(s) => return s,
        };
        write_needs_rehash(hash, &policy_from_c(&*policy), out_needs_rehash)
    })
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
    fn secret_and_ad_roundtrip_via_ffi() {
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
        let secret = b"app-held-secret";
        let ad = b"tenant-1";
        let mut out: *mut c_char = std::ptr::null_mut();
        unsafe {
            assert_eq!(
                antech_hash_with_inputs_and_salt(
                    pw.as_ptr(),
                    pw.len(),
                    salt.as_ptr(),
                    salt.len(),
                    &cfg,
                    secret.as_ptr(),
                    secret.len(),
                    ad.as_ptr(),
                    ad.len(),
                    &mut out
                ),
                AntechStatus::Ok
            );
            let encoded = CStr::from_ptr(out).to_str().unwrap();
            assert!(encoded.contains(",sk=1"));
            assert!(encoded.contains(",adl=8"));
            assert!(!encoded.contains("app-held-secret"));
            assert_eq!(
                antech_verify_bytes(pw.as_ptr(), pw.len(), out),
                AntechStatus::InvalidInput
            );
            assert_eq!(
                antech_verify_with_inputs_bytes(
                    pw.as_ptr(),
                    pw.len(),
                    out,
                    secret.as_ptr(),
                    secret.len(),
                    ad.as_ptr(),
                    ad.len()
                ),
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
