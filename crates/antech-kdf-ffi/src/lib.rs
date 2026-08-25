//! C ABI Bindings for Antech KDF.
//!
//! Exposes a minimal, thread-safe C ABI interface for FFI binding layers.
//!
//! # Safety & Ownership Guarantees
//! - All pointer inputs must be non-null and point to valid null-terminated strings.
//! - Password bytes may be arbitrary (including non-UTF-8); embedded NUL terminates the password.
//! - Encoded hash strings must be valid UTF-8.
//! - Strings returned by `antech_hash` are heap-allocated by Rust and MUST be freed by calling `antech_free`.
//! - Thread safety: All functions are thread-safe and stateless.
//! - Panics are caught at the FFI boundary and reported as `InternalError`.

use libc::{c_char, c_int};
use std::ffi::{CStr, CString};

/// Status codes returned by C ABI functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntechStatus {
    /// Operation completed successfully
    Ok = 0,
    /// Password verification failed (mismatch)
    VerificationFailed = 1,
    /// Invalid input pointer or encoding
    InvalidInput = -1,
    /// Hash string parsing or parameter failure
    InvalidHash = -2,
    /// Internal engine error
    InternalError = -3,
}

/// Hashes a password string into a heap-allocated self-describing hash string.
///
/// # Safety
/// `password` must be a valid null-terminated C string.
/// `out_hash` must be a valid pointer to receive a `*mut c_char`.
/// Caller MUST release `*out_hash` using `antech_free`.
#[no_mangle]
pub unsafe extern "C" fn antech_hash(
    password: *const c_char,
    out_hash: *mut *mut c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hash_impl(password, out_hash)
    })) {
        Ok(status) => status,
        Err(_) => AntechStatus::InternalError,
    }
}

unsafe fn hash_impl(password: *const c_char, out_hash: *mut *mut c_char) -> AntechStatus {
    if password.is_null() || out_hash.is_null() {
        return AntechStatus::InvalidInput;
    }

    let c_pass = CStr::from_ptr(password).to_bytes();

    match antech_kdf::hash(c_pass) {
        Ok(hash_str) => match CString::new(hash_str) {
            Ok(c_str) => {
                *out_hash = c_str.into_raw();
                AntechStatus::Ok
            }
            Err(_) => AntechStatus::InternalError,
        },
        Err(_) => AntechStatus::InternalError,
    }
}

/// Verifies a password against a stored encoded hash string.
///
/// Returns `AntechStatus::Ok` on match, `AntechStatus::VerificationFailed` on mismatch, or error code.
///
/// # Safety
/// `password` and `encoded_hash` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn antech_verify(
    password: *const c_char,
    encoded_hash: *const c_char,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_impl(password, encoded_hash)
    })) {
        Ok(status) => status,
        Err(_) => AntechStatus::InternalError,
    }
}

unsafe fn verify_impl(password: *const c_char, encoded_hash: *const c_char) -> AntechStatus {
    if password.is_null() || encoded_hash.is_null() {
        return AntechStatus::InvalidInput;
    }

    let c_pass = CStr::from_ptr(password).to_bytes();

    let c_hash = match CStr::from_ptr(encoded_hash).to_str() {
        Ok(s) => s,
        Err(_) => return AntechStatus::InvalidInput,
    };

    match antech_kdf::verify(c_pass, c_hash) {
        Ok(true) => AntechStatus::Ok,
        Ok(false) => AntechStatus::VerificationFailed,
        Err(_) => AntechStatus::InvalidHash,
    }
}

/// Checks whether a stored hash string requires rehashing.
///
/// Out parameter `out_needs_rehash` receives `1` if rehash is needed, `0` otherwise.
///
/// # Safety
/// `encoded_hash` must be a valid null-terminated C string. `out_needs_rehash` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn antech_needs_rehash(
    encoded_hash: *const c_char,
    out_needs_rehash: *mut c_int,
) -> AntechStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        needs_rehash_impl(encoded_hash, out_needs_rehash)
    })) {
        Ok(status) => status,
        Err(_) => AntechStatus::InternalError,
    }
}

unsafe fn needs_rehash_impl(
    encoded_hash: *const c_char,
    out_needs_rehash: *mut c_int,
) -> AntechStatus {
    if encoded_hash.is_null() || out_needs_rehash.is_null() {
        return AntechStatus::InvalidInput;
    }

    let c_hash = match CStr::from_ptr(encoded_hash).to_str() {
        Ok(s) => s,
        Err(_) => return AntechStatus::InvalidInput,
    };

    match antech_kdf::needs_rehash(c_hash) {
        Ok(needed) => {
            *out_needs_rehash = if needed { 1 } else { 0 };
            AntechStatus::Ok
        }
        Err(_) => AntechStatus::InvalidHash,
    }
}

/// Frees a hash string previously allocated by `antech_hash`.
///
/// # Safety
/// `ptr` must be a pointer allocated by `antech_hash` or NULL.
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
        // C strings cannot contain interior NUL; password is bytes before first NUL.
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
    fn embedded_nul_truncates_password() {
        // CString cannot hold interior NUL; construct a C string manually.
        let pw = vec![0xFFu8, 0x00, 0x42, 0];
        let truncated = CString::new([0xFFu8]).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        unsafe {
            let c_pw = pw.as_ptr() as *const c_char;
            assert_eq!(antech_hash(c_pw, &mut out), AntechStatus::Ok);
            assert_eq!(
                antech_verify(truncated.as_ptr(), CStr::from_ptr(out).as_ptr()),
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
