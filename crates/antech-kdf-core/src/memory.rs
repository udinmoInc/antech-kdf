//! Memory buffer management and zeroization.
//!
//! # Memory Security & Rust Guarantees
//!
//! - Secret key buffers and intermediate state arrays are wrapped in [`zeroize::Zeroizing`]
//!   or zeroized upon drop to overwrite memory with zeroes.
//! - **Limitations**: Rust standard library allocators do not guarantee protection against OS
//!   swapping (paging to disk), core dumps, or compiler optimizations re-ordering un-pinned buffers.
//!   Users in extreme threat environments should ensure OS-level memory locking (mlock) is enabled.

use zeroize::Zeroize;

/// Secure memory buffer container that zeroizes memory on drop.
pub struct ProtectedBuffer {
    data: Vec<u8>,
}

impl ProtectedBuffer {
    /// Creates a new zero-initialized buffer of specified size.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    /// Access underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Access underlying mutable byte slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
