//! Core traits for KDF engine abstraction and resource scheduling.

use antech_kdf_types::{Algorithm, AntechConfig, KdfError};

/// Trait implemented by cryptographic key derivation engines.
pub trait KdfEngine: Send + Sync {
    /// Return algorithm variant identifier.
    fn algorithm(&self) -> Algorithm;

    /// Execute password derivation given input password, salt bytes, and parameter configuration.
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        config: &AntechConfig,
    ) -> Result<Vec<u8>, KdfError>;
}

/// Resource permit handle returned by `ResourceScheduler`.
#[derive(Debug)]
pub struct ResourcePermit {
    pub memory_kib: usize,
}

/// Trait implemented by server memory and concurrency schedulers.
pub trait ResourceScheduler: Send + Sync {
    /// Attempt to acquire memory permit for a derivation request.
    fn acquire(&self, memory_kib: usize) -> Result<ResourcePermit, KdfError>;

    /// Release acquired memory permit.
    fn release(&self, permit: ResourcePermit);
}
