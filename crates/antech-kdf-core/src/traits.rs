//! Traits for the KDF engine and host resource admission.

use antech_kdf_types::{Algorithm, AntechConfig, KdfError};

pub trait KdfEngine: Send + Sync {
    fn algorithm(&self) -> Algorithm;

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        config: &AntechConfig,
    ) -> Result<Vec<u8>, KdfError>;
}

#[derive(Debug)]
pub struct ResourcePermit {
    pub memory_kib: usize,
}

/// Host memory / concurrency admission (separate from KDF parameters).
pub trait ResourceScheduler: Send + Sync {
    fn acquire(&self, memory_kib: usize) -> Result<ResourcePermit, KdfError>;
    fn release(&self, permit: ResourcePermit);
}
