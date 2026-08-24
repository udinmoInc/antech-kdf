//! Password hash encoding and decoding library for Antech KDF.

pub mod encoder;
pub mod error;
pub mod parser;

pub use encoder::encode_hash;
pub use error::FormatError;
pub use parser::parse_hash;
