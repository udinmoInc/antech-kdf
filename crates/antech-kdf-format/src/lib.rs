//! Hash format encoding and parsing crate.

pub mod encoder;
pub mod parser;

pub use encoder::encode_hash;
pub use parser::parse_hash;
