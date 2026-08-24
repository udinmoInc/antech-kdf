//! Algorithm enum and version identifiers.

use std::fmt;

/// Strongly-typed identifier for supported password KDF algorithm variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Algorithm {
    /// Standard symmetric Antech KDF Candidate-004 construction.
    #[default]
    Antech,

    /// Variant K1: Parallelism Reduction (Candidate dynamic S-box feedback).
    K1,

    /// Variant K2: Quad-Node TMTO Graph.
    K2,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Antech => "antech",
            Algorithm::K1 => "k1",
            Algorithm::K2 => "k2",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "antech" | "cand-004" | "candidate-004" => Some(Algorithm::Antech),
            "k1" | "variant-k1" => Some(Algorithm::K1),
            "k2" | "variant-k2" => Some(Algorithm::K2),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
