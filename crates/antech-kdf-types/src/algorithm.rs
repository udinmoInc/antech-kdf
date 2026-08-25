//! Algorithm and graph identifiers for stored hashes.

use std::fmt;

/// Supported production algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Algorithm {
    /// Canonical Antech compute-memory construction.
    #[default]
    Antech,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Antech => "antech",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "antech" => Some(Algorithm::Antech),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Encoding version of a stored hash. Older research encodings are not reinterpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
pub enum AlgorithmVersion {
    /// Canonical compute-memory encoding (structural memory/graph parameters).
    #[default]
    V2 = 2,
}

impl AlgorithmVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlgorithmVersion::V2 => "v2",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "v2" | "2" => Some(AlgorithmVersion::V2),
            _ => None,
        }
    }
}

impl fmt::Display for AlgorithmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Dependency-graph family used by the compute-memory engine.
///
/// Production hashing defaults to [`GraphKind::CombinedFrontier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GraphKind {
    ReducedCriticalPath,
    CacheLocality,
    #[default]
    CombinedFrontier,
}

impl GraphKind {
    /// Stable identifier mixed into the seed and stored in encoded hashes.
    pub fn tag(self) -> u32 {
        match self {
            GraphKind::ReducedCriticalPath => 1,
            GraphKind::CacheLocality => 2,
            GraphKind::CombinedFrontier => 3,
        }
    }

    pub fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(GraphKind::ReducedCriticalPath),
            2 => Some(GraphKind::CacheLocality),
            3 => Some(GraphKind::CombinedFrontier),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            GraphKind::ReducedCriticalPath => "reduced-critical-path",
            GraphKind::CacheLocality => "cache-locality",
            GraphKind::CombinedFrontier => "combined-frontier",
        }
    }
}

impl fmt::Display for GraphKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
