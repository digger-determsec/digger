/// Supported source language for parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Language {
    Solidity,
    Rust,
    Anchor,
    Unknown,
}

/// Visibility level of an executable unit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Visibility {
    Public,
    Private,
    Internal,
    External,
}

/// Whether a storage unit can be modified after initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutability {
    Immutable,
    Mutable,
}

/// The type of semantic relationship between IR elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeType {
    Call,
    State,
    Authority,
    External,
}

/// Canonical severity level for findings and hypotheses.
///
/// Used across all analysis crates. Ordering: Info < Low < Medium < High < Critical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    /// Informational — structural observation.
    Info,
    /// Low — minor structural concern.
    Low,
    /// Medium — notable structural pattern.
    Medium,
    /// High — significant structural pattern.
    High,
    /// Critical — severe structural pattern.
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Solidity => write!(f, "Solidity"),
            Self::Rust => write!(f, "Rust"),
            Self::Anchor => write!(f, "Anchor"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}
