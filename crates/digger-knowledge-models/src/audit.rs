/// Audit report types — the top-level extraction unit.
use serde::{Deserialize, Serialize};

/// An extracted audit report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditReport {
    /// Deterministic report identifier (hash of filename + content).
    pub report_id: String,
    /// Protocol name.
    pub protocol_name: String,
    /// Protocol category.
    pub protocol_category: ProtocolCategory,
    /// Auditor name.
    pub auditor: String,
    /// Individual reviewers (if available).
    pub reviewers: Vec<String>,
    /// Audit date (ISO format if available).
    pub audit_date: Option<String>,
    /// Source repository.
    pub source_repo: String,
    /// Source file path.
    pub source_path: String,
    /// Review commit hash.
    pub commit_hash: Option<String>,
    /// Contracts/files in scope.
    pub scope: Vec<ScopedFile>,
    /// Extracted findings.
    pub findings: Vec<super::finding::ExtractedFinding>,
    /// Privileged roles identified.
    pub privileged_roles: Vec<PrivilegedRole>,
    /// Centralization notes.
    pub centralization_notes: Vec<String>,
    /// Raw section content (section_name -> content).
    pub raw_sections: std::collections::BTreeMap<String, String>,
}

/// Protocol category — deterministic classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolCategory {
    Lending,
    Stablecoin,
    DEX,
    Yield,
    Bridge,
    Governance,
    Infrastructure,
    NFT,
    Gaming,
    RWA,
    Perps,
    Options,
    Insurance,
    Token,
    Vault,
    Unknown,
}

impl std::fmt::Display for ProtocolCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lending => write!(f, "lending"),
            Self::Stablecoin => write!(f, "stablecoin"),
            Self::DEX => write!(f, "dex"),
            Self::Yield => write!(f, "yield"),
            Self::Bridge => write!(f, "bridge"),
            Self::Governance => write!(f, "governance"),
            Self::Infrastructure => write!(f, "infrastructure"),
            Self::NFT => write!(f, "nft"),
            Self::Gaming => write!(f, "gaming"),
            Self::RWA => write!(f, "rwa"),
            Self::Perps => write!(f, "perps"),
            Self::Options => write!(f, "options"),
            Self::Insurance => write!(f, "insurance"),
            Self::Token => write!(f, "token"),
            Self::Vault => write!(f, "vault"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A file in the audit scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopedFile {
    pub path: String,
    pub language: String,
}

/// A privileged role identified in the audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrivilegedRole {
    pub role_name: String,
    pub description: String,
    pub functions: Vec<String>,
    pub risk_level: String,
}
