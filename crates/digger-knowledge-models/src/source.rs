/// Knowledge source abstraction — generic security knowledge providers.
///
/// A KnowledgeSource represents any provider of structured security knowledge.
/// Implementations extract semantic knowledge from source-specific formats
/// and normalize it into canonical models before it enters the reasoning engine.
///
/// The reasoning engine never knows where knowledge originated.
/// All downstream systems consume identical normalized structures
/// regardless of the original source.
///
/// Source categories:
///   - Audit repositories (Pashov, Code4rena, Cantina, Sherlock, Immunefi)
///   - Exploit postmortems
///   - Protocol documentation and specifications
///   - ERC/EIP/SIP standards
///   - Formal verification specifications
///   - Academic research papers
///   - Security blogs and technical writeups
///   - Internal Digger findings
///   - Regression corpora
///   - Future sources that do not yet exist
use serde::{Deserialize, Serialize};

/// A knowledge source — a provider of structured security knowledge.
///
/// Implementations extract knowledge from source-specific formats and
/// normalize it into canonical semantic models. Every implementation
/// produces the same output type, enabling the reasoning engine to
/// consume unified knowledge regardless of source.
pub trait KnowledgeSource {
    /// Source identifier (e.g., "pashov/audits", "code4rena", "eip-20").
    fn source_id(&self) -> &str;

    /// Source kind — categorizes the type of knowledge provider.
    fn source_kind(&self) -> KnowledgeSourceKind;

    /// Human-readable description of this source.
    fn description(&self) -> &str;

    /// Supported input formats (file extensions, MIME types, or identifiers).
    fn supported_formats(&self) -> Vec<&str>;

    /// Extract normalized knowledge from a single input.
    ///
    /// The input may be a file, a URL response, a structured document,
    /// or any other content the source can process. The output is always
    /// a NormalizedKnowledge containing canonical semantic models.
    fn extract(
        &self,
        content: &str,
        identifier: &str,
    ) -> Result<NormalizedKnowledge, ExtractionError>;
}

/// Kind of knowledge source.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum KnowledgeSourceKind {
    /// Audit report repository (Pashov, Code4rena, Cantina, Sherlock, Immunefi).
    AuditRepository,
    /// Exploit postmortem or incident report.
    ExploitPostmortem,
    /// Protocol documentation or specification.
    ProtocolDocumentation,
    /// Token or contract standard (ERC, EIP, SIP).
    Standard,
    /// Formal verification specification or result.
    FormalVerification,
    /// Academic research paper or publication.
    AcademicResearch,
    /// Security blog post or technical writeup.
    TechnicalWriteup,
    /// Internal Digger analysis output.
    InternalAnalysis,
    /// Regression test corpus.
    RegressionCorpus,
    /// Other or unknown source type.
    Other,
}

impl std::fmt::Display for KnowledgeSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuditRepository => write!(f, "audit_repository"),
            Self::ExploitPostmortem => write!(f, "exploit_postmortem"),
            Self::ProtocolDocumentation => write!(f, "protocol_documentation"),
            Self::Standard => write!(f, "standard"),
            Self::FormalVerification => write!(f, "formal_verification"),
            Self::AcademicResearch => write!(f, "academic_research"),
            Self::TechnicalWriteup => write!(f, "technical_writeup"),
            Self::InternalAnalysis => write!(f, "internal_analysis"),
            Self::RegressionCorpus => write!(f, "regression_corpus"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Normalized knowledge — the canonical output of every knowledge source.
///
/// This is the only type that enters the reasoning engine from the
/// knowledge subsystem. All source-specific details are absorbed during
/// extraction. Downstream systems never see the original source format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizedKnowledge {
    /// Deterministic knowledge identifier (hash of source + content).
    pub knowledge_id: String,
    /// Source identifier (where this knowledge came from).
    pub source_id: String,
    /// Source kind.
    pub source_kind: KnowledgeSourceKind,
    /// Source format identifier (filename, URL, DOI, etc.).
    pub source_identifier: String,
    /// Protocol or subject this knowledge relates to.
    pub subject: String,
    /// Subject category.
    pub subject_category: String,
    /// Extracted findings normalized to canonical taxonomy.
    pub findings: Vec<super::finding::NormalizedFinding>,
    /// Knowledge evidence items for the reasoning engine.
    pub evidence: Vec<super::knowledge_evidence::KnowledgeEvidence>,
    /// Security invariants described or violated.
    pub invariants: Vec<SecurityInvariant>,
    /// Architectural patterns described.
    pub architectural_patterns: Vec<ArchitecturalPattern>,
    /// Mitigation patterns described.
    pub mitigation_patterns: Vec<super::finding::MitigationPattern>,
    /// References to related knowledge.
    pub references: Vec<KnowledgeReference>,
    /// Key claims or assertions extracted.
    pub claims: Vec<SecurityClaim>,
    /// Raw content sections (section_name -> content).
    pub raw_sections: std::collections::BTreeMap<String, String>,
}

/// A security invariant described in a knowledge source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityInvariant {
    /// Invariant identifier.
    pub invariant_id: String,
    /// Invariant description.
    pub description: String,
    /// Invariant kind (conservation, solvency, authority, etc.).
    pub kind: String,
    /// State variables or properties involved.
    pub properties: Vec<String>,
    /// Whether this invariant was violated in the source.
    pub is_violated: bool,
    /// Context (protocol, contract, function).
    pub context: String,
}

/// An architectural pattern described in a knowledge source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArchitecturalPattern {
    /// Pattern identifier.
    pub pattern_id: String,
    /// Pattern name.
    pub name: String,
    /// Pattern description.
    pub description: String,
    /// Pattern category (proxy, vault, AMM, lending, etc.).
    pub category: String,
    /// Known vulnerability classes for this pattern.
    pub known_vulnerabilities: Vec<String>,
    /// Security properties this pattern should maintain.
    pub security_properties: Vec<String>,
}

/// A reference to related knowledge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeReference {
    /// Reference identifier (URL, DOI, finding ID, etc.).
    pub reference_id: String,
    /// Reference kind.
    pub kind: ReferenceKind,
    /// Human-readable description.
    pub description: String,
}

/// Kind of knowledge reference.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReferenceKind {
    /// Link to another audit report.
    AuditReport,
    /// Link to an exploit transaction.
    ExploitTransaction,
    /// Link to a protocol's source code.
    SourceCode,
    /// Link to documentation.
    Documentation,
    /// Link to a standard (ERC, EIP, SIP).
    Standard,
    /// Link to academic paper.
    AcademicPaper,
    /// Link to a blog post or writeup.
    BlogPost,
    /// Link to a GitHub issue or PR.
    GitHubReference,
    /// Other reference.
    Other,
}

impl std::fmt::Display for ReferenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuditReport => write!(f, "audit_report"),
            Self::ExploitTransaction => write!(f, "exploit_transaction"),
            Self::SourceCode => write!(f, "source_code"),
            Self::Documentation => write!(f, "documentation"),
            Self::Standard => write!(f, "standard"),
            Self::AcademicPaper => write!(f, "academic_paper"),
            Self::BlogPost => write!(f, "blog_post"),
            Self::GitHubReference => write!(f, "github_reference"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// A security claim or assertion extracted from a knowledge source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityClaim {
    /// Claim identifier.
    pub claim_id: String,
    /// The claim text.
    pub claim: String,
    /// Claim kind.
    pub kind: ClaimKind,
    /// Confidence in this claim (structural, not heuristic).
    pub confidence: ClaimConfidence,
    /// Evidence supporting this claim.
    pub evidence: Vec<String>,
    /// Context (where this claim was made).
    pub context: String,
}

/// Kind of security claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimKind {
    /// A vulnerability exists in this code.
    VulnerabilityExists,
    /// This code is safe against a specific attack class.
    SafeAgainstAttack,
    /// This invariant must hold for correctness.
    InvariantRequired,
    /// This pattern is secure when used correctly.
    PatternSecureWhen,
    /// This mitigation is effective.
    MitigationEffective,
    /// This assumption is required for security.
    AssumptionRequired,
    /// Other claim.
    Other,
}

impl std::fmt::Display for ClaimKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VulnerabilityExists => write!(f, "vulnerability_exists"),
            Self::SafeAgainstAttack => write!(f, "safe_against_attack"),
            Self::InvariantRequired => write!(f, "invariant_required"),
            Self::PatternSecureWhen => write!(f, "pattern_secure_when"),
            Self::MitigationEffective => write!(f, "mitigation_effective"),
            Self::AssumptionRequired => write!(f, "assumption_required"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Confidence in a security claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimConfidence {
    /// Claim is proven (formal verification, mathematical proof).
    Proven,
    /// Claim is verified (tested, audited, confirmed).
    Verified,
    /// Claim is asserted (stated but not independently verified).
    Asserted,
    /// Claim is speculative (hypothesis, conjecture).
    Speculative,
}

impl std::fmt::Display for ClaimConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proven => write!(f, "proven"),
            Self::Verified => write!(f, "verified"),
            Self::Asserted => write!(f, "asserted"),
            Self::Speculative => write!(f, "speculative"),
        }
    }
}

/// Extraction error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, thiserror::Error)]
#[error("Extraction error in {source_identifier}: {message}")]
pub struct ExtractionError {
    pub message: String,
    pub source_identifier: String,
    pub line: Option<usize>,
}

/// Source metadata — records where knowledge came from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceMetadata {
    /// Source identifier.
    pub source_id: String,
    /// Source kind.
    pub source_kind: KnowledgeSourceKind,
    /// Source format identifier.
    pub source_identifier: String,
    /// Extraction hash (deterministic, not wall clock).
    pub extraction_hash: String,
    /// Source format version.
    pub format_version: String,
}
