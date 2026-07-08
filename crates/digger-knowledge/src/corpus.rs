/// Corpus Expansion Framework — accelerates knowledge growth.
///
/// Reusable deterministic ingestion pipelines for batch processing.
/// Every source normalizes into canonical semantic models through
/// the existing KnowledgeSource abstraction.
///
/// The reasoning engine never knows the original source.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// Source Tier Prioritization
// ═══════════════════════════════════════════════════════════════

/// Source tier for deterministic prioritization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceTier {
    /// Highest signal: Pashov, Trail of Bits, OpenZeppelin, Cantina, Code4rena, Sherlock.
    Tier1,
    /// High value: Immunefi disclosures, exploit postmortems, protocol documentation.
    Tier2,
    /// Standards: ERC/EIP/SIP, formal specifications, academic research.
    Tier3,
    /// Enrichment: security blogs, conference talks, community writeups.
    Tier4,
}

impl std::fmt::Display for SourceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tier1 => write!(f, "tier1"),
            Self::Tier2 => write!(f, "tier2"),
            Self::Tier3 => write!(f, "tier3"),
            Self::Tier4 => write!(f, "tier4"),
        }
    }
}

/// A registered knowledge source with tier and metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegisteredSource {
    /// Source identifier.
    pub source_id: String,
    /// Source kind.
    pub source_kind: KnowledgeSourceKind,
    /// Source tier.
    pub tier: SourceTier,
    /// Human-readable description.
    pub description: String,
    /// Supported formats.
    pub formats: Vec<String>,
    /// Number of items ingested.
    pub ingested_count: usize,
    /// Last ingestion hash (deterministic).
    pub last_ingestion_hash: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Corpus Expander — bulk ingestion framework
// ═══════════════════════════════════════════════════════════════

/// Result of a bulk ingestion run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IngestionResult {
    /// Source identifier.
    pub source_id: String,
    /// Items successfully ingested.
    pub ingested: usize,
    /// Items that failed parsing.
    pub failed: usize,
    /// Parse errors.
    pub errors: Vec<IngestionError>,
    /// Normalized knowledge produced.
    pub knowledge_items: Vec<NormalizedKnowledge>,
    /// Deterministic hash of all ingested items.
    pub ingestion_hash: String,
}

/// An ingestion error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, thiserror::Error)]
#[error("Ingestion error in {source_identifier}: {message}")]
pub struct IngestionError {
    /// Source identifier.
    pub source_identifier: String,
    /// Error message.
    pub message: String,
    /// Whether the error is recoverable.
    pub recoverable: bool,
}

// ═══════════════════════════════════════════════════════════════
// Source Onboarding Workflow
// ═══════════════════════════════════════════════════════════════

/// Stage in the source onboarding workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OnboardingStage {
    /// Source discovered but not yet analyzed.
    Discovered,
    /// Parsing format identified.
    Parsed,
    /// Extraction rules defined.
    Extracted,
    /// Canonical normalization verified.
    Normalized,
    /// Semantic equivalence checked.
    Equivalent,
    /// Pattern extraction complete.
    Patterned,
    /// Knowledge graph integrated.
    Integrated,
    /// Analytics computed.
    Analyzed,
    /// Validation passed.
    Validated,
    /// Observability configured.
    Observable,
}

impl std::fmt::Display for OnboardingStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovered => write!(f, "discovered"),
            Self::Parsed => write!(f, "parsed"),
            Self::Extracted => write!(f, "extracted"),
            Self::Normalized => write!(f, "normalized"),
            Self::Equivalent => write!(f, "equivalent"),
            Self::Patterned => write!(f, "patterned"),
            Self::Integrated => write!(f, "integrated"),
            Self::Analyzed => write!(f, "analyzed"),
            Self::Validated => write!(f, "validated"),
            Self::Observable => write!(f, "observable"),
        }
    }
}

/// A source onboarding workflow record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceOnboarding {
    /// Source identifier.
    pub source_id: String,
    /// Current stage.
    pub stage: OnboardingStage,
    /// Stage history.
    pub stages: Vec<StageRecord>,
    /// Issues found during onboarding.
    pub issues: Vec<OnboardingIssue>,
    /// Recommendations for human review.
    pub recommendations: Vec<String>,
}

/// A record of a stage transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StageRecord {
    /// Stage that was completed.
    pub stage: OnboardingStage,
    /// Whether the stage passed.
    pub passed: bool,
    /// Issues found.
    pub issues: Vec<String>,
    /// Deterministic hash of stage output.
    pub output_hash: String,
}

/// An issue found during onboarding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OnboardingIssue {
    /// Issue kind.
    pub kind: OnboardingIssueKind,
    /// Description.
    pub description: String,
    /// Recommendation.
    pub recommendation: String,
}

/// Kind of onboarding issue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OnboardingIssueKind {
    /// Parse failure.
    ParseFailure,
    /// Missing fields.
    MissingFields,
    /// Normalization gap.
    NormalizationGap,
    /// No semantic equivalence found.
    NoEquivalence,
    /// Low pattern coverage.
    LowPatternCoverage,
    /// Validation failure.
    ValidationFailure,
}

impl std::fmt::Display for OnboardingIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseFailure => write!(f, "parse_failure"),
            Self::MissingFields => write!(f, "missing_fields"),
            Self::NormalizationGap => write!(f, "normalization_gap"),
            Self::NoEquivalence => write!(f, "no_equivalence"),
            Self::LowPatternCoverage => write!(f, "low_pattern_coverage"),
            Self::ValidationFailure => write!(f, "validation_failure"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Normalization Improvement Framework
// ═══════════════════════════════════════════════════════════════

/// Normalization audit — identifies gaps in the canonical taxonomy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizationAudit {
    /// Frequently unmatched vulnerability classes.
    pub unmatched_classes: Vec<UnmatchedConcept>,
    /// Frequently unmatched root causes.
    pub unmatched_root_causes: Vec<UnmatchedConcept>,
    /// Frequently unmatched attack techniques.
    pub unmatched_techniques: Vec<UnmatchedConcept>,
    /// Frequently unmatched mitigation patterns.
    pub unmatched_mitigations: Vec<UnmatchedConcept>,
    /// Recommendations for canonical additions.
    pub recommendations: Vec<NormalizationRecommendation>,
}

/// An unmatched concept — appears in corpus but not in canonical taxonomy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnmatchedConcept {
    /// The unmatched text.
    pub text: String,
    /// How many findings contain this text.
    pub frequency: usize,
    /// Protocols where this appears.
    pub protocols: Vec<String>,
    /// Suggested canonical name.
    pub suggested_canonical: String,
    /// Suggested parent class (if mapping to existing class).
    pub suggested_parent: Option<String>,
}

/// A recommendation for canonical taxonomy addition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizationRecommendation {
    /// Recommendation identifier.
    pub recommendation_id: String,
    /// Kind of recommendation.
    pub kind: NormalizationAction,
    /// Target section (vulnerability_class, root_cause, etc.).
    pub section: String,
    /// Proposed canonical name.
    pub proposed_name: String,
    /// Description.
    pub description: String,
    /// Supporting evidence.
    pub evidence: Vec<String>,
    /// Priority: high, medium, low.
    pub priority: String,
}

/// Kind of normalization action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NormalizationAction {
    /// Add new canonical concept.
    Add,
    /// Merge into existing concept.
    Merge,
    /// Split existing concept.
    Split,
    /// Deprecate existing concept.
    Deprecate,
}

impl std::fmt::Display for NormalizationAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Add => write!(f, "add"),
            Self::Merge => write!(f, "merge"),
            Self::Split => write!(f, "split"),
            Self::Deprecate => write!(f, "deprecate"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Reasoning Coverage
// ═══════════════════════════════════════════════════════════════

/// Reasoning coverage — how well each semantic concept is supported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningCoverageReport {
    /// Per-concept coverage.
    pub concepts: Vec<ConceptCoverage>,
    /// Overall coverage score (0.0–1.0).
    pub overall_score: f64,
    /// Concepts with insufficient evidence.
    pub weak_concepts: Vec<String>,
}

/// Coverage for a single canonical concept.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConceptCoverage {
    /// Concept name.
    pub name: String,
    /// Concept kind (vulnerability_class, root_cause, etc.).
    pub kind: String,
    /// Number of supporting findings.
    pub finding_count: usize,
    /// Number of supporting protocols.
    pub protocol_count: usize,
    /// Number of supporting sources.
    pub source_count: usize,
    /// Number of supporting exploit postmortems.
    pub postmortem_count: usize,
    /// Number of supporting standards.
    pub standard_count: usize,
    /// Number of supporting documentation entries.
    pub documentation_count: usize,
    /// Number of supporting reasoning patterns.
    pub pattern_count: usize,
    /// Coverage level: high, medium, low, none.
    pub coverage_level: String,
    /// Coverage score (0.0–1.0).
    pub score: f64,
}

// ═══════════════════════════════════════════════════════════════
// Engine Functions
// ═══════════════════════════════════════════════════════════════

/// Compute normalization audit from corpus analytics.
pub fn compute_normalization_audit(
    analytics: &super::analytics::CorpusAnalyticsReport,
) -> NormalizationAudit {
    let mut unmatched_classes = Vec::new();
    let mut unmatched_root_causes = Vec::new();
    let mut unmatched_techniques = Vec::new();

    // Collect unclassified clusters
    for cluster in &analytics.gaps.unclassified_clusters {
        if cluster.count >= 2 {
            unmatched_classes.push(UnmatchedConcept {
                text: cluster.pattern.clone(),
                frequency: cluster.count,
                protocols: cluster.protocols.clone(),
                suggested_canonical: cluster.suggested_class.clone(),
                suggested_parent: None,
            });
        }
    }

    // Collect unknown root causes
    for rc in &analytics.gaps.unknown_root_causes {
        if rc.frequency >= 2 {
            unmatched_root_causes.push(UnmatchedConcept {
                text: rc.description.clone(),
                frequency: rc.frequency,
                protocols: rc.protocols.clone(),
                suggested_canonical: String::new(),
                suggested_parent: None,
            });
        }
    }

    // Collect unknown techniques
    for tech in &analytics.gaps.unknown_techniques {
        if tech.frequency >= 2 {
            unmatched_techniques.push(UnmatchedConcept {
                text: tech.description.clone(),
                frequency: tech.frequency,
                protocols: tech.protocols.clone(),
                suggested_canonical: String::new(),
                suggested_parent: None,
            });
        }
    }

    // Generate recommendations
    let mut recommendations = Vec::new();
    let mut rec_id = 0;

    for concept in &unmatched_classes {
        if concept.frequency >= 5 {
            recommendations.push(NormalizationRecommendation {
                recommendation_id: format!("rec:{:04}", rec_id),
                kind: if concept.suggested_parent.is_some() {
                    NormalizationAction::Merge
                } else {
                    NormalizationAction::Add
                },
                section: "vulnerability_class".into(),
                proposed_name: concept.suggested_canonical.clone(),
                description: format!(
                    "Add '{}' as canonical vulnerability class ({} findings, {} protocols)",
                    concept.text,
                    concept.frequency,
                    concept.protocols.len()
                ),
                evidence: concept.protocols.clone(),
                priority: if concept.frequency >= 10 {
                    "high"
                } else {
                    "medium"
                }
                .into(),
            });
            rec_id += 1;
        }
    }

    for concept in &unmatched_root_causes {
        if concept.frequency >= 5 {
            recommendations.push(NormalizationRecommendation {
                recommendation_id: format!("rec:{:04}", rec_id),
                kind: NormalizationAction::Add,
                section: "root_cause".into(),
                proposed_name: concept.text.clone(),
                description: format!(
                    "Add '{}' as canonical root cause ({} protocols)",
                    concept.text,
                    concept.protocols.len()
                ),
                evidence: concept.protocols.clone(),
                priority: if concept.frequency >= 10 {
                    "high"
                } else {
                    "medium"
                }
                .into(),
            });
            rec_id += 1;
        }
    }

    NormalizationAudit {
        unmatched_classes,
        unmatched_root_causes,
        unmatched_techniques,
        unmatched_mitigations: vec![],
        recommendations,
    }
}

/// Compute reasoning coverage from knowledge items.
pub fn compute_reasoning_coverage(
    knowledge_items: &[NormalizedKnowledge],
) -> ReasoningCoverageReport {
    let mut concept_data: BTreeMap<String, ConceptCoverage> = BTreeMap::new();

    for item in knowledge_items {
        for finding in &item.findings {
            let class = finding.vulnerability_class.to_string();
            let entry = concept_data
                .entry(class.clone())
                .or_insert_with(|| ConceptCoverage {
                    name: class.clone(),
                    kind: "vulnerability_class".into(),
                    finding_count: 0,
                    protocol_count: 0,
                    source_count: 0,
                    postmortem_count: 0,
                    standard_count: 0,
                    documentation_count: 0,
                    pattern_count: 0,
                    coverage_level: "none".into(),
                    score: 0.0,
                });
            entry.finding_count += 1;
        }
    }

    // Compute scores
    for concept in concept_data.values_mut() {
        let mut score: f64 = 0.0;
        if concept.finding_count > 0 {
            score += 0.3;
        }
        if concept.protocol_count > 0 {
            score += 0.2;
        }
        if concept.source_count > 0 {
            score += 0.2;
        }
        if concept.postmortem_count > 0 {
            score += 0.15;
        }
        if concept.standard_count > 0 {
            score += 0.1;
        }
        if concept.pattern_count > 0 {
            score += 0.05;
        }
        concept.score = score.min(1.0);
        concept.coverage_level = if score >= 0.7 {
            "high".into()
        } else if score >= 0.4 {
            "medium".into()
        } else if score > 0.0 {
            "low".into()
        } else {
            "none".into()
        };
    }

    let concepts: Vec<ConceptCoverage> = concept_data.into_values().collect();
    let overall_score = if concepts.is_empty() {
        0.0
    } else {
        concepts.iter().map(|c| c.score).sum::<f64>() / concepts.len() as f64
    };
    let weak_concepts: Vec<String> = concepts
        .iter()
        .filter(|c| c.score < 0.3)
        .map(|c| c.name.clone())
        .collect();

    ReasoningCoverageReport {
        concepts,
        overall_score,
        weak_concepts,
    }
}

/// Serialize normalization audit to JSON.
pub fn audit_to_json(audit: &NormalizationAudit) -> String {
    serde_json::to_string_pretty(audit).unwrap_or_else(|_| "{}".into())
}

/// Serialize reasoning coverage to JSON.
pub fn coverage_to_json(coverage: &ReasoningCoverageReport) -> String {
    serde_json::to_string_pretty(coverage).unwrap_or_else(|_| "{}".into())
}
