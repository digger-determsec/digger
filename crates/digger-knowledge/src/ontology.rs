/// Ontology Evolution — human-curated growth of the canonical security ontology.
///
/// Collects candidate concepts from corpus analytics and produces
/// deterministic review artifacts for human approval.
///
/// Never automatically modifies the canonical ontology.
/// Every change preserves version history and evidence.
///
/// Deterministic: same inputs → same outputs.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// Ontology Version
// ═══════════════════════════════════════════════════════════════

/// The canonical security ontology with version history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityOntology {
    /// Current version identifier.
    pub version: String,
    /// Version history.
    pub history: Vec<OntologyVersion>,
    /// Canonical vulnerability classes.
    pub vulnerability_classes: Vec<OntologyEntry>,
    /// Canonical attack techniques.
    pub attack_techniques: Vec<OntologyEntry>,
    /// Canonical root causes.
    pub root_causes: Vec<OntologyEntry>,
    /// Canonical invariant types.
    pub invariant_types: Vec<OntologyEntry>,
    /// Canonical mitigation patterns.
    pub mitigation_patterns: Vec<OntologyEntry>,
    /// Canonical architectural patterns.
    pub architectural_patterns: Vec<OntologyEntry>,
}

/// A single ontology version record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OntologyVersion {
    /// Version identifier.
    pub version: String,
    /// Change description.
    pub description: String,
    /// Changes made.
    pub changes: Vec<OntologyChange>,
    /// Deterministic hash of the state at this version.
    pub state_hash: String,
}

/// A change to the ontology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OntologyChange {
    /// Change kind.
    pub kind: ChangeKind,
    /// Which section was changed.
    pub section: String,
    /// The entry affected.
    pub entry_name: String,
    /// Evidence that justified this change.
    pub evidence: ChangeEvidence,
}

/// Kind of ontology change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeKind {
    /// New concept added.
    Addition,
    /// Two or more concepts merged.
    Merge,
    /// One concept split into multiple.
    Split,
    /// Concept deprecated (no longer recommended).
    Deprecation,
    /// Concept description or metadata updated.
    Update,
}

impl std::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Addition => write!(f, "addition"),
            Self::Merge => write!(f, "merge"),
            Self::Split => write!(f, "split"),
            Self::Deprecation => write!(f, "deprecation"),
            Self::Update => write!(f, "update"),
        }
    }
}

/// Evidence that justified an ontology change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChangeEvidence {
    /// Number of findings supporting this change.
    pub support_count: usize,
    /// Protocols where this was observed.
    pub protocols: Vec<String>,
    /// Knowledge sources that contributed.
    pub sources: Vec<String>,
    /// Review recommendation ID that led to this change.
    pub recommendation_id: String,
}

/// A single entry in the canonical ontology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OntologyEntry {
    /// Canonical name.
    pub name: String,
    /// Description.
    pub description: String,
    /// When this entry was added.
    pub added_in_version: String,
    /// Evidence at time of addition.
    pub addition_evidence: ChangeEvidence,
    /// Related entries (for merges/splits).
    pub related_entries: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Candidate Concepts
// ═══════════════════════════════════════════════════════════════

/// A candidate concept for ontology inclusion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateConcept {
    /// Proposed canonical name.
    pub name: String,
    /// Concept kind.
    pub kind: ConceptKind,
    /// Description.
    pub description: String,
    /// Supporting metadata.
    pub metadata: CandidateMetadata,
}

/// Kind of concept.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConceptKind {
    VulnerabilityClass,
    AttackTechnique,
    RootCause,
    InvariantType,
    MitigationPattern,
    ArchitecturalPattern,
}

impl std::fmt::Display for ConceptKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VulnerabilityClass => write!(f, "vulnerability_class"),
            Self::AttackTechnique => write!(f, "attack_technique"),
            Self::RootCause => write!(f, "root_cause"),
            Self::InvariantType => write!(f, "invariant_type"),
            Self::MitigationPattern => write!(f, "mitigation_pattern"),
            Self::ArchitecturalPattern => write!(f, "architectural_pattern"),
        }
    }
}

/// Supporting metadata for a candidate concept.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateMetadata {
    /// Number of findings matching this candidate.
    pub support_count: usize,
    /// Protocols where this was observed.
    pub contributing_protocols: Vec<String>,
    /// Knowledge sources that contributed.
    pub contributing_sources: Vec<String>,
    /// Semantic equivalence cluster sizes.
    pub equivalence_clusters: Vec<usize>,
    /// Associated reasoning pattern IDs.
    pub reasoning_patterns: Vec<String>,
    /// Historical example finding IDs.
    pub historical_examples: Vec<String>,
    /// Severity distribution of supporting findings.
    pub severity_distribution: BTreeMap<String, usize>,
}

// ═══════════════════════════════════════════════════════════════
// Review Artifacts
// ═══════════════════════════════════════════════════════════════

/// An ontology review artifact — a set of recommendations for human approval.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OntologyReview {
    /// Review identifier (deterministic).
    pub review_id: String,
    /// Current ontology version.
    pub current_version: String,
    /// Recommendations.
    pub recommendations: Vec<OntologyRecommendation>,
    /// Summary statistics.
    pub summary: ReviewSummary,
}

/// A single recommendation for ontology change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OntologyRecommendation {
    /// Recommendation identifier.
    pub recommendation_id: String,
    /// Change kind.
    pub kind: ChangeKind,
    /// Which section to change.
    pub section: String,
    /// The candidate concept(s) involved.
    pub candidates: Vec<CandidateConcept>,
    /// Existing entries affected (for merge/split/deprecation).
    pub affected_entries: Vec<String>,
    /// Human-readable justification.
    pub justification: String,
    /// Supporting evidence.
    pub evidence: ChangeEvidence,
    /// Priority: "high" (strong corpus support), "medium", "low".
    pub priority: String,
    /// Status: "pending", "approved", "rejected", "deferred".
    pub status: String,
}

/// Summary statistics for a review.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReviewSummary {
    /// Total recommendations.
    pub total_recommendations: usize,
    /// Recommendations by kind.
    pub by_kind: BTreeMap<String, usize>,
    /// Recommendations by section.
    pub by_section: BTreeMap<String, usize>,
    /// Recommendations by priority.
    pub by_priority: BTreeMap<String, usize>,
    /// Total supporting findings across all recommendations.
    pub total_supporting_findings: usize,
    /// Total protocols represented.
    pub total_protocols: usize,
}

// ═══════════════════════════════════════════════════════════════
// Evolution Engine
// ═══════════════════════════════════════════════════════════════

/// Compute ontology review from corpus analytics and current ontology.
pub fn compute_ontology_review(
    _analytics: &super::analytics::CorpusAnalyticsReport,
    knowledge_items: &[NormalizedKnowledge],
    current_ontology: &SecurityOntology,
) -> OntologyReview {
    let mut recommendations = Vec::new();
    let all_findings: Vec<&NormalizedFinding> = knowledge_items
        .iter()
        .flat_map(|k| k.findings.iter())
        .collect();

    // Collect candidates from each dimension
    let class_candidates = collect_class_candidates(&all_findings, current_ontology);
    let tech_candidates = collect_technique_candidates(&all_findings, current_ontology);
    let rc_candidates = collect_root_cause_candidates(&all_findings, current_ontology);

    // Generate recommendations
    for candidate in &class_candidates {
        recommendations.push(build_addition_recommendation(
            candidate,
            "vulnerability_classes",
        ));
    }
    for candidate in &tech_candidates {
        recommendations.push(build_addition_recommendation(
            candidate,
            "attack_techniques",
        ));
    }
    for candidate in &rc_candidates {
        recommendations.push(build_addition_recommendation(candidate, "root_causes"));
    }

    // Check for merge candidates (similar existing entries)
    recommendations.extend(find_merge_candidates(
        &class_candidates,
        &current_ontology.vulnerability_classes,
        "vulnerability_classes",
    ));
    recommendations.extend(find_merge_candidates(
        &tech_candidates,
        &current_ontology.attack_techniques,
        "attack_techniques",
    ));

    // Check for deprecation candidates (entries with very low support)
    recommendations.extend(find_deprecation_candidates(
        &current_ontology.vulnerability_classes,
        &all_findings,
        "vulnerability_classes",
    ));

    // Sort by priority then by support count
    recommendations.sort_by(|a, b| {
        priority_rank(&a.priority)
            .cmp(&priority_rank(&b.priority))
            .then(b.evidence.support_count.cmp(&a.evidence.support_count))
    });

    // Assign IDs
    for (i, rec) in recommendations.iter_mut().enumerate() {
        rec.recommendation_id = format!("rec:{:04}", i);
    }

    let summary = build_review_summary(&recommendations);

    OntologyReview {
        review_id: compute_review_id(&recommendations),
        current_version: current_ontology.version.clone(),
        recommendations,
        summary,
    }
}

/// Collect candidate vulnerability classes from unclassified findings.
fn collect_class_candidates<'a>(
    findings: &[&'a NormalizedFinding],
    ontology: &SecurityOntology,
) -> Vec<CandidateConcept> {
    let existing: std::collections::BTreeSet<String> = ontology
        .vulnerability_classes
        .iter()
        .map(|e| e.name.clone())
        .collect();

    let mut clusters: BTreeMap<String, Vec<&'a NormalizedFinding>> = BTreeMap::new();
    for f in findings {
        let class = f.vulnerability_class.to_string();
        if class.starts_with("other(") && !existing.contains(&class) {
            clusters.entry(class).or_default().push(f);
        }
    }

    clusters
        .into_iter()
        .filter(|(_, findings)| {
            let mut protocols: Vec<String> =
                findings.iter().map(|f| f.protocol_name.clone()).collect();
            protocols.sort();
            protocols.dedup();
            protocols.len() >= 2 // require 2+ protocols
        })
        .map(|(name, findings)| build_candidate(&name, ConceptKind::VulnerabilityClass, &findings))
        .collect()
}

/// Collect candidate attack techniques.
fn collect_technique_candidates<'a>(
    findings: &[&'a NormalizedFinding],
    ontology: &SecurityOntology,
) -> Vec<CandidateConcept> {
    let existing: std::collections::BTreeSet<String> = ontology
        .attack_techniques
        .iter()
        .map(|e| e.name.clone())
        .collect();

    let mut clusters: BTreeMap<String, Vec<&'a NormalizedFinding>> = BTreeMap::new();
    for f in findings {
        let tech = f.attack_technique.to_string();
        if tech.starts_with("other(") && !existing.contains(&tech) {
            clusters.entry(tech).or_default().push(f);
        }
    }

    clusters
        .into_iter()
        .filter(|(_, findings)| {
            let mut protocols: Vec<String> =
                findings.iter().map(|f| f.protocol_name.clone()).collect();
            protocols.sort();
            protocols.dedup();
            protocols.len() >= 2
        })
        .map(|(name, findings)| build_candidate(&name, ConceptKind::AttackTechnique, &findings))
        .collect()
}

/// Collect candidate root causes.
fn collect_root_cause_candidates<'a>(
    findings: &[&'a NormalizedFinding],
    ontology: &SecurityOntology,
) -> Vec<CandidateConcept> {
    let existing: std::collections::BTreeSet<String> = ontology
        .root_causes
        .iter()
        .map(|e| e.name.clone())
        .collect();

    let mut clusters: BTreeMap<String, Vec<&'a NormalizedFinding>> = BTreeMap::new();
    for f in findings {
        let rc = f.root_cause.to_string();
        if rc.starts_with("other(") && !existing.contains(&rc) {
            clusters.entry(rc).or_default().push(f);
        }
    }

    clusters
        .into_iter()
        .filter(|(_, findings)| {
            let mut protocols: Vec<String> =
                findings.iter().map(|f| f.protocol_name.clone()).collect();
            protocols.sort();
            protocols.dedup();
            protocols.len() >= 2
        })
        .map(|(name, findings)| build_candidate(&name, ConceptKind::RootCause, &findings))
        .collect()
}

/// Build a candidate concept from a cluster of findings.
fn build_candidate(
    name: &str,
    kind: ConceptKind,
    findings: &[&NormalizedFinding],
) -> CandidateConcept {
    let mut protocols: Vec<String> = findings.iter().map(|f| f.protocol_name.clone()).collect();
    protocols.sort();
    protocols.dedup();

    let mut sources: Vec<String> = findings.iter().map(|f| f.report_id.clone()).collect();
    sources.sort();
    sources.dedup();

    let mut severity_dist: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        *severity_dist.entry(f.severity.to_string()).or_insert(0) += 1;
    }

    let examples: Vec<String> = findings
        .iter()
        .take(5)
        .map(|f| f.finding_id.clone())
        .collect();

    CandidateConcept {
        name: name.to_string(),
        kind,
        description: format!(
            "Candidate with {} findings across {} protocols",
            findings.len(),
            protocols.len()
        ),
        metadata: CandidateMetadata {
            support_count: findings.len(),
            contributing_protocols: protocols,
            contributing_sources: sources,
            equivalence_clusters: vec![],
            reasoning_patterns: vec![],
            historical_examples: examples,
            severity_distribution: severity_dist,
        },
    }
}

/// Build an addition recommendation.
fn build_addition_recommendation(
    candidate: &CandidateConcept,
    section: &str,
) -> OntologyRecommendation {
    let priority = if candidate.metadata.support_count >= 10 {
        "high"
    } else if candidate.metadata.support_count >= 5 {
        "medium"
    } else {
        "low"
    };

    OntologyRecommendation {
        recommendation_id: String::new(), // assigned later
        kind: ChangeKind::Addition,
        section: section.to_string(),
        candidates: vec![candidate.clone()],
        affected_entries: vec![],
        justification: format!(
            "Add '{}' to {} based on {} findings across {} protocols",
            candidate.name,
            section,
            candidate.metadata.support_count,
            candidate.metadata.contributing_protocols.len()
        ),
        evidence: ChangeEvidence {
            support_count: candidate.metadata.support_count,
            protocols: candidate.metadata.contributing_protocols.clone(),
            sources: candidate.metadata.contributing_sources.clone(),
            recommendation_id: String::new(),
        },
        priority: priority.to_string(),
        status: "pending".to_string(),
    }
}

/// Find merge candidates — new candidates that are similar to existing entries.
fn find_merge_candidates(
    candidates: &[CandidateConcept],
    existing: &[OntologyEntry],
    section: &str,
) -> Vec<OntologyRecommendation> {
    let mut recommendations = Vec::new();

    for candidate in candidates {
        for entry in existing {
            if are_similar(&candidate.name, &entry.name) {
                recommendations.push(OntologyRecommendation {
                    recommendation_id: String::new(),
                    kind: ChangeKind::Merge,
                    section: section.to_string(),
                    candidates: vec![candidate.clone()],
                    affected_entries: vec![entry.name.clone()],
                    justification: format!(
                        "Merge '{}' into existing '{}' — similar concepts",
                        candidate.name, entry.name
                    ),
                    evidence: ChangeEvidence {
                        support_count: candidate.metadata.support_count,
                        protocols: candidate.metadata.contributing_protocols.clone(),
                        sources: candidate.metadata.contributing_sources.clone(),
                        recommendation_id: String::new(),
                    },
                    priority: "medium".to_string(),
                    status: "pending".to_string(),
                });
            }
        }
    }

    recommendations
}

/// Find deprecation candidates — existing entries with very low corpus support.
fn find_deprecation_candidates(
    existing: &[OntologyEntry],
    findings: &[&NormalizedFinding],
    section: &str,
) -> Vec<OntologyRecommendation> {
    let mut recommendations = Vec::new();

    for entry in existing {
        let support = findings
            .iter()
            .filter(|f| f.vulnerability_class.to_string() == entry.name)
            .count();

        if support == 0 {
            recommendations.push(OntologyRecommendation {
                recommendation_id: String::new(),
                kind: ChangeKind::Deprecation,
                section: section.to_string(),
                candidates: vec![],
                affected_entries: vec![entry.name.clone()],
                justification: format!(
                    "Deprecate '{}' — zero findings in current corpus",
                    entry.name
                ),
                evidence: ChangeEvidence {
                    support_count: 0,
                    protocols: vec![],
                    sources: vec![],
                    recommendation_id: String::new(),
                },
                priority: "low".to_string(),
                status: "pending".to_string(),
            });
        }
    }

    recommendations
}

/// Check if two concept names are similar (simple heuristic).
fn are_similar(a: &str, b: &str) -> bool {
    let a_lower = a.to_lowercase().replace(['_', '-'], " ");
    let b_lower = b.to_lowercase().replace(['_', '-'], " ");

    // Exact match after normalization
    if a_lower == b_lower {
        return true;
    }

    // One contains the other
    if a_lower.contains(&b_lower) || b_lower.contains(&a_lower) {
        return true;
    }

    // Check for common stems
    let a_words: Vec<&str> = a_lower.split_whitespace().collect();
    let b_words: Vec<&str> = b_lower.split_whitespace().collect();
    let common = a_words.iter().filter(|w| b_words.contains(w)).count();
    if common >= 2 && common >= a_words.len().min(b_words.len()) / 2 {
        return true;
    }

    false
}

/// Priority ranking for sorting.
fn priority_rank(priority: &str) -> u8 {
    match priority {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

/// Build review summary.
fn build_review_summary(recommendations: &[OntologyRecommendation]) -> ReviewSummary {
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_section: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_priority: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_support = 0;
    let mut all_protocols: Vec<String> = Vec::new();

    for rec in recommendations {
        *by_kind.entry(rec.kind.to_string()).or_insert(0) += 1;
        *by_section.entry(rec.section.clone()).or_insert(0) += 1;
        *by_priority.entry(rec.priority.clone()).or_insert(0) += 1;
        total_support += rec.evidence.support_count;
        all_protocols.extend(rec.evidence.protocols.clone());
    }

    all_protocols.sort();
    all_protocols.dedup();

    ReviewSummary {
        total_recommendations: recommendations.len(),
        by_kind,
        by_section,
        by_priority,
        total_supporting_findings: total_support,
        total_protocols: all_protocols.len(),
    }
}

/// Compute deterministic review ID.
fn compute_review_id(recommendations: &[OntologyRecommendation]) -> String {
    let mut h: u64 = 0;
    for rec in recommendations {
        for byte in rec.recommendation_id.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
        for byte in rec.section.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
    }
    format!("{:x}", h)
}

/// Create an initial ontology with the current canonical concepts.
pub fn initial_ontology() -> SecurityOntology {
    SecurityOntology {
        version: "1.0.0".into(),
        history: vec![OntologyVersion {
            version: "1.0.0".into(),
            description: "Initial canonical ontology".into(),
            changes: vec![],
            state_hash: "initial".into(),
        }],
        vulnerability_classes: vec![
            entry(
                "missing_access_control",
                "Missing or insufficient access control checks",
            ),
            entry("privilege_escalation", "Unauthorized privilege escalation"),
            entry(
                "unprotected_initialization",
                "Unprotected or uninitialized contracts",
            ),
            entry("reentrancy", "Reentrant calls violating state consistency"),
            entry(
                "cross_function_reentrancy",
                "Reentrancy across functions within same contract",
            ),
            entry("cross_contract_reentrancy", "Reentrancy across contracts"),
            entry("flash_loan_attack", "Flash loan enabled economic attacks"),
            entry("oracle_manipulation", "Oracle price feed manipulation"),
            entry(
                "price_manipulation",
                "Price manipulation via market actions",
            ),
            entry("sandwich_attack", "Front and back running for profit"),
            entry("front_running", "Transaction ordering exploitation"),
            entry("mev_extraction", "Maximal extractable value extraction"),
            entry(
                "liquidation_manipulation",
                "Liquidation mechanism exploitation",
            ),
            entry("precision_loss", "Arithmetic precision loss"),
            entry("rounding_error", "Rounding direction errors"),
            entry("integer_overflow", "Integer overflow or underflow"),
            entry("invariant_violation", "Protocol invariant violation"),
            entry("state_corruption", "Unauthorized state modification"),
            entry("denial_of_service", "Service availability attacks"),
            entry("griefing", "Economic griefing attacks"),
            entry(
                "business_logic_flaw",
                "Business logic implementation errors",
            ),
            entry("missing_validation", "Missing input or state validation"),
            entry("incorrect_calculation", "Incorrect arithmetic or logic"),
            entry("unchecked_return", "Unchecked external call return values"),
            entry("storage_collision", "Proxy storage slot collision"),
            entry(
                "proxy_initialization",
                "Proxy initialization vulnerabilities",
            ),
            entry("upgradeability_risk", "Upgrade mechanism risks"),
            entry("composability_risk", "Cross-protocol composability risks"),
            entry(
                "cross_protocol_dependency",
                "Cross-protocol dependency risks",
            ),
            entry("governance_attack", "Governance mechanism attacks"),
            entry("timelock_bypass", "Timelock mechanism bypass"),
            entry("voting_manipulation", "Voting mechanism manipulation"),
            entry("centralization_risk", "Centralization trust assumptions"),
        ],
        attack_techniques: vec![
            entry("reentrancy_exploit", "Reentrant call exploitation"),
            entry("flash_loan_borrow", "Flash loan capital acquisition"),
            entry(
                "price_oracle_manipulation",
                "Oracle price feed manipulation",
            ),
            entry(
                "front_running_transaction",
                "Transaction reordering exploitation",
            ),
            entry("sandwich_attack_vector", "Front-back running for profit"),
            entry(
                "governance_proposal_attack",
                "Governance proposal manipulation",
            ),
            entry("timelock_exploitation", "Timelock mechanism exploitation"),
            entry(
                "storage_collision_exploit",
                "Proxy storage collision exploitation",
            ),
            entry(
                "delegatecall_exploitation",
                "Delegatecall context confusion",
            ),
            entry(
                "unchecked_external_call",
                "Unchecked external call exploitation",
            ),
            entry("precision_loss_exploitation", "Precision loss exploitation"),
            entry("access_control_bypass", "Access control bypass techniques"),
            entry("initialization_bypass", "Initialization bypass techniques"),
        ],
        root_causes: vec![
            entry(
                "missing_authority_check",
                "Missing authority or access control check",
            ),
            entry(
                "incorrect_operation_order",
                "Operations in wrong order (CEI violation)",
            ),
            entry("missing_state_update", "State not updated after operation"),
            entry(
                "shared_mutable_state",
                "Shared mutable state without synchronization",
            ),
            entry("unvalidated_external_input", "External input not validated"),
            entry(
                "incorrect_invariant_assumption",
                "Incorrect assumption about invariants",
            ),
            entry("missing_boundary_check", "Missing bounds or limit checks"),
            entry("unsafe_composition", "Unsafe protocol composition"),
            entry(
                "fee_on_transfer_incompatibility",
                "Protocol incompatible with fee-on-transfer tokens",
            ),
            entry(
                "stale_state_assumption",
                "Protocol assumes state remains fresh when it may be stale",
            ),
            entry(
                "unchecked_return_value",
                "External call return value not checked",
            ),
            entry(
                "incorrect_rounding_direction",
                "Rounding favors attacker instead of protocol",
            ),
            entry(
                "missing_event_emission",
                "State change without corresponding event",
            ),
            entry(
                "unsafe_external_dependency",
                "Protocol relies on external contract behavior",
            ),
            entry(
                "gas_griefing",
                "External call can consume excess gas or grief",
            ),
            entry(
                "signature_malleability",
                "ECDSA signature can be modified without invalidation",
            ),
            entry("front_running_risk", "Transaction ordering dependency"),
            entry("oracle_staleness", "Price feed not validated for freshness"),
            entry(
                "missing_slippage_protection",
                "No minimum output or maximum input check",
            ),
            entry(
                "missing_zero_address_check",
                "Address not validated against zero",
            ),
            entry(
                "timestamp_dependency",
                "Logic depends on block.timestamp manipulation",
            ),
            entry(
                "cross_function_state_inconsistency",
                "State becomes inconsistent across function calls",
            ),
        ],
        invariant_types: vec![
            entry("conservation", "Total quantity preserved across operations"),
            entry("solvency", "Assets >= liabilities"),
            entry("collateralization", "Collateral >= debt * factor"),
            entry("accounting", "Debits == credits"),
            entry("authority", "Only authorized actors can perform actions"),
            entry("ordering", "Operations must follow specified order"),
        ],
        mitigation_patterns: vec![
            entry(
                "checks_effects_interactions",
                "Checks-Effects-Interactions pattern",
            ),
            entry("access_control_modifier", "Access control modifier pattern"),
            entry("flash_loan_protection", "Flash loan protection mechanisms"),
            entry("oracle_validation", "Oracle data validation"),
            entry("reentrancy_guard", "Reentrancy guard mutex"),
            entry("timelock_enforcement", "Timelock enforcement pattern"),
        ],
        architectural_patterns: vec![
            entry("transparent_proxy", "Transparent proxy pattern"),
            entry("uups_proxy", "UUPS proxy pattern"),
            entry("beacon_proxy", "Beacon proxy pattern"),
            entry("amm_curve", "Automated market maker curve"),
            entry("lending_pool", "Lending pool pattern"),
            entry("vault_strategy", "Vault and strategy pattern"),
            entry("governance_timelock", "Governance with timelock"),
        ],
    }
}

fn entry(name: &str, description: &str) -> OntologyEntry {
    OntologyEntry {
        name: name.into(),
        description: description.into(),
        added_in_version: "1.0.0".into(),
        addition_evidence: ChangeEvidence {
            support_count: 0,
            protocols: vec![],
            sources: vec![],
            recommendation_id: "initial".into(),
        },
        related_entries: vec![],
    }
}

/// Serialize review to JSON.
pub fn review_to_json(review: &OntologyReview) -> String {
    serde_json::to_string_pretty(review).unwrap_or_else(|_| "{}".into())
}
