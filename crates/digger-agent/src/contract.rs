use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Typed error returned when projecting raw engine strings into contract enums.
///
/// Replaces the previous `Result<_, String>` boundary so callers can match on
/// typed variants instead of parsing error prose. Display strings are preserved
/// verbatim so existing logs and string-based assertions remain stable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    #[error("unknown severity: {0}")]
    UnknownSeverity(String),
    #[error("unknown confidence: {0}")]
    UnknownConfidence(String),
    #[error("unknown stage: {0} (must be shadow/advisory/armed)")]
    UnknownStage(String),
}

/// Severity enum mirroring the engine's ordering.
/// From digger_ir::Severity — reused here via string projection with
/// compile-time rejection of invalid values.
///
/// Wire casing: lowercase (info, low, medium, high, critical).
/// Engine origin: digger_ir::Severity (Info < Low < Medium < High < Critical).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl Severity {
    pub fn from_engine_str(s: &str) -> Result<Self, ContractError> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(ContractError::UnknownSeverity(other.to_string())),
        }
    }
}

/// Confidence enum — ordered Experimental < Graduated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Experimental,
    Graduated,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Experimental => write!(f, "experimental"),
            Self::Graduated => write!(f, "graduated"),
        }
    }
}

impl Confidence {
    pub fn from_engine_str(s: &str) -> Result<Self, ContractError> {
        match s.to_lowercase().as_str() {
            "experimental" => Ok(Self::Experimental),
            "graduated" => Ok(Self::Graduated),
            other => Err(ContractError::UnknownConfidence(other.to_string())),
        }
    }
}

/// Stage enum mirroring the engine's PredicateStage ordering.
/// Shadow < Advisory < Armed.
///
/// Wire casing: lowercase (shadow, advisory, armed).
/// Engine origin: digger_evidence::PredicateStage (Shadow/Advisory/Armed).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Shadow,
    Advisory,
    Armed,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shadow => write!(f, "shadow"),
            Self::Advisory => write!(f, "advisory"),
            Self::Armed => write!(f, "armed"),
        }
    }
}

impl Stage {
    pub fn from_engine_str(s: &str) -> Result<Self, ContractError> {
        match s.to_lowercase().as_str() {
            "shadow" => Ok(Self::Shadow),
            "advisory" => Ok(Self::Advisory),
            "armed" => Ok(Self::Armed),
            other => Err(ContractError::UnknownStage(other.to_string())),
        }
    }
}

/// Tri-state predicate outcome — replaces (matched: bool, undetermined: bool).
/// The contradiction matched=true AND undetermined=true is unrepresentable.
///
/// Wire casing: snake_case (matched, not_matched, undetermined).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateOutcomeState {
    Matched,
    NotMatched,
    Undetermined,
}

/// Exploit status as claimed by an assistant.
///
/// Wire casing: snake_case (none, suspected, confirmed).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitStatus {
    None,
    Suspected,
    Confirmed,
}

/// Projected view of a finding for agent consumption.
///
/// Severity, confidence, and stage are typed enums — invalid values
/// are rejected at deserialization, making unlabeled findings unrepresentable.
///
/// Projects from: digger_evidence::Finding + digger_evidence::PredicateStage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingView {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub stage: Stage,
    pub summary: String,
    pub locations: Vec<LocationView>,
    pub evidence_ids: Vec<String>,
}

/// Location within source code.
///
/// Projects from: digger_evidence::Location
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocationView {
    pub file: String,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub symbol: Option<String>,
}

/// Evidence bundle projected for agent consumption.
///
/// Projects from: digger_evidence::EvidenceBundle (thin slice)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundleView {
    pub evidence_id: String,
    pub finding_id: String,
    pub kind: String,
    pub locations: Vec<LocationView>,
    pub raw_refs: Vec<String>,
}

/// Ingredients for explaining a finding — NO natural-language generation.
///
/// Projects from: digger_evidence::Finding + digger_evidence::ExploitPredicate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExplanationContext {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub stage: Stage,
    pub summary: String,
    pub evidence: Vec<EvidenceBundleView>,
    pub locations: Vec<LocationView>,
    pub attack_shape: String,
    pub remediation_hints: Vec<String>,
    pub precedents: Vec<String>,
}

/// Projection of a predicate's evaluation state.
///
/// Uses PredicateOutcomeState (tri-state) — undetermined is first-class,
/// matched+undetermined contradiction is unrepresentable.
///
/// Projects from: digger_evidence::PredicateOutcome
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PredicateState {
    pub predicate_id: String,
    pub outcome: PredicateOutcomeState,
    pub missing_facts: Vec<String>,
    pub resolved_facts: BTreeMap<String, String>,
    pub stage: Stage,
    pub tier: String,
}

// ── Projections from engine types ──────────────────────────────

impl FindingView {
    /// Project from engine Finding + predicate stage.
    pub fn from_engine(
        finding: &digger_evidence::Finding,
        stage: &str,
        summary: &str,
    ) -> Result<Self, ContractError> {
        let view = FindingView {
            finding_id: finding.finding_id.clone(),
            rule_id: finding.rule_id.clone(),
            severity: Severity::from_engine_str(&finding.severity)?,
            confidence: Confidence::from_engine_str(&finding.confidence_label)?,
            stage: Stage::from_engine_str(stage)?,
            summary: summary.to_string(),
            locations: finding
                .locations
                .iter()
                .map(LocationView::from_engine)
                .collect(),
            evidence_ids: finding.evidence_refs.clone(),
        };
        Ok(view)
    }
}

impl LocationView {
    pub fn from_engine(loc: &digger_evidence::Location) -> Self {
        LocationView {
            file: loc.file.clone(),
            line_start: loc.line_start,
            line_end: loc.line_end,
            symbol: loc.symbol.clone(),
        }
    }
}

impl EvidenceBundleView {
    pub fn from_engine(
        bundle_id: &str,
        finding_id: &str,
        kind: &str,
        locations: Vec<LocationView>,
        raw_refs: Vec<String>,
    ) -> Self {
        EvidenceBundleView {
            evidence_id: bundle_id.to_string(),
            finding_id: finding_id.to_string(),
            kind: kind.to_string(),
            locations,
            raw_refs,
        }
    }
}

impl PredicateState {
    /// Project from digger_evidence::PredicateOutcome + ExploitPredicate.
    /// Preserves undetermined as a first-class tri-state value.
    pub fn from_engine(
        outcome: &digger_evidence::PredicateOutcome,
        predicate: &digger_evidence::ExploitPredicate,
    ) -> Self {
        let resolved_facts: BTreeMap<String, String> = outcome
            .resolved_facts
            .iter()
            .filter_map(|f| {
                if f.resolved {
                    Some((f.name.clone(), f.value.clone().unwrap_or_default()))
                } else {
                    None
                }
            })
            .collect();

        let tri_state = if outcome.undetermined {
            PredicateOutcomeState::Undetermined
        } else if outcome.matched {
            PredicateOutcomeState::Matched
        } else {
            PredicateOutcomeState::NotMatched
        };

        PredicateState {
            predicate_id: outcome.predicate_id.clone(),
            outcome: tri_state,
            missing_facts: outcome.missing_facts.clone(),
            resolved_facts,
            stage: Stage::from_engine_str(&format!("{:?}", predicate.stage))
                .unwrap_or(Stage::Shadow),
            tier: format!("{:?}", predicate.tier),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> digger_evidence::Finding {
        digger_evidence::Finding {
            finding_id: "f-test-1".into(),
            rule_id: "access_control".into(),
            severity: "high".into(),
            confidence_label: "experimental".into(),
            locations: vec![digger_evidence::Location {
                file: "StaxLPStaking.sol".into(),
                line_start: Some(42),
                line_end: Some(60),
                symbol: Some("migrateStake".into()),
            }],
            evidence_refs: vec!["ev-1".into(), "ev-2".into()],
            repro_ref: None,
        }
    }

    #[test]
    fn test_finding_view_from_engine() {
        let f = sample_finding();
        let view = FindingView::from_engine(&f, "Shadow", "migrateStake lacks auth check").unwrap();
        assert_eq!(view.finding_id, "f-test-1");
        assert_eq!(view.severity, Severity::High);
        assert_eq!(view.confidence, Confidence::Experimental);
        assert_eq!(view.stage, Stage::Shadow);
        assert_eq!(view.locations.len(), 1);
        assert_eq!(view.evidence_ids, vec!["ev-1", "ev-2"]);
    }

    #[test]
    fn test_l51_confidence_required() {
        // Invalid severity string must fail at construction
        let mut f = sample_finding();
        f.severity = "banana".into();
        assert!(FindingView::from_engine(&f, "Shadow", "test").is_err());
        assert!(FindingView::from_engine(&f, "Shadow", "test")
            .unwrap_err()
            .to_string()
            .contains("unknown severity"));

        // Invalid confidence string must fail
        let mut f2 = sample_finding();
        f2.confidence_label = "banana".into();
        assert!(FindingView::from_engine(&f2, "Shadow", "test").is_err());
        assert!(FindingView::from_engine(&f2, "Shadow", "test")
            .unwrap_err()
            .to_string()
            .contains("unknown confidence"));

        // Invalid stage must fail (use a valid finding, not the banana-severity one)
        let f_valid = sample_finding();
        assert!(FindingView::from_engine(&f_valid, "Deployed", "test").is_err());
        assert!(FindingView::from_engine(&f_valid, "Deployed", "test")
            .unwrap_err()
            .to_string()
            .contains("unknown stage"));

        // Valid values must succeed
        assert!(FindingView::from_engine(&sample_finding(), "Shadow", "test").is_ok());
        assert!(FindingView::from_engine(&sample_finding(), "Advisory", "test").is_ok());
        assert!(FindingView::from_engine(&sample_finding(), "Armed", "test").is_ok());
    }

    #[test]
    fn test_l51_enums_make_invalid_unrepresentable() {
        // Deserialize with invalid severity → must fail
        let bad_json = r#"{"finding_id":"x","rule_id":"r","severity":"INVALID","confidence":"experimental","stage":"shadow","summary":"","locations":[],"evidence_ids":[]}"#;
        assert!(serde_json::from_str::<FindingView>(bad_json).is_err());

        // Deserialize with invalid confidence → must fail
        let bad_json2 = r#"{"finding_id":"x","rule_id":"r","severity":"high","confidence":"INVALID","stage":"shadow","summary":"","locations":[],"evidence_ids":[]}"#;
        assert!(serde_json::from_str::<FindingView>(bad_json2).is_err());

        // Deserialize with invalid stage → must fail
        let bad_json3 = r#"{"finding_id":"x","rule_id":"r","severity":"high","confidence":"experimental","stage":"INVALID","summary":"","locations":[],"evidence_ids":[]}"#;
        assert!(serde_json::from_str::<FindingView>(bad_json3).is_err());

        // Valid values must deserialize
        let good_json = r#"{"finding_id":"x","rule_id":"r","severity":"high","confidence":"experimental","stage":"shadow","summary":"","locations":[],"evidence_ids":[]}"#;
        assert!(serde_json::from_str::<FindingView>(good_json).is_ok());
    }

    #[test]
    fn test_l51_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_l51_confidence_ordering() {
        assert!(Confidence::Experimental < Confidence::Graduated);
    }

    #[test]
    fn test_l51_stage_ordering() {
        assert!(Stage::Shadow < Stage::Advisory);
        assert!(Stage::Advisory < Stage::Armed);
    }

    #[test]
    fn test_l51_roundtrip_serialization() {
        let f = sample_finding();
        let view = FindingView::from_engine(&f, "Shadow", "migrateStake lacks auth").unwrap();

        let json = serde_json::to_string(&view).unwrap();
        let deserialized: FindingView = serde_json::from_str(&json).unwrap();
        assert_eq!(view, deserialized);

        // Enum labels in JSON
        assert!(json.contains("\"severity\":\"high\""));
        assert!(json.contains("\"confidence\":\"experimental\""));
        assert!(json.contains("\"stage\":\"shadow\""));
    }

    #[test]
    fn test_predicate_state_undetermined_preserved() {
        let outcome = digger_evidence::PredicateOutcome {
            predicate_id: "pred-test".into(),
            matched: false,
            undetermined: true,
            missing_facts: vec!["account_owner_mismatch".into()],
            resolved_facts: vec![],
            tier: digger_evidence::PredicateTier::TierA,
        };
        let predicate = digger_evidence::ExploitPredicate {
            id: "pred-test".into(),
            name: "Test".into(),
            rule_id: "access_control".into(),
            conditions: vec![digger_evidence::PredicateCondition {
                fact_name: "account_owner_mismatch".into(),
                expected: Some("mismatch".into()),
            }],
            stage: digger_evidence::PredicateStage::Shadow,
            tier: digger_evidence::PredicateTier::TierA,
        };

        let state = PredicateState::from_engine(&outcome, &predicate);
        assert_eq!(state.outcome, PredicateOutcomeState::Undetermined);
        assert_eq!(state.missing_facts, vec!["account_owner_mismatch"]);

        // Round-trip: undetermined survives serialization
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: PredicateState = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.outcome,
            PredicateOutcomeState::Undetermined,
            "undetermined must survive JSON round-trip"
        );
    }

    #[test]
    fn test_predicate_state_matched_and_not_matched() {
        // Matched
        let outcome_m = digger_evidence::PredicateOutcome {
            predicate_id: "p1".into(),
            matched: true,
            undetermined: false,
            missing_facts: vec![],
            resolved_facts: vec![digger_evidence::PredicateFact {
                name: "caller_is_not_authority".into(),
                resolved: true,
                value: Some("unauthorized".into()),
            }],
            tier: digger_evidence::PredicateTier::TierA,
        };
        let predicate = digger_evidence::ExploitPredicate {
            id: "p1".into(),
            name: "Test".into(),
            rule_id: "access_control".into(),
            conditions: vec![],
            stage: digger_evidence::PredicateStage::Shadow,
            tier: digger_evidence::PredicateTier::TierA,
        };
        let state = PredicateState::from_engine(&outcome_m, &predicate);
        assert_eq!(state.outcome, PredicateOutcomeState::Matched);

        // Not matched
        let outcome_n = digger_evidence::PredicateOutcome {
            predicate_id: "p2".into(),
            matched: false,
            undetermined: false,
            missing_facts: vec![],
            resolved_facts: vec![],
            tier: digger_evidence::PredicateTier::TierA,
        };
        let state2 = PredicateState::from_engine(&outcome_n, &predicate);
        assert_eq!(state2.outcome, PredicateOutcomeState::NotMatched);
    }

    #[test]
    fn test_predicate_tri_state_serialization() {
        // The matched+undetermined contradiction is unrepresentable at type level
        for outcome_state in &[
            PredicateOutcomeState::Matched,
            PredicateOutcomeState::NotMatched,
            PredicateOutcomeState::Undetermined,
        ] {
            let json = serde_json::to_string(outcome_state).unwrap();
            let deserialized: PredicateOutcomeState = serde_json::from_str(&json).unwrap();
            assert_eq!(*outcome_state, deserialized);
        }
    }

    #[test]
    fn test_location_view_from_engine() {
        let loc = digger_evidence::Location {
            file: "test.sol".into(),
            line_start: Some(10),
            line_end: Some(20),
            symbol: Some("foo".into()),
        };
        let view = LocationView::from_engine(&loc);
        assert_eq!(view.file, "test.sol");
        assert_eq!(view.line_start, Some(10));
        assert_eq!(view.symbol, Some("foo".into()));
    }
}
