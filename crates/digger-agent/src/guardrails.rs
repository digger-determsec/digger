use crate::contract::*;
use serde::{Deserialize, Serialize};

/// An assistant's structured claims about a scan result.
///
/// Every finding claim must carry typed severity/confidence/stage enums.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantClaim {
    pub scan_id: String,
    pub claimed_findings: Vec<FindingClaim>,
    pub prose: Option<String>,
}

/// A single finding claim within an AssistantClaim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingClaim {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub stage: Stage,
    pub locations: Vec<LocationView>,
    pub exploit_status: ExploitStatus,
    pub claim_text: String,
}

/// Validation report: pass/fail + deterministic violations + heuristic warnings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationReport {
    pub pass: bool,
    pub violations: Vec<Violation>,
    pub warnings: Vec<Warning>,
}

/// A deterministic violation — proves the assistant lied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Violation {
    pub code: ViolationCode,
    pub finding_id: Option<String>,
    pub expected: String,
    pub actual: String,
    pub message: String,
}

/// A heuristic warning — non-authoritative, never affects pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

/// Deterministic violation codes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ViolationCode {
    /// Claimed finding_id not present in the scan.
    UnknownFinding,
    /// Claimed severity higher than engine severity.
    SeverityUpgraded,
    /// Claimed confidence or stage stronger than engine's.
    ConfidencePromoted,
    /// A cited location not in the finding's evidence locations.
    LocationNotInEvidence,
    /// exploit_status=Confirmed when engine state is not confirmed.
    UnsupportedExploitConfirmed,
    /// Claim asserts a positive finding where predicate is Undetermined.
    UndeterminedAsPositive,
    /// Claimed rule_id does not match the engine's rule_id for that finding.
    RuleIdMismatch,
}

impl std::fmt::Display for ViolationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFinding => write!(f, "UNKNOWN_FINDING"),
            Self::SeverityUpgraded => write!(f, "SEVERITY_UPGRADED"),
            Self::ConfidencePromoted => write!(f, "CONFIDENCE_PROMOTED"),
            Self::LocationNotInEvidence => write!(f, "LOCATION_NOT_IN_EVIDENCE"),
            Self::UnsupportedExploitConfirmed => write!(f, "UNSUPPORTED_EXPLOIT_CONFIRMED"),
            Self::UndeterminedAsPositive => write!(f, "UNDETERMINED_AS_POSITIVE"),
            Self::RuleIdMismatch => write!(f, "RULE_ID_MISMATCH"),
        }
    }
}

/// Scan context: the ground truth from the engine that claims are validated against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanContext {
    pub scan_id: String,
    pub findings: Vec<FindingView>,
    pub predicate_states: Vec<PredicateState>,
}

/// Deterministic validator: given an AssistantClaim + ScanContext,
/// catch the LLM lying about findings.
///
/// Checks are enum-ordered (not string-compared). Warnings are heuristic-only.
pub fn validate(claim: &AssistantClaim, ctx: &ScanContext) -> ValidationReport {
    let mut violations = Vec::new();
    let mut warnings = Vec::new();

    // Build lookup maps
    let findings_by_id: std::collections::BTreeMap<&str, &FindingView> = ctx
        .findings
        .iter()
        .map(|f| (f.finding_id.as_str(), f))
        .collect();

    let predicates_by_finding: std::collections::BTreeMap<&str, &PredicateState> = ctx
        .predicate_states
        .iter()
        .map(|p| {
            // Find the predicate's associated finding_id — for now, match by rule_id
            (p.predicate_id.as_str(), p)
        })
        .collect();

    for fc in &claim.claimed_findings {
        // 1. UNKNOWN_FINDING
        let engine_finding = match findings_by_id.get(fc.finding_id.as_str()) {
            Some(f) => *f,
            None => {
                violations.push(Violation {
                    code: ViolationCode::UnknownFinding,
                    finding_id: Some(fc.finding_id.clone()),
                    expected: "known finding_id".into(),
                    actual: fc.finding_id.clone(),
                    message: format!("finding_id '{}' not present in scan", fc.finding_id),
                });
                continue;
            }
        };

        // 2. RULE_ID_MISMATCH (exact equality)
        if fc.rule_id != engine_finding.rule_id {
            violations.push(Violation {
                code: ViolationCode::RuleIdMismatch,
                finding_id: Some(fc.finding_id.clone()),
                expected: engine_finding.rule_id.clone(),
                actual: fc.rule_id.clone(),
                message: format!(
                    "rule_id '{}' != engine rule_id '{}'",
                    fc.rule_id, engine_finding.rule_id
                ),
            });
        }

        // 3. SEVERITY_UPGRADED (enum ordering)
        if fc.severity > engine_finding.severity {
            violations.push(Violation {
                code: ViolationCode::SeverityUpgraded,
                finding_id: Some(fc.finding_id.clone()),
                expected: engine_finding.severity.to_string(),
                actual: fc.severity.to_string(),
                message: format!(
                    "severity {} > engine severity {}",
                    fc.severity, engine_finding.severity
                ),
            });
        }

        // 3. CONFIDENCE_PROMOTED (enum ordering)
        if fc.confidence > engine_finding.confidence {
            violations.push(Violation {
                code: ViolationCode::ConfidencePromoted,
                finding_id: Some(fc.finding_id.clone()),
                expected: engine_finding.confidence.to_string(),
                actual: fc.confidence.to_string(),
                message: format!(
                    "confidence {} > engine confidence {}",
                    fc.confidence, engine_finding.confidence
                ),
            });
        }
        if fc.stage > engine_finding.stage {
            violations.push(Violation {
                code: ViolationCode::ConfidencePromoted,
                finding_id: Some(fc.finding_id.clone()),
                expected: engine_finding.stage.to_string(),
                actual: fc.stage.to_string(),
                message: format!("stage {} > engine stage {}", fc.stage, engine_finding.stage),
            });
        }

        // 4. LOCATION_NOT_IN_EVIDENCE
        let engine_locations: std::collections::BTreeSet<&str> = engine_finding
            .locations
            .iter()
            .map(|l| l.file.as_str())
            .collect();
        for claimed_loc in &fc.locations {
            if !engine_locations.contains(claimed_loc.file.as_str()) {
                violations.push(Violation {
                    code: ViolationCode::LocationNotInEvidence,
                    finding_id: Some(fc.finding_id.clone()),
                    expected: format!(
                        "location in {:?}",
                        engine_finding
                            .locations
                            .iter()
                            .map(|l| l.file.as_str())
                            .collect::<Vec<_>>()
                    ),
                    actual: claimed_loc.file.clone(),
                    message: format!(
                        "location '{}' not in finding's evidence locations",
                        claimed_loc.file
                    ),
                });
            }
        }

        // 5. UNSUPPORTED_EXPLOIT_CONFIRMED
        // Current corpus: ALL findings are Shadow/experimental → Confirmed is ALWAYS a violation
        if fc.exploit_status == ExploitStatus::Confirmed
            && (engine_finding.stage == Stage::Shadow
                || engine_finding.confidence == Confidence::Experimental)
        {
            violations.push(Violation {
                code: ViolationCode::UnsupportedExploitConfirmed,
                finding_id: Some(fc.finding_id.clone()),
                expected: "exploit_status != Confirmed (engine is Shadow/experimental)".into(),
                actual: "Confirmed".into(),
                message: format!(
                    "exploit_status=Confirmed but engine finding is {}/{}",
                    engine_finding.stage, engine_finding.confidence
                ),
            });
        }

        // 6. UNDETERMINED_AS_POSITIVE
        // Check if any predicate for this finding's rule is undetermined
        // and the claim asserts a positive (matched/exploited)
        for pred_state in predicates_by_finding.values() {
            if pred_state.outcome == PredicateOutcomeState::Undetermined
                && fc.exploit_status != ExploitStatus::None
            {
                violations.push(Violation {
                    code: ViolationCode::UndeterminedAsPositive,
                    finding_id: Some(fc.finding_id.clone()),
                    expected: "predicate outcome respected as Undetermined".into(),
                    actual: format!("claim asserts {:?}", fc.exploit_status),
                    message: "claim asserts positive finding where predicate is Undetermined"
                        .into(),
                });
            }
        }
    }

    // 7. HEURISTIC: scan prose for absolute claims
    if let Some(ref prose) = claim.prose {
        let lower = prose.to_lowercase();
        let absolutes = ["guaranteed", "definitely exploitable", "100%", "certain"];
        for word in &absolutes {
            if lower.contains(word) {
                warnings.push(Warning {
                    code: "PROSE_ABSOLUTE".into(),
                    message: format!(
                        "prose contains absolute claim '{}' — non-authoritative lint",
                        word
                    ),
                });
            }
        }
    }

    ValidationReport {
        pass: violations.is_empty(),
        violations,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn engine_finding(
        id: &str,
        severity: Severity,
        confidence: Confidence,
        stage: Stage,
    ) -> FindingView {
        FindingView {
            finding_id: id.into(),
            rule_id: "access_control".into(),
            severity,
            confidence,
            stage,
            summary: "test".into(),
            locations: vec![LocationView {
                file: "target.sol".into(),
                line_start: Some(10),
                line_end: Some(20),
                symbol: Some("migrateStake".into()),
            }],
            evidence_ids: vec!["ev-1".into()],
        }
    }

    fn engine_predicate_state(pred_id: &str, outcome: PredicateOutcomeState) -> PredicateState {
        let is_undetermined = outcome == PredicateOutcomeState::Undetermined;
        PredicateState {
            predicate_id: pred_id.into(),
            outcome,
            missing_facts: if is_undetermined {
                vec!["account_owner_mismatch".into()]
            } else {
                vec![]
            },
            resolved_facts: BTreeMap::new(),
            stage: Stage::Shadow,
            tier: "TierA".into(),
        }
    }

    fn base_ctx() -> ScanContext {
        ScanContext {
            scan_id: "scan-1".into(),
            findings: vec![engine_finding(
                "f-1",
                Severity::High,
                Confidence::Experimental,
                Stage::Shadow,
            )],
            predicate_states: vec![engine_predicate_state(
                "pred-1",
                PredicateOutcomeState::Undetermined,
            )],
        }
    }

    fn clean_claim() -> AssistantClaim {
        AssistantClaim {
            scan_id: "scan-1".into(),
            claimed_findings: vec![FindingClaim {
                finding_id: "f-1".into(),
                rule_id: "access_control".into(),
                severity: Severity::High,
                confidence: Confidence::Experimental,
                stage: Stage::Shadow,
                locations: vec![LocationView {
                    file: "target.sol".into(),
                    line_start: Some(10),
                    line_end: Some(20),
                    symbol: Some("migrateStake".into()),
                }],
                exploit_status: ExploitStatus::None,
                claim_text: "migrateStake lacks auth".into(),
            }],
            prose: None,
        }
    }

    #[test]
    fn test_clean_claim_passes() {
        let report = validate(&clean_claim(), &base_ctx());
        assert!(
            report.pass,
            "clean claim should pass: {:?}",
            report.violations
        );
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_unknown_finding() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].finding_id = "f-nonexistent".into();
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::UnknownFinding));
    }

    #[test]
    fn test_severity_upgraded_caught() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].severity = Severity::Critical; // engine is High
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::SeverityUpgraded));
    }

    #[test]
    fn test_severity_downgrade_passes() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].severity = Severity::Medium; // engine is High — downgrade OK
        let report = validate(&claim, &base_ctx());
        assert!(report.pass);
    }

    #[test]
    fn test_confidence_promoted_caught() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].confidence = Confidence::Graduated; // engine is Experimental
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::ConfidencePromoted));
    }

    #[test]
    fn test_stage_promoted_caught() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].stage = Stage::Armed; // engine is Shadow
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::ConfidencePromoted));
    }

    #[test]
    fn test_location_not_in_evidence() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].locations = vec![LocationView {
            file: "wrong_file.sol".into(),
            line_start: None,
            line_end: None,
            symbol: None,
        }];
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::LocationNotInEvidence));
    }

    #[test]
    fn test_unsupported_exploit_confirmed() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].exploit_status = ExploitStatus::Confirmed;
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::UnsupportedExploitConfirmed));
    }

    #[test]
    fn test_undetermined_as_positive() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].exploit_status = ExploitStatus::Suspected; // positive claim
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::UndeterminedAsPositive));
    }

    #[test]
    fn test_prose_absolute_yields_warning_not_violation() {
        let mut claim = clean_claim();
        claim.prose = Some("This is definitely exploitable with 100% certainty.".into());
        let report = validate(&claim, &base_ctx());
        assert!(report.pass, "prose absolute must NOT affect pass");
        assert!(!report.warnings.is_empty());
        assert!(report.warnings.iter().any(|w| w.code == "PROSE_ABSOLUTE"));
    }

    #[test]
    fn test_prose_clean_no_warnings() {
        let mut claim = clean_claim();
        claim.prose = Some("This finding was identified by the deterministic engine.".into());
        let report = validate(&claim, &base_ctx());
        assert!(report.pass);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn test_multiple_violations() {
        // Use a valid finding_id so we don't hit UnknownFinding (which skips via continue),
        // then stack multiple other violations.
        let mut claim = clean_claim();
        claim.claimed_findings[0].severity = Severity::Critical; // upgrade from High
        claim.claimed_findings[0].confidence = Confidence::Graduated; // upgrade from Experimental
        claim.claimed_findings[0].stage = Stage::Armed; // upgrade from Shadow
        claim.claimed_findings[0].exploit_status = ExploitStatus::Confirmed; // unsupported
        claim.claimed_findings[0].locations = vec![LocationView {
            file: "wrong.sol".into(),
            line_start: None,
            line_end: None,
            symbol: None,
        }];
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report.violations.len() >= 3);
        // Verify we got multiple distinct violation types
        let codes: std::collections::BTreeSet<_> =
            report.violations.iter().map(|v| v.code.clone()).collect();
        assert!(codes.contains(&ViolationCode::SeverityUpgraded));
        assert!(codes.contains(&ViolationCode::ConfidencePromoted));
        assert!(codes.contains(&ViolationCode::UnsupportedExploitConfirmed));
    }

    #[test]
    fn test_exploit_status_suspected_with_undetermined_predicate() {
        // Suspected is NOT a violation on its own — it's the Confirmed that triggers
        // UNSUPPORTED_EXPLOIT_CONFIRMED. But with an undetermined predicate, it triggers
        // UNDETERMINED_AS_POSITIVE.
        let mut claim = clean_claim();
        claim.claimed_findings[0].exploit_status = ExploitStatus::Suspected;
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::UndeterminedAsPositive));
    }

    #[test]
    fn test_exploit_status_none_passes_with_undetermined() {
        // ExploitStatus::None with undetermined predicate should pass
        let report = validate(&clean_claim(), &base_ctx());
        assert!(report.pass);
    }

    #[test]
    fn test_severity_ordering_caught() {
        // Low claim against Critical engine = downgrade (passes)
        let ctx = ScanContext {
            scan_id: "scan-1".into(),
            findings: vec![engine_finding(
                "f-1",
                Severity::Critical,
                Confidence::Experimental,
                Stage::Shadow,
            )],
            predicate_states: vec![],
        };
        let mut claim = clean_claim();
        claim.claimed_findings[0].severity = Severity::High; // downgrade from Critical — OK
        let report = validate(&claim, &ctx);
        assert!(report.pass, "downgrade should pass");

        // Now upgrade: High claim against Medium engine
        let ctx2 = ScanContext {
            scan_id: "scan-1".into(),
            findings: vec![engine_finding(
                "f-1",
                Severity::Medium,
                Confidence::Experimental,
                Stage::Shadow,
            )],
            predicate_states: vec![],
        };
        let mut claim2 = clean_claim();
        claim2.claimed_findings[0].severity = Severity::High;
        let report2 = validate(&claim2, &ctx2);
        assert!(!report2.pass, "upgrade must be caught");
        assert!(report2
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::SeverityUpgraded));
    }

    #[test]
    fn test_rule_id_mismatch_caught() {
        let mut claim = clean_claim();
        claim.claimed_findings[0].rule_id = "unchecked_account_owner".into();
        let report = validate(&claim, &base_ctx());
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::RuleIdMismatch));
    }

    #[test]
    fn test_rule_id_correct_passes() {
        let claim = clean_claim();
        assert_eq!(claim.claimed_findings[0].rule_id, "access_control");
        let report = validate(&claim, &base_ctx());
        assert!(report.pass, "correct rule_id should pass");
    }
}
