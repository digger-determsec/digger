use digger_agent::contract::*;
use digger_agent::guardrails::*;
use serde::{Deserialize, Serialize};

/// Tool definition for MCP discovery. Each tool declares its name,
/// description, readOnly flag, and input/output JSON schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(rename = "readOnlyHint")]
    pub read_only_hint: bool,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
}

/// Returns the 4 MCP tool definitions with their JSON schemas.
pub fn list_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "list_findings".into(),
            description: "List all findings in a scan with their typed labels (severity, confidence, stage). Read-only.".into(),
            read_only_hint: true,
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "scan_id": { "type": "string", "description": "The scan ID to query" }
                },
                "required": ["scan_id"]
            }),
            output_schema: serde_json::json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": { "type": "string" },
                        "rule_id": { "type": "string" },
                        "severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
                        "confidence": { "type": "string", "enum": ["experimental", "graduated"] },
                        "stage": { "type": "string", "enum": ["shadow", "advisory", "armed"] },
                        "summary": { "type": "string" },
                        "locations": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "file": { "type": "string" },
                                    "line_start": { "type": ["integer", "null"] },
                                    "line_end": { "type": ["integer", "null"] },
                                    "symbol": { "type": ["string", "null"] }
                                }
                            }
                        },
                        "evidence_ids": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["finding_id", "rule_id", "severity", "confidence", "stage"]
                }
            }),
        },
        ToolDefinition {
            name: "get_evidence".into(),
            description: "Get evidence bundles for a specific finding. Read-only.".into(),
            read_only_hint: true,
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "finding_id": { "type": "string", "description": "The finding ID to get evidence for" }
                },
                "required": ["finding_id"]
            }),
            output_schema: serde_json::json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "evidence_id": { "type": "string" },
                        "finding_id": { "type": "string" },
                        "kind": { "type": "string" },
                        "locations": { "type": "array" },
                        "raw_refs": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["evidence_id", "finding_id", "kind"]
                }
            }),
        },
        ToolDefinition {
            name: "get_explanation_context".into(),
            description: "Get explanation ingredients for a finding (NO natural-language generation). Read-only.".into(),
            read_only_hint: true,
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "finding_id": { "type": "string", "description": "The finding ID to explain" }
                },
                "required": ["finding_id"]
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "finding_id": { "type": "string" },
                    "rule_id": { "type": "string" },
                    "severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
                    "confidence": { "type": "string", "enum": ["experimental", "graduated"] },
                    "stage": { "type": "string", "enum": ["shadow", "advisory", "armed"] },
                    "summary": { "type": "string" },
                    "evidence": { "type": "array" },
                    "locations": { "type": "array" },
                    "attack_shape": { "type": "string" },
                    "remediation_hints": { "type": "array", "items": { "type": "string" } },
                    "precedents": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["finding_id", "rule_id", "severity", "confidence", "stage"]
            }),
        },
        ToolDefinition {
            name: "validate_assistant_output".into(),
            description: "Deterministically validate an assistant's structured claims against engine truth. Pure function, no side effects.".into(),
            read_only_hint: true,
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "scan_id": { "type": "string" },
                    "claimed_findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "finding_id": { "type": "string" },
                                "rule_id": { "type": "string" },
                                "severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
                                "confidence": { "type": "string", "enum": ["experimental", "graduated"] },
                                "stage": { "type": "string", "enum": ["shadow", "advisory", "armed"] },
                                "locations": { "type": "array" },
                                "exploit_status": { "type": "string", "enum": ["none", "suspected", "confirmed"] },
                                "claim_text": { "type": "string" }
                            },
                            "required": ["finding_id", "rule_id", "severity", "confidence", "stage", "exploit_status", "claim_text"]
                        }
                    },
                    "prose": { "type": ["string", "null"] }
                },
                "required": ["scan_id", "claimed_findings"]
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "pass": { "type": "boolean" },
                    "violations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "code": { "type": "string" },
                                "finding_id": { "type": ["string", "null"] },
                                "expected": { "type": "string" },
                                "actual": { "type": "string" },
                                "message": { "type": "string" }
                            }
                        }
                    },
                    "warnings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "code": { "type": "string" },
                                "message": { "type": "string" }
                            }
                        }
                    }
                },
                "required": ["pass", "violations", "warnings"]
            }),
        },
    ]
}

// ── Tool implementations ──────────────────────────────────────

/// Tool: list_findings — returns all FindingViews from a scan context.
pub fn tool_list_findings(ctx: &ScanContext, _scan_id: &str) -> Vec<FindingView> {
    ctx.findings.clone()
}

/// Tool: get_evidence — returns EvidenceBundleViews for a specific finding.
pub fn tool_get_evidence(ctx: &ScanContext, finding_id: &str) -> Vec<EvidenceBundleView> {
    ctx.findings
        .iter()
        .filter(|f| f.finding_id == finding_id)
        .map(|f| {
            EvidenceBundleView::from_engine(
                &f.evidence_ids.first().cloned().unwrap_or_default(),
                &f.finding_id,
                "engine_output",
                f.locations.clone(),
                f.evidence_ids.clone(),
            )
        })
        .collect()
}

/// Tool: get_explanation_context — builds explanation ingredients for a finding.
pub fn tool_get_explanation_context(
    ctx: &ScanContext,
    finding_id: &str,
) -> Option<ExplanationContext> {
    let finding = ctx.findings.iter().find(|f| f.finding_id == finding_id)?;

    let _predicate_state = ctx
        .predicate_states
        .iter()
        .find(|p| p.predicate_id.contains(&finding.rule_id))
        .cloned();

    let mut precedents = Vec::new();
    let mut remediation_hints = Vec::new();

    match finding.rule_id.as_str() {
        "access_control" => {
            precedents.push("TempleDAO StaxLPStaking migrateStake (2022-10-11, $3.1M loss)".into());
            remediation_hints.push(
                "Add role-based access control or signer validation to migration functions".into(),
            );
            remediation_hints.push("Use a timelock or multi-sig for privileged operations".into());
        }
        "unchecked_account_owner" => {
            precedents.push("Cashio CASH mint (2022-03-23, $52M loss)".into());
            remediation_hints.push(
                "Validate account ownership against expected program before deserialization".into(),
            );
        }
        _ => {}
    }

    let attack_shape = match finding.rule_id.as_str() {
        "access_control" => "Attacker calls a privileged function (migration, upgrade, admin) without authorization, draining protocol funds."
            .into(),
        "unchecked_account_owner" => "Attacker passes a counterfeit account that deserializes successfully but is owned by attacker-controlled program, allowing unauthorized state modification."
            .into(),
        _ => format!("Pattern for rule '{}': review authorization and ownership checks.", finding.rule_id),
    };

    Some(ExplanationContext {
        finding_id: finding.finding_id.clone(),
        rule_id: finding.rule_id.clone(),
        severity: finding.severity.clone(),
        confidence: finding.confidence.clone(),
        stage: finding.stage.clone(),
        summary: finding.summary.clone(),
        evidence: vec![EvidenceBundleView::from_engine(
            &finding.evidence_ids.first().cloned().unwrap_or_default(),
            &finding.finding_id,
            "engine_output",
            finding.locations.clone(),
            finding.evidence_ids.clone(),
        )],
        locations: finding.locations.clone(),
        attack_shape,
        remediation_hints,
        precedents,
    })
}

/// Tool: validate_assistant_output — deterministic validation.
pub fn tool_validate_assistant_output(
    claim: &AssistantClaim,
    ctx: &ScanContext,
) -> ValidationReport {
    validate(claim, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_finding_view() -> FindingView {
        FindingView {
            finding_id: "f-1".into(),
            rule_id: "access_control".into(),
            severity: Severity::High,
            confidence: Confidence::Experimental,
            stage: Stage::Shadow,
            summary: "migrateStake lacks auth check".into(),
            locations: vec![LocationView {
                file: "StaxLPStaking.sol".into(),
                line_start: Some(42),
                line_end: Some(60),
                symbol: Some("migrateStake".into()),
            }],
            evidence_ids: vec!["ev-1".into()],
        }
    }

    fn test_scan_ctx() -> ScanContext {
        ScanContext {
            scan_id: "scan-test".into(),
            findings: vec![test_finding_view()],
            predicate_states: vec![PredicateState {
                predicate_id: "pred-access-control-1".into(),
                outcome: PredicateOutcomeState::Undetermined,
                missing_facts: vec!["account_owner_mismatch".into()],
                resolved_facts: BTreeMap::new(),
                stage: Stage::Shadow,
                tier: "TierA".into(),
            }],
        }
    }

    #[test]
    fn test_tool_listing_returns_4_tools() {
        let tools = list_tools();
        assert_eq!(tools.len(), 4);

        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"list_findings"));
        assert!(names.contains(&"get_evidence"));
        assert!(names.contains(&"get_explanation_context"));
        assert!(names.contains(&"validate_assistant_output"));
    }

    #[test]
    fn test_all_read_tools_are_read_only() {
        let tools = list_tools();
        for tool in &tools {
            assert!(
                tool.read_only_hint,
                "tool {} must have readOnlyHint=true",
                tool.name
            );
        }
    }

    #[test]
    fn test_list_findings_returns_expected_shape() {
        let ctx = test_scan_ctx();
        let findings = tool_list_findings(&ctx, "scan-test");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_id, "f-1");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Experimental);
        assert_eq!(findings[0].stage, Stage::Shadow);

        // Verify JSON round-trip
        let json = serde_json::to_string(&findings).unwrap();
        let deserialized: Vec<FindingView> = serde_json::from_str(&json).unwrap();
        assert_eq!(findings, deserialized);
    }

    #[test]
    fn test_get_evidence_returns_expected_shape() {
        let ctx = test_scan_ctx();
        let evidence = tool_get_evidence(&ctx, "f-1");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].finding_id, "f-1");
        assert_eq!(evidence[0].kind, "engine_output");
    }

    #[test]
    fn test_get_explanation_context_returns_expected_shape() {
        let ctx = test_scan_ctx();
        let context = tool_get_explanation_context(&ctx, "f-1");
        assert!(context.is_some());
        let ctx = context.unwrap();
        assert_eq!(ctx.finding_id, "f-1");
        assert_eq!(ctx.rule_id, "access_control");
        assert_eq!(ctx.severity, Severity::High);
        assert_eq!(ctx.confidence, Confidence::Experimental);
        assert_eq!(ctx.stage, Stage::Shadow);
        assert!(!ctx.attack_shape.is_empty());
        assert!(!ctx.precedents.is_empty());
        assert!(!ctx.remediation_hints.is_empty());
    }

    #[test]
    fn test_validate_clean_claim_passes() {
        let ctx = test_scan_ctx();
        let claim = AssistantClaim {
            scan_id: "scan-test".into(),
            claimed_findings: vec![FindingClaim {
                finding_id: "f-1".into(),
                rule_id: "access_control".into(),
                severity: Severity::High,
                confidence: Confidence::Experimental,
                stage: Stage::Shadow,
                locations: vec![LocationView {
                    file: "StaxLPStaking.sol".into(),
                    line_start: Some(42),
                    line_end: Some(60),
                    symbol: Some("migrateStake".into()),
                }],
                exploit_status: ExploitStatus::None,
                claim_text: "migrateStake lacks auth".into(),
            }],
            prose: None,
        };
        let report = tool_validate_assistant_output(&claim, &ctx);
        assert!(
            report.pass,
            "clean claim should pass: {:?}",
            report.violations
        );
    }

    #[test]
    fn test_validate_bad_claim_returns_wrong_code() {
        let ctx = test_scan_ctx();
        let claim = AssistantClaim {
            scan_id: "scan-test".into(),
            claimed_findings: vec![FindingClaim {
                finding_id: "f-nonexistent".into(),
                rule_id: "access_control".into(),
                severity: Severity::Critical,
                confidence: Confidence::Graduated,
                stage: Stage::Armed,
                locations: vec![],
                exploit_status: ExploitStatus::Confirmed,
                claim_text: "definitely exploitable".into(),
            }],
            prose: Some("This is 100% guaranteed exploitable.".into()),
        };
        let report = tool_validate_assistant_output(&claim, &ctx);
        assert!(!report.pass);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::UnknownFinding));
        // Prose absolute should yield a warning too
        assert!(!report.warnings.is_empty());
    }

    #[test]
    fn test_undetermined_predicate_through_tool_boundary() {
        let ctx = test_scan_ctx();
        // Verify the undetermined predicate state serializes correctly
        let json = serde_json::to_string(&ctx.predicate_states).unwrap();
        let deserialized: Vec<PredicateState> = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized[0].outcome,
            PredicateOutcomeState::Undetermined,
            "undetermined must survive tool boundary serialization"
        );
    }

    #[test]
    fn test_tool_schemas_are_valid_json() {
        let tools = list_tools();
        for tool in &tools {
            // Input and output schemas must be valid JSON
            assert!(tool.input_schema.is_object() || tool.input_schema.is_array());
            assert!(tool.output_schema.is_object() || tool.output_schema.is_array());
        }
    }

    #[test]
    fn test_severity_enums_on_wire() {
        let finding = test_finding_view();
        let json = serde_json::to_string(&finding).unwrap();

        // Verify enum labels are human-readable on the wire
        assert!(json.contains("\"severity\":\"high\""));
        assert!(json.contains("\"confidence\":\"experimental\""));
        assert!(json.contains("\"stage\":\"shadow\""));
        assert!(json.contains("\"finding_id\":\"f-1\""));

        // Deserialize back
        let deserialized: FindingView = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.severity, Severity::High);
        assert_eq!(deserialized.confidence, Confidence::Experimental);
        assert_eq!(deserialized.stage, Stage::Shadow);
    }

    // ── Track I: engine-as-truth boundary tests ──────────────

    /// Build a claim that exactly mirrors the engine's truth for f-1.
    /// All fields pulled off `test_scan_ctx().findings[0]` so helper can't drift.
    fn engine_true_claim() -> AssistantClaim {
        let ctx = test_scan_ctx();
        let f = &ctx.findings[0];
        AssistantClaim {
            scan_id: ctx.scan_id.clone(),
            claimed_findings: vec![FindingClaim {
                finding_id: f.finding_id.clone(),
                rule_id: f.rule_id.clone(),
                severity: f.severity.clone(),
                confidence: f.confidence.clone(),
                stage: f.stage.clone(),
                locations: f.locations.clone(),
                exploit_status: ExploitStatus::None,
                claim_text: "benign analysis text".into(),
            }],
            prose: Some("benign prose".into()),
        }
    }

    #[test]
    fn boundary_engine_true_claim_passes() {
        let claim = engine_true_claim();
        let ctx = test_scan_ctx();
        let report = validate(&claim, &ctx);
        assert!(
            report.pass,
            "engine-true claim must pass with zero violations, got: {:?}",
            report.violations
        );
        assert!(
            report.violations.is_empty(),
            "engine-true claim must have zero violations"
        );
    }

    #[test]
    fn boundary_confidence_promotion_is_rejected() {
        let ctx = test_scan_ctx();
        let baseline = validate(&engine_true_claim(), &ctx);
        assert!(
            baseline
                .violations
                .iter()
                .all(|v| v.code != ViolationCode::ConfidencePromoted),
            "baseline must NOT carry CONFIDENCE_PROMOTED"
        );

        let mut claim = engine_true_claim();
        claim.claimed_findings[0].confidence = Confidence::Graduated;
        let report = validate(&claim, &ctx);
        assert!(!report.pass);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == ViolationCode::ConfidencePromoted),
            "promoted confidence must trigger CONFIDENCE_PROMOTED, got: {:?}",
            report.violations
        );
    }

    #[test]
    fn boundary_stage_promotion_is_rejected() {
        let ctx = test_scan_ctx();
        let baseline = validate(&engine_true_claim(), &ctx);
        assert!(
            baseline
                .violations
                .iter()
                .all(|v| v.code != ViolationCode::ConfidencePromoted),
            "baseline must NOT carry CONFIDENCE_PROMOTED"
        );

        let mut claim = engine_true_claim();
        claim.claimed_findings[0].stage = Stage::Armed;
        let report = validate(&claim, &ctx);
        assert!(!report.pass);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == ViolationCode::ConfidencePromoted),
            "stage promotion must trigger CONFIDENCE_PROMOTED, got: {:?}",
            report.violations
        );
    }

    #[test]
    fn boundary_severity_upgrade_is_rejected() {
        let ctx = test_scan_ctx();
        let baseline = validate(&engine_true_claim(), &ctx);
        assert!(
            baseline
                .violations
                .iter()
                .all(|v| v.code != ViolationCode::SeverityUpgraded),
            "baseline must NOT carry SEVERITY_UPGRADED"
        );

        let mut claim = engine_true_claim();
        claim.claimed_findings[0].severity = Severity::Critical;
        let report = validate(&claim, &ctx);
        assert!(!report.pass);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == ViolationCode::SeverityUpgraded),
            "severity upgrade must trigger SEVERITY_UPGRADED, got: {:?}",
            report.violations
        );
    }

    #[test]
    fn boundary_confirmed_exploit_is_rejected() {
        let ctx = test_scan_ctx();
        let baseline = validate(&engine_true_claim(), &ctx);
        assert!(
            baseline
                .violations
                .iter()
                .all(|v| v.code != ViolationCode::UnsupportedExploitConfirmed),
            "baseline must NOT carry UNSUPPORTED_EXPLOIT_CONFIRMED"
        );

        let mut claim = engine_true_claim();
        claim.claimed_findings[0].exploit_status = ExploitStatus::Confirmed;
        let report = validate(&claim, &ctx);
        assert!(!report.pass);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == ViolationCode::UnsupportedExploitConfirmed),
            "confirmed exploit must trigger UNSUPPORTED_EXPLOIT_CONFIRMED, got: {:?}",
            report.violations
        );
    }

    #[test]
    fn boundary_caller_scan_id_cannot_inject_other_findings() {
        let ctx = test_scan_ctx();
        let baseline = validate(&engine_true_claim(), &ctx);
        assert!(
            baseline
                .violations
                .iter()
                .all(|v| v.code != ViolationCode::UnknownFinding),
            "baseline must NOT carry UNKNOWN_FINDING"
        );

        let mut claim = engine_true_claim();
        claim.claimed_findings[0].finding_id = "f-999".into();
        let report = validate(&claim, &ctx);
        assert!(!report.pass);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.code == ViolationCode::UnknownFinding),
            "fabricated finding_id must trigger UNKNOWN_FINDING, got: {:?}",
            report.violations
        );
    }

    #[test]
    fn boundary_read_tools_echo_engine_labels_only() {
        let ctx = test_scan_ctx();

        let findings = tool_list_findings(&ctx, &ctx.scan_id);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "read tool must echo engine severity"
        );
        assert_eq!(
            findings[0].confidence,
            Confidence::Experimental,
            "read tool must echo engine confidence"
        );
        assert_eq!(
            findings[0].stage,
            Stage::Shadow,
            "read tool must echo engine stage"
        );

        let explanation = tool_get_explanation_context(&ctx, "f-1").expect("f-1 exists");
        assert_eq!(
            explanation.severity,
            Severity::High,
            "explanation must echo engine severity"
        );
        assert_eq!(
            explanation.confidence,
            Confidence::Experimental,
            "explanation must echo engine confidence"
        );
        assert_eq!(
            explanation.stage,
            Stage::Shadow,
            "explanation must echo engine stage"
        );
    }
}
