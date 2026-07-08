/// Gen2 → legacy-shape compatibility shim (C3.4a).
///
/// Provides `analyze_compat(ir) -> Vec<CompatHypothesis>` which runs the Gen2
/// derivation engine and maps each structured `Hypothesis` into the flat legacy
/// shape (`kind: String`, `confidence: f32`, `evidence: Vec<String>`, etc.)
/// so consumers can switch engines without changing their data model.
///
/// This module is ADDITIVE — no existing code is modified.
use crate::derivation;
use crate::models::{GraphFact, Hypothesis, HypothesisEvidence, HypothesisType};
use digger_ir::{Edge, Severity, SystemIR};

/// Legacy-shaped hypothesis produced by the Gen2 engine via compatibility mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct CompatHypothesis {
    pub id: String,
    pub kind: String,
    pub severity: Severity,
    /// Deterministically derived from severity: Critical=0.95, High=0.8,
    /// Medium=0.6, Low=0.4, Info=0.2.
    pub confidence: f32,
    pub affected_function: String,
    pub evidence: Vec<String>,
    pub reasoning: String,
}

/// Map Gen2 `HypothesisType` → legacy kind string.
///
/// Uses the canonical legacy kind strings emitted by `digger-hypothesis-legacy`
/// rules. Where a Gen2 type has no exact legacy equivalent the variant's own
/// canonical name is used (these will be flagged in the C3.4a drift diagnostic).
pub fn kind_for(ty: &HypothesisType) -> &'static str {
    match ty {
        HypothesisType::ReentrancyCandidate => "ReentrancyRisk",
        HypothesisType::AuthorityBypassCandidate => "MissingAuthorityCheck",
        HypothesisType::CPITrustViolationCandidate => "CPIExternalCall",
        HypothesisType::StateCorruptionCandidate => "StateCorruption",
        HypothesisType::EconomicInvariantViolationCandidate => "EconomicInvariantViolation",
        HypothesisType::AdversarialPathCandidate => "AdversarialPath",
        HypothesisType::OracleManipulationCandidate => "OracleManipulation",
        HypothesisType::FlashLoanGovernanceCandidate => "FlashLoanGovernance",
        HypothesisType::MissingAccountConstraintCandidate => "MissingAccountConstraint",
        HypothesisType::UncheckedArithmeticCandidate => "UncheckedArithmetic",
        HypothesisType::PrecisionLossCandidate => "PrecisionLoss",
    }
}

/// Deterministic severity → confidence mapping (documented, stable).
pub(crate) fn confidence_for(severity: &Severity) -> f32 {
    match severity {
        Severity::Critical => 0.95,
        Severity::High => 0.8,
        Severity::Medium => 0.6,
        Severity::Low => 0.4,
        Severity::Info => 0.2,
    }
}

/// Render a single `HypothesisEvidence` into a deterministic plain-text string.
fn render_evidence(ev: &HypothesisEvidence) -> String {
    let functions = ev.involved_functions.join(", ");
    let facts: Vec<String> = ev.graph_facts.iter().map(render_graph_fact).collect();
    let facts_str = facts.join("; ");
    format!(
        "[{}] functions=[{}] facts=[{}]",
        ev.path_id, functions, facts_str
    )
}

fn render_graph_fact(fact: &GraphFact) -> String {
    format!("{}({}: {})", fact.fact_type, fact.function, fact.detail)
}

/// Run the Gen2 derivation engine and map every hypothesis to legacy shape.
///
/// For `AuthorityBypassCandidate`, the shim inspects the IR edges for each
/// function and emits the same set of legacy sub-kinds that
/// `digger-hypothesis-legacy::rules::authority` would emit. This is a
/// multi-kind expansion: legacy stacks kinds (not mutually exclusive).
///
/// Additionally, emits surface-risk kinds (ExternalCallRisk, StateMutationRisk,
/// MultipleStateWrites) directly from IR edges — these are NOT tied to Gen2
/// hypotheses but mirror legacy's independent rule modules.
pub fn analyze_compat(ir: &SystemIR) -> Vec<CompatHypothesis> {
    let result = derivation::derive(ir);
    let mut out = Vec::new();

    // 1. Gen2 hypotheses → legacy kinds (authority sub-kind expansion)
    for h in result.hypotheses {
        if h.hypothesis_type == HypothesisType::AuthorityBypassCandidate {
            let fn_name = &h.primary_function;
            let sub_kinds = authority_sub_kinds(ir, fn_name);
            for (kind, sev) in sub_kinds {
                let confidence = confidence_for(&sev);
                out.push(CompatHypothesis {
                    id: format!("{}-{}", h.id.0, normalize_kind(kind)),
                    kind: kind.to_string(),
                    severity: sev,
                    confidence,
                    affected_function: h.primary_function.clone(),
                    evidence: h.evidence.iter().map(render_evidence).collect(),
                    reasoning: h.structural_explanation.clone(),
                });
            }
        } else {
            out.push(hyp_to_compat(h));
        }
    }

    // 2. Surface-risk kinds from IR edges (mirror legacy rules/external, rules/state, rules/composition)
    // These are independent of Gen2 hypotheses and emit directly from edge evidence.
    out.extend(surface_risk_kinds(ir));

    out
}

/// Emit surface-risk kinds by inspecting IR edges directly, mirroring legacy's
/// rules/external.rs, rules/state.rs, and rules/composition.rs.
///
/// PRINCIPLED SUPPRESSION (precision-pass-1):
/// When a function already has a Critical or High severity hypothesis from the
/// authority/reentrancy analysis, demote surface-risk kinds for that function
/// to Info. This prevents the surface-risk enumeration from burying true
/// positives while preserving the information for uncovered functions.
fn surface_risk_kinds(ir: &SystemIR) -> Vec<CompatHypothesis> {
    let mut out = Vec::new();

    // Pre-compute which functions already have Critical/High hypotheses from
    // the authority and reentrancy analysis (built from edges).
    let high_coverage_fns = compute_high_coverage_fns(ir);

    // ── rules/external.rs: ExternalCallRisk per Edge::External ──
    for edge in &ir.edges {
        if let Edge::External(e) = edge {
            // Skip constructors — they necessarily make calls during init.
            if is_constructor(&e.function) {
                continue;
            }
            let severity = if high_coverage_fns.contains(&e.function) {
                Severity::Info
            } else if e.risk_flags.contains(&"cpi".to_string()) {
                Severity::High
            } else {
                Severity::Medium
            };
            let confidence = confidence_for(&severity);
            out.push(CompatHypothesis {
                id: format!("EXT-{}-{}", e.function, e.target),
                kind: "ExternalCallRisk".to_string(),
                severity,
                confidence,
                affected_function: e.function.clone(),
                evidence: e.risk_flags.clone(),
                reasoning: format!(
                    "Function '{}' has external dependency on '{}' — introduces trust boundary",
                    e.function, e.target
                ),
            });
        }
    }

    // ── rules/state.rs: StateMutationRisk per Edge::State write ──
    for edge in &ir.edges {
        if let Edge::State(s) = edge {
            if s.access == "write" {
                // Skip constructors.
                if is_constructor(&s.function) {
                    continue;
                }
                let has_authority = ir.edges.iter().any(|e| match e {
                    Edge::Authority(a) => a.function == s.function && a.check_type == "enforced",
                    _ => false,
                });

                let severity = if high_coverage_fns.contains(&s.function) {
                    Severity::Info
                } else if has_authority {
                    Severity::Low
                } else {
                    Severity::Medium
                };
                let confidence = confidence_for(&severity);

                out.push(CompatHypothesis {
                    id: format!("STATE-WRITE-{}-{}", s.function, s.state),
                    kind: "StateMutationRisk".to_string(),
                    severity,
                    confidence,
                    affected_function: s.function.clone(),
                    evidence: vec![
                        format!("Writes to state variable: {}", s.state),
                        if has_authority {
                            "Authority check present".into()
                        } else {
                            "No authority check detected".into()
                        },
                    ],
                    reasoning: format!(
                        "Function '{}' mutates state variable '{}'",
                        s.function, s.state
                    ),
                });
            }
        }
    }

    // ── rules/composition.rs: MultipleStateWrites per function ──
    // Count write edges per function. Emit once if count > 1 && no enforced authority.
    let enforced_fns: std::collections::BTreeSet<String> = ir
        .edges
        .iter()
        .filter_map(|e| match e {
            Edge::Authority(a) if a.check_type == "enforced" => Some(a.function.clone()),
            _ => None,
        })
        .collect();

    let mut write_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for edge in &ir.edges {
        if let Edge::State(s) = edge {
            if s.access == "write" && !is_constructor(&s.function) {
                *write_counts.entry(s.function.clone()).or_insert(0) += 1;
            }
        }
    }

    for (fn_name, count) in &write_counts {
        if *count > 1 && !enforced_fns.contains(fn_name) {
            let severity = if high_coverage_fns.contains(fn_name) {
                Severity::Info
            } else {
                Severity::Medium
            };
            out.push(CompatHypothesis {
                id: format!("COMP-MULTIWRITE-{}", fn_name),
                kind: "MultipleStateWrites".to_string(),
                severity,
                confidence: 0.55,
                affected_function: fn_name.clone(),
                evidence: vec![
                    format!("{} state mutations in single function", count),
                    "No authority check detected".into(),
                ],
                reasoning: format!(
                    "Function '{}' has {} state mutations without authority",
                    fn_name, count
                ),
            });
        }
    }

    out
}

/// Compute the set of functions that already have a Critical or High severity
/// hypothesis from the authority or reentrancy edge analysis.
fn compute_high_coverage_fns(ir: &SystemIR) -> std::collections::BTreeSet<String> {
    let mut fns = std::collections::BTreeSet::new();

    for edge in &ir.edges {
        match edge {
            // Authority gap on state mutation = Critical → function is covered
            Edge::State(s) if s.access == "write" => {
                let has_enforced = ir.edges.iter().any(|e| match e {
                    Edge::Authority(a) => a.function == s.function && a.check_type == "enforced",
                    _ => false,
                });
                if !has_enforced {
                    fns.insert(s.function.clone());
                }
            }
            // External call without authority = High
            Edge::External(e) => {
                let has_enforced = ir.edges.iter().any(|a| match a {
                    Edge::Authority(a) => a.function == e.function && a.check_type == "enforced",
                    _ => false,
                });
                if !has_enforced {
                    fns.insert(e.function.clone());
                }
            }
            _ => {}
        }
    }

    fns
}

/// Normalize a kind string to a stable suffix for id generation.
fn normalize_kind(kind: &str) -> String {
    kind.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Compute the legacy sub-kinds for a function, mirroring rules/authority.rs exactly.
///
/// Returns (kind, severity) pairs. Legacy emits MULTIPLE kinds per function
/// (they stack, not mutually exclusive). The ordering matches legacy's emit order.
///
/// PRINCIPLED SUPPRESSION (precision-pass-1):
/// - Constructors are never flagged (they necessarily write state).
/// - Rule 4 catch-all requires the function to actually mutate state OR have an
///   external effect. A bare public getter must NOT produce MissingAuthorityCheck.
fn authority_sub_kinds(ir: &SystemIR, fn_name: &str) -> Vec<(&'static str, Severity)> {
    // Suppress constructors — they necessarily write state during initialization.
    if is_constructor(fn_name) {
        return vec![];
    }

    // Check if the function has an enforced authority edge
    let has_enforced = ir.edges.iter().any(|e| match e {
        Edge::Authority(a) => a.function == fn_name && a.check_type == "enforced",
        _ => false,
    });
    if has_enforced {
        return vec![]; // legacy would not emit any authority kind
    }

    let mutates_state = ir.edges.iter().any(|e| match e {
        Edge::State(s) => s.function == fn_name && s.access == "write",
        _ => false,
    });

    let has_external = ir
        .edges
        .iter()
        .any(|e| matches!(e, Edge::External(ext) if ext.function == fn_name));

    let f = ir.functions.iter().find(|f| f.name == fn_name);
    let is_public = f
        .map(|f| f.visibility == digger_ir::Visibility::Public)
        .unwrap_or(false);
    let has_value_transfer = f.map(|f| f.effects.value_transfer).unwrap_or(false);
    let has_external_effect = has_external || has_value_transfer;

    let mut kinds: Vec<(&str, Severity)> = Vec::new();

    // Rule 1: mutates_state && !has_enforced (Critical)
    if mutates_state && !has_enforced {
        kinds.push(("MissingAuthorityOnStateMutation", Severity::Critical));
    }

    // Rule 2: has_external && !has_enforced (High)
    if has_external && !has_enforced {
        kinds.push(("MissingAuthorityOnExternalCall", Severity::High));
    }

    // Rule 3: public + external_effect + !has_enforced + !mutates_state (High)
    if is_public && has_external_effect && !has_enforced && !mutates_state {
        kinds.push(("UnprotectedExternalEffectCandidate", Severity::High));
    }

    // Rule 4: catch-all — ONLY when function actually has an observable effect.
    // A bare public getter (no state write, no external call, no value transfer)
    // must NOT produce MissingAuthorityCheck. This eliminates the dominant source
    // of FPs: interface methods (balanceOf, transfer), view helpers, etc.
    let has_observable_effect = mutates_state || has_external_effect;
    if !has_enforced && is_public && has_observable_effect {
        kinds.push(("MissingAuthorityCheck", Severity::Medium));
    }

    kinds
}

/// Returns true if the function name matches a constructor pattern.
fn is_constructor(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "constructor" || lower.ends_with("constructor")
}

fn hyp_to_compat(h: Hypothesis) -> CompatHypothesis {
    let severity = h.severity.clone();
    let confidence = confidence_for(&h.severity);
    CompatHypothesis {
        id: h.id.0,
        kind: kind_for(&h.hypothesis_type).to_string(),
        severity,
        confidence,
        affected_function: h.primary_function,
        evidence: h.evidence.iter().map(render_evidence).collect(),
        reasoning: h.structural_explanation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_graph::build_system_ir;
    use digger_ir::*;
    use digger_parser::model::*;

    /// Fixture: public state-mutating functions with external call + no authority.
    /// Built via RawProgram → build_system_ir so the Gen2 graph engines get
    /// proper Call/External/State/Authority edges.
    fn fixture_ir() -> SystemIR {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "deposit".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "balances[msg.sender] += msg.value".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "withdraw".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "require(balances[msg.sender] >= amount); \
                           (bool success, ) = msg.sender.call{value: amount}(\"\"); \
                           balances = new_balances"
                        .into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "setOwner".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "owner = newOwner".into(),
                    ..Default::default()
                },
            ],
            state: vec![
                RawState {
                    name: "balances".into(),
                    ty: "mapping".into(),
                    ..Default::default()
                },
                RawState {
                    name: "owner".into(),
                    ty: "address".into(),
                    ..Default::default()
                },
            ],
            calls: vec![RawCall {
                from: "withdraw".into(),
                to: "external".into(),
                kind: CallKind::External,
            }],
            ..Default::default()
        };
        build_system_ir(program)
    }

    #[test]
    fn analyze_compat_yields_hypotheses_with_expected_kinds() {
        let result = analyze_compat(&fixture_ir());
        assert!(
            !result.is_empty(),
            "analyze_compat should produce at least one hypothesis"
        );
        let kinds: Vec<&str> = result.iter().map(|h| h.kind.as_str()).collect();
        // The fixture has public state-mutating functions with external calls
        // and no authority — expect at least MissingAuthorityCheck kind.
        assert!(
            kinds.contains(&"MissingAuthorityCheck"),
            "Expected MissingAuthorityCheck kind, got: {:?}",
            kinds
        );
    }

    #[test]
    fn determinism() {
        let a = format!("{:#?}", analyze_compat(&fixture_ir()));
        let b = format!("{:#?}", analyze_compat(&fixture_ir()));
        assert_eq!(a, b, "analyze_compat is not deterministic");
    }

    #[test]
    fn confidence_derived_from_severity() {
        assert_eq!(confidence_for(&Severity::Critical), 0.95);
        assert_eq!(confidence_for(&Severity::High), 0.8);
        assert_eq!(confidence_for(&Severity::Medium), 0.6);
        assert_eq!(confidence_for(&Severity::Low), 0.4);
        assert_eq!(confidence_for(&Severity::Info), 0.2);
    }

    #[test]
    fn kind_mapping_covers_all_gen2_types() {
        for ty in [
            HypothesisType::ReentrancyCandidate,
            HypothesisType::AuthorityBypassCandidate,
            HypothesisType::CPITrustViolationCandidate,
            HypothesisType::StateCorruptionCandidate,
            HypothesisType::EconomicInvariantViolationCandidate,
            HypothesisType::AdversarialPathCandidate,
            HypothesisType::OracleManipulationCandidate,
            HypothesisType::FlashLoanGovernanceCandidate,
        ] {
            let k = kind_for(&ty);
            assert!(!k.is_empty(), "kind_for({:?}) returned empty string", ty);
        }
    }

    #[test]
    fn evidence_rendering_is_deterministic() {
        let ev = HypothesisEvidence {
            path_id: "PATH-1".into(),
            evidence_chain_id: "FIND-1".into(),
            involved_functions: vec!["foo".into(), "bar".into()],
            graph_facts: vec![GraphFact {
                fact_type: "authority_gap".into(),
                function: "foo".into(),
                detail: "no guard".into(),
            }],
        };
        let s = render_evidence(&ev);
        assert!(s.contains("PATH-1"));
        assert!(s.contains("foo, bar"));
        assert!(s.contains("authority_gap"));
    }

    /// public + state write + missing authority → emits both the sub-kind
    /// (MissingAuthorityOnStateMutation, Critical) AND the catch-all
    /// (MissingAuthorityCheck, Medium).
    #[test]
    fn authority_state_write_emits_sub_kinds() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "setOwner".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "owner = newOwner".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "owner".into(),
                ty: "address".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = analyze_compat(&ir);
        let kinds: Vec<&str> = result.iter().map(|h| h.kind.as_str()).collect();
        assert!(
            kinds.contains(&"MissingAuthorityOnStateMutation"),
            "Expected MissingAuthorityOnStateMutation, got: {:?}",
            kinds
        );
        assert!(
            kinds.contains(&"MissingAuthorityCheck"),
            "Expected MissingAuthorityCheck catch-all, got: {:?}",
            kinds
        );
        // The sub-kind should be Critical, catch-all Medium
        let crit: Vec<_> = result
            .iter()
            .filter(|h| h.kind == "MissingAuthorityOnStateMutation")
            .collect();
        assert_eq!(crit.len(), 1);
        assert_eq!(crit[0].severity, Severity::Critical);
        let med: Vec<_> = result
            .iter()
            .filter(|h| h.kind == "MissingAuthorityCheck")
            .collect();
        assert!(!med.is_empty());
        assert_eq!(med[0].severity, Severity::Medium);
    }

    /// public + enforced authority → no authority sub-kinds emitted.
    #[test]
    fn enforced_authority_yields_no_sub_kinds() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "setOwner".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "require(msg.sender == owner); owner = newOwner".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = analyze_compat(&ir);
        let auth_kinds: Vec<&str> = result
            .iter()
            .filter(|h| {
                h.kind == "MissingAuthorityCheck"
                    || h.kind == "MissingAuthorityOnStateMutation"
                    || h.kind == "MissingAuthorityOnExternalCall"
                    || h.kind == "UnprotectedExternalEffectCandidate"
            })
            .map(|h| h.kind.as_str())
            .collect();
        assert!(
            auth_kinds.is_empty(),
            "Should not emit authority sub-kinds for enforced function, got: {:?}",
            auth_kinds
        );
    }

    /// Analyze_compat is deterministic across runs.
    #[test]
    fn analyze_compat_determinism_with_subkinds() {
        let ir = fixture_ir();
        let a = format!("{:#?}", analyze_compat(&ir));
        let b = format!("{:#?}", analyze_compat(&ir));
        assert_eq!(a, b, "analyze_compat must be deterministic");
    }

    /// public + external call + missing authority → emits MissingAuthorityOnExternalCall.
    #[test]
    fn authority_external_call_emits_sub_kind() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "withdraw".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "(bool ok,) = recipient.call{value: amount}(\"\");".into(),
                ..Default::default()
            }],
            state: vec![],
            calls: vec![RawCall {
                from: "withdraw".into(),
                to: "external".into(),
                kind: CallKind::External,
            }],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = analyze_compat(&ir);
        let kinds: Vec<&str> = result.iter().map(|h| h.kind.as_str()).collect();
        assert!(
            kinds.contains(&"MissingAuthorityOnExternalCall"),
            "Expected MissingAuthorityOnExternalCall, got: {:?}",
            kinds
        );
        assert!(
            kinds.contains(&"MissingAuthorityCheck"),
            "Expected MissingAuthorityCheck catch-all, got: {:?}",
            kinds
        );
    }

    // ── RECALL-GUARD TESTS (precision-pass-1) ───────────────────────
    // These tests encode the REAL exploited patterns from Poly Network and
    // Spartan Protocol. They MUST pass even after precision suppression.
    // If a future change silences either catch, these tests fail.

    /// Poly Network shape: public state-mutating function with no authority check.
    /// The exploited function putCurEpochConnectPubKeys() was public, wrote state,
    /// and had no modifier. This pattern MUST still produce
    /// MissingAuthorityOnStateMutation at Critical severity.
    #[test]
    fn recall_guard_poly_network_access_control() {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "putCurEpochConnectPubKeys".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "currentEpochConnectPublicKeys = _newKeys".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "setEthCrossChainAddress".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "ethCrossChainAddress = _addr".into(),
                    ..Default::default()
                },
            ],
            state: vec![
                RawState {
                    name: "currentEpochConnectPublicKeys".into(),
                    ty: "bytes".into(),
                    ..Default::default()
                },
                RawState {
                    name: "ethCrossChainAddress".into(),
                    ty: "address".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = analyze_compat(&ir);

        // The CRITICAL MissingAuthorityOnStateMutation must be present
        // for the exploited function.
        let crit_state_auth: Vec<_> = result
            .iter()
            .filter(|h| {
                h.kind == "MissingAuthorityOnStateMutation" && h.severity == Severity::Critical
            })
            .collect();
        assert!(
            !crit_state_auth.is_empty(),
            "RECALL GUARD: Poly-Network-shaped contract MUST still produce \
             MissingAuthorityOnStateMutation (Critical). Got: {:?}",
            result
                .iter()
                .map(|h| (&h.kind, &h.severity))
                .collect::<Vec<_>>()
        );
        // The exploited function must be among those flagged.
        let flagged_fns: Vec<&str> = crit_state_auth
            .iter()
            .map(|h| h.affected_function.as_str())
            .collect();
        assert!(
            flagged_fns.contains(&"putCurEpochConnectPubKeys"),
            "RECALL GUARD: putCurEpochConnectPubKeys must be flagged. Flagged: {:?}",
            flagged_fns
        );
    }

    /// Spartan Protocol shape: external call before state update = reentrancy.
    /// The exploited function claimBond() transferred tokens BEFORE updating
    /// totalBonded. This pattern MUST still produce ReentrancyRisk at
    /// Critical severity.
    #[test]
    fn recall_guard_spartan_reentrancy() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "claimBond".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "(bool ok,) = msg.sender.call{value: amount}(\"\"); \
                       totalBonded -= amount; info.amount = 0"
                    .into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "totalBonded".into(),
                ty: "uint256".into(),
                ..Default::default()
            }],
            calls: vec![RawCall {
                from: "claimBond".into(),
                to: "external".into(),
                kind: CallKind::External,
            }],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = analyze_compat(&ir);

        // Must have ReentrancyRisk hypothesis
        let reentrancy: Vec<_> = result
            .iter()
            .filter(|h| h.kind == "ReentrancyRisk")
            .collect();
        assert!(
            !reentrancy.is_empty(),
            "RECALL GUARD: Spartan-shaped reentrancy MUST still produce ReentrancyRisk. Got: {:?}",
            result
                .iter()
                .map(|h| (&h.kind, &h.severity))
                .collect::<Vec<_>>()
        );
        // Must be Critical severity (external call before state write)
        let crit_reentrancy: Vec<_> = reentrancy
            .iter()
            .filter(|h| h.severity == Severity::Critical)
            .collect();
        assert!(
            !crit_reentrancy.is_empty(),
            "RECALL GUARD: Spartan reentrancy must be Critical severity."
        );
    }

    /// Verify that the precision pass correctly suppresses a bare getter.
    /// A public function that only reads state (no write, no external call)
    /// must NOT produce MissingAuthorityCheck.
    #[test]
    fn precision_suppresses_bare_getter() {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "balanceOf".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "return balances[account]".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "totalSupply".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "return supply".into(),
                    ..Default::default()
                },
            ],
            state: vec![
                RawState {
                    name: "balances".into(),
                    ty: "mapping".into(),
                    ..Default::default()
                },
                RawState {
                    name: "supply".into(),
                    ty: "uint256".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = analyze_compat(&ir);

        let getter_auth: Vec<_> = result
            .iter()
            .filter(|h| {
                (h.affected_function == "balanceOf" || h.affected_function == "totalSupply")
                    && h.kind == "MissingAuthorityCheck"
            })
            .collect();
        assert!(
            getter_auth.is_empty(),
            "Bare getters must NOT produce MissingAuthorityCheck. Got: {:?}",
            getter_auth
        );
    }

    /// Verify that the precision pass correctly suppresses constructors.
    #[test]
    fn precision_suppresses_constructor() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "constructor".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "owner = msg.sender; supply = 1000000".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "owner".into(),
                ty: "address".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = analyze_compat(&ir);

        let ctor_auth: Vec<_> = result
            .iter()
            .filter(|h| {
                h.affected_function == "constructor"
                    && (h.kind == "MissingAuthorityCheck"
                        || h.kind == "MissingAuthorityOnStateMutation")
            })
            .collect();
        assert!(
            ctor_auth.is_empty(),
            "Constructor must NOT produce authority hypotheses. Got: {:?}",
            ctor_auth
        );
    }
}
