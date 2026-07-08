/// Adversarial Modeling Engine — Generation 2 baseline.
///
/// Pipeline:
///
///   SemanticModels → CapabilityGraph → GoalPreconditions
///       → AttackGoal → GoalSearch → EvidenceGraph → GoalHypothesis
///       → ReasoningSession → CapabilityReport
///
/// Every inference step is backed by a ReasoningRule with provenance.
/// Every analysis run produces a ReasoningSession as canonical record.
/// Confidence is computed from configurable structural weights.
///
/// Deterministic: same inputs → same output.
/// No exploit signatures. No heuristics. No AI.
use crate::models::*;
use digger_actors::*;
use digger_economics::*;
use digger_gen2_protocol::ProtocolIR;
use digger_parser::model::*;
use digger_resource_lifecycle::{self, ResourceLifecycle, ResourceLifecycleReport};
use digger_state_transitions::*;
use digger_temporal::{TemporalDependency, TemporalReport};
use digger_verification::*;

const MAX_CAPABILITIES: usize = 50;
const MAX_ATTACK_PATHS: usize = 100;
const MAX_HYPOTHESES: usize = 20;

/// Analyze adversarial capabilities for a program.
#[allow(clippy::too_many_arguments)]
pub fn analyze_adversarial(
    program: &RawProgram,
    transitions: &StateTransitionReport,
    lifecycles: &ResourceLifecycleReport,
    temporal: &TemporalReport,
    actors: &MultiActorReport,
    economics: &EconomicReport,
    verification: &VerificationReport,
    protocol: Option<&ProtocolIR>,
    protocol_id: &str,
) -> CapabilityReport {
    let context = default_context();
    let session = analyze_adversarial_with_context(
        program,
        transitions,
        lifecycles,
        temporal,
        actors,
        economics,
        verification,
        protocol,
        protocol_id,
        &context,
    );
    let capabilities = session.capability_graph.flat_capabilities();
    CapabilityReport {
        session: session.clone(),
        capabilities,
        hypotheses: session.hypotheses.clone(),
        attack_paths: session.paths_found.clone(),
        summary: session.summary.clone(),
    }
}

/// Analyze with explicit context.
#[allow(clippy::too_many_arguments)]
pub fn analyze_adversarial_with_context(
    program: &RawProgram,
    transitions: &StateTransitionReport,
    lifecycles: &ResourceLifecycleReport,
    temporal: &TemporalReport,
    actors: &MultiActorReport,
    economics: &EconomicReport,
    verification: &VerificationReport,
    protocol: Option<&ProtocolIR>,
    protocol_id: &str,
    context: &ReasoningContext,
) -> ReasoningSession {
    let mut trace = ReasoningTrace { entries: vec![] };
    let mut failures = FailureAnalysis { failures: vec![] };
    let mut all_rules = Vec::new();

    // Step 1: Build capability graph with compositions
    let mut cap_graph = build_capability_graph(
        program,
        transitions,
        lifecycles,
        temporal,
        actors,
        protocol,
        &mut trace,
        &mut all_rules,
    );
    let compositions = discover_compositions(&cap_graph, &mut trace, &mut all_rules);
    cap_graph.compositions = compositions;

    // Step 2: Derive goals
    let goals = derive_goals(
        economics,
        verification,
        temporal,
        lifecycles,
        actors,
        &mut trace,
        &mut all_rules,
    );

    // Step 3: Check preconditions
    let precondition_results = check_goal_preconditions(
        &goals, &cap_graph, economics, lifecycles, temporal, &mut trace,
    );

    // Step 4: Search for paths
    let mut all_paths = Vec::new();
    for (goal, precond) in goals.iter().zip(precondition_results.iter()) {
        if !precond.satisfied {
            failures.failures.push(FailureReason {
                goal: goal.clone(),
                reason: if !precond.missing_capabilities.is_empty() {
                    FailureKind::MissingCapability
                } else {
                    FailureKind::MissingRelation
                },
                missing: precond
                    .missing_capabilities
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
                rule_id: format!("search:{}", goal),
            });
            continue;
        }
        let paths = search_paths_for_goal(
            goal,
            &cap_graph,
            economics,
            temporal,
            actors,
            lifecycles,
            verification,
            transitions,
            &context.confidence_weights,
            &mut trace,
            &mut all_rules,
        );
        all_paths.extend(paths);
    }

    all_paths.sort_by(|a, b| a.path_id.cmp(&b.path_id));
    all_paths.dedup_by(|a, b| a.path_id == b.path_id);
    all_paths.truncate(MAX_ATTACK_PATHS);

    // Step 5: Build hypotheses
    let mut hypotheses = build_hypotheses(&goals, &all_paths, &precondition_results);
    hypotheses.sort_by_key(|a| a.goal.to_string());
    hypotheses.truncate(MAX_HYPOTHESES);

    // Step 6: Summary
    let violable_constraints = all_paths
        .iter()
        .map(|p| &p.violated_constraint)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let feasible_goals = hypotheses.iter().filter(|h| h.is_feasible).count();
    let evidence_diversity = all_paths
        .iter()
        .map(|p| p.evidence_graph.model_diversity())
        .max()
        .unwrap_or(0);

    let summary = AdversarialSummary {
        total_capabilities: cap_graph.nodes.len(),
        total_attack_paths: all_paths.len(),
        total_hypotheses: hypotheses.len(),
        feasible_goals,
        violable_constraints,
        total_rules_applied: trace.entries.len(),
        total_failures: failures.failures.len(),
        evidence_model_diversity: evidence_diversity,
        total_compositions: cap_graph.compositions.len(),
    };

    // Step 7: Build input snapshot
    let input = build_input_snapshot(
        program,
        transitions,
        lifecycles,
        temporal,
        actors,
        economics,
        verification,
    );

    // Step 8: Build session
    let session_id = compute_session_id(&input, context);
    ReasoningSession {
        session_id,
        protocol_id: protocol_id.into(),
        input,
        context: context.clone(),
        capability_graph: cap_graph,
        goals_derived: goals,
        precondition_results,
        paths_found: all_paths,
        hypotheses,
        failures,
        trace,
        rules_used: all_rules,
        summary,
    }
}

// ═══════════════════════════════════════════════════════════════
// Context and Session Construction
// ═══════════════════════════════════════════════════════════════

fn default_context() -> ReasoningContext {
    ReasoningContext {
        scope: "single_file".into(),
        chain: "unknown".into(),
        language: "auto".into(),
        baseline_version: "gen2-baseline".into(),
        enabled_rules: vec![],
        confidence_weights: ConfidenceWeights::default(),
        max_capabilities: MAX_CAPABILITIES,
        max_attack_paths: MAX_ATTACK_PATHS,
        max_hypotheses: MAX_HYPOTHESES,
    }
}

fn build_input_snapshot(
    program: &RawProgram,
    transitions: &StateTransitionReport,
    lifecycles: &ResourceLifecycleReport,
    temporal: &TemporalReport,
    actors: &MultiActorReport,
    economics: &EconomicReport,
    verification: &VerificationReport,
) -> InputSnapshot {
    let input_hash = format!("{:x}", {
        let mut h: u64 = 0;
        for op in &program.operations {
            for byte in op.target.bytes() {
                h = h.wrapping_mul(31).wrapping_add(byte as u64);
            }
        }
        h = h
            .wrapping_mul(31)
            .wrapping_add(transitions.transitions.len() as u64);
        h = h
            .wrapping_mul(31)
            .wrapping_add(economics.relations.len() as u64);
        h = h
            .wrapping_mul(31)
            .wrapping_add(verification.properties.len() as u64);
        h
    });

    InputSnapshot {
        transition_count: transitions.transitions.len(),
        lifecycle_count: lifecycles.lifecycles.len(),
        dependency_count: temporal.dependencies.len(),
        sequence_count: temporal.sequences.len(),
        actor_count: actors.actors.len(),
        interaction_count: actors.interactions.len(),
        relation_count: economics.relations.len(),
        invariant_count: economics.invariants.len(),
        property_count: verification.properties.len(),
        input_hash,
    }
}

fn compute_session_id(input: &InputSnapshot, context: &ReasoningContext) -> String {
    format!("{:x}", {
        let mut h: u64 = 0;
        for byte in input.input_hash.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
        for byte in context.baseline_version.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
        h = h
            .wrapping_mul(31)
            .wrapping_add(context.max_capabilities as u64);
        h
    })
}

// ═══════════════════════════════════════════════════════════════
// Rule and Trace Helpers
// ═══════════════════════════════════════════════════════════════

fn make_rule(
    rule_id: &str,
    kind: RuleKind,
    description: &str,
    inputs: Vec<&str>,
    preconditions: Vec<&str>,
    outputs: Vec<&str>,
    confidence_weight: f64,
) -> ReasoningRule {
    ReasoningRule {
        rule_id: rule_id.into(),
        kind,
        description: description.into(),
        inputs: inputs.into_iter().map(|s| s.into()).collect(),
        preconditions: preconditions.into_iter().map(|s| s.into()).collect(),
        outputs: outputs.into_iter().map(|s| s.into()).collect(),
        confidence_weight,
        provenance: RuleProvenance {
            origin: "gen2_baseline".into(),
            phase: 12,
            last_validated: None,
        },
        validation_history: vec![],
    }
}

fn trace_entry(
    rule_id: &str,
    rule_kind: RuleKind,
    inputs: Vec<&str>,
    outputs: Vec<&str>,
    fired: bool,
) -> TraceEntry {
    let entry_hash = format!("{:x}", {
        let mut h: u64 = 0;
        for byte in rule_id.bytes() {
            h = h.wrapping_mul(31).wrapping_add(byte as u64);
        }
        h
    });
    TraceEntry {
        rule_id: rule_id.into(),
        rule_kind,
        inputs: inputs.into_iter().map(|s| s.into()).collect(),
        outputs: outputs.into_iter().map(|s| s.into()).collect(),
        fired,
        entry_hash,
    }
}

// ═══════════════════════════════════════════════════════════════
// CapabilityGraph Construction
// ═══════════════════════════════════════════════════════════════

#[allow(clippy::too_many_arguments)]
fn build_capability_graph(
    program: &RawProgram,
    transitions: &StateTransitionReport,
    lifecycles: &ResourceLifecycleReport,
    temporal: &TemporalReport,
    actors: &MultiActorReport,
    protocol: Option<&ProtocolIR>,
    trace: &mut ReasoningTrace,
    rules: &mut Vec<ReasoningRule>,
) -> CapabilityGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Register rules
    rules.push(make_rule(
        "cap:call_public",
        RuleKind::CapabilityDetection,
        "Detect callable public/external functions",
        vec!["RawProgram.functions"],
        vec!["visibility == public || external"],
        vec!["CapabilityKind::CanCallPublicFunction"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:observe_state",
        RuleKind::CapabilityDetection,
        "Detect state observation capability",
        vec!["StateTransition.read_before_write"],
        vec!["read_before_write == true"],
        vec!["CapabilityKind::CanObserveState"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:reenter",
        RuleKind::CapabilityDetection,
        "Detect reentrancy capability",
        vec!["StateTransition.external_between_read_write"],
        vec!["external_between_read_write == true"],
        vec!["CapabilityKind::CanReenter"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:borrow_liquidity",
        RuleKind::CapabilityDetection,
        "Detect liquidity borrowing capability",
        vec!["StateTransition", "ResourceLifecycle.anomalies"],
        vec!["external_between_read_write && liquidity_var || egress_without_accounting"],
        vec!["CapabilityKind::CanBorrowLiquidity"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:split_transactions",
        RuleKind::CapabilityDetection,
        "Detect cross-transaction splitting",
        vec!["TemporalDependency"],
        vec!["dependencies.len() > 0"],
        vec!["CapabilityKind::CanSplitAcrossTransactions"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:control_governance",
        RuleKind::CapabilityDetection,
        "Detect governance control capability",
        vec!["Actor.role == Governance"],
        vec!["governance actor exists"],
        vec!["CapabilityKind::CanControlGovernance"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:manipulate_price",
        RuleKind::CapabilityDetection,
        "Detect price manipulation capability",
        vec!["ActorInteraction", "StateTransition"],
        vec!["PriceManipulation interaction || price/oracle state var with external call"],
        vec!["CapabilityKind::CanManipulatePrice"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:delay_settlement",
        RuleKind::CapabilityDetection,
        "Detect settlement delay capability",
        vec!["TemporalAnomaly", "ResourceLifecycle"],
        vec!["ReorderingAttack || Settlement without authority"],
        vec!["CapabilityKind::CanDelaySettlement"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:trigger_callback",
        RuleKind::CapabilityDetection,
        "Detect callback triggering capability",
        vec!["StateTransition.external_between_read_write"],
        vec!["external_between_read_write == true"],
        vec!["CapabilityKind::CanTriggerCallback"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:deploy_contract",
        RuleKind::CapabilityDetection,
        "Detect contract deployment capability",
        vec!["RawProgram.operations"],
        vec!["create || create2 in assembly"],
        vec!["CapabilityKind::CanDeployContract"],
        1.0,
    ));
    rules.push(make_rule(
        "cap:control_ordering",
        RuleKind::CapabilityDetection,
        "Detect transaction ordering control",
        vec!["TemporalDependency.is_enforced"],
        vec!["!is_enforced"],
        vec!["CapabilityKind::CanControlTransactionOrdering"],
        1.0,
    ));

    // ── CanCallPublicFunction ──
    let public_fns: Vec<String> = program
        .functions
        .iter()
        .filter(|f| f.visibility == "public" || f.visibility == "external")
        .map(|f| f.name.clone())
        .collect();
    if !public_fns.is_empty() {
        nodes.push(CapabilityNode {
            capability_id: "cap:call_public".into(),
            kind: CapabilityKind::CanCallPublicFunction,
            functions: public_fns,
            state_vars: vec![],
            detected_by: "cap:call_public".into(),
        });
        trace.entries.push(trace_entry(
            "cap:call_public",
            RuleKind::CapabilityDetection,
            vec!["RawProgram.functions"],
            vec!["CanCallPublicFunction"],
            true,
        ));
    } else {
        trace.entries.push(trace_entry(
            "cap:call_public",
            RuleKind::CapabilityDetection,
            vec!["RawProgram.functions"],
            vec![],
            false,
        ));
    }

    // ── CanObserveState ──
    let read_fns: Vec<String> = transitions
        .transitions
        .iter()
        .filter(|t| t.read_before_write)
        .map(|t| t.function.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !read_fns.is_empty() {
        nodes.push(CapabilityNode {
            capability_id: "cap:observe_state".into(),
            kind: CapabilityKind::CanObserveState,
            functions: read_fns,
            state_vars: vec![],
            detected_by: "cap:observe_state".into(),
        });
        trace.entries.push(trace_entry(
            "cap:observe_state",
            RuleKind::CapabilityDetection,
            vec!["StateTransition.read_before_write"],
            vec!["CanObserveState"],
            true,
        ));
    }

    // ── CanReenter ──
    let reentrant_fns: Vec<String> = transitions
        .transitions
        .iter()
        .filter(|t| t.external_between_read_write)
        .map(|t| t.function.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !reentrant_fns.is_empty() {
        nodes.push(CapabilityNode {
            capability_id: "cap:reenter".into(),
            kind: CapabilityKind::CanReenter,
            functions: reentrant_fns,
            state_vars: vec![],
            detected_by: "cap:reenter".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:reenter".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
        trace.entries.push(trace_entry(
            "cap:reenter",
            RuleKind::CapabilityDetection,
            vec!["StateTransition.external_between_read_write"],
            vec!["CanReenter"],
            true,
        ));
    }

    // ── CanBorrowLiquidity ──
    let mut borrow_fns: Vec<String> = transitions
        .transitions
        .iter()
        .filter(|t| t.external_between_read_write)
        .filter(|t| {
            t.state_var.contains("balance")
                || t.state_var.contains("deposit")
                || t.state_var.contains("borrow")
                || t.state_var.contains("liquidity")
                || t.state_var.contains("reserve")
        })
        .map(|t| t.function.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for lc in &lifecycles.lifecycles {
        for anomaly in &lc.anomalies {
            if matches!(
                anomaly.kind,
                digger_resource_lifecycle::AnomalyKind::EgressWithoutAccountingDecrease
                    | digger_resource_lifecycle::AnomalyKind::UnauthorizedEgress
            ) && !borrow_fns.contains(&lc.function)
            {
                borrow_fns.push(lc.function.clone());
            }
        }
    }
    if !borrow_fns.is_empty() {
        borrow_fns.sort();
        borrow_fns.dedup();
        nodes.push(CapabilityNode {
            capability_id: "cap:borrow_liquidity".into(),
            kind: CapabilityKind::CanBorrowLiquidity,
            functions: borrow_fns,
            state_vars: vec![],
            detected_by: "cap:borrow_liquidity".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:borrow_liquidity".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
        trace.entries.push(trace_entry(
            "cap:borrow_liquidity",
            RuleKind::CapabilityDetection,
            vec!["StateTransition", "ResourceLifecycle.anomalies"],
            vec!["CanBorrowLiquidity"],
            true,
        ));
    }

    // ── CanSplitAcrossTransactions ──
    if !temporal.dependencies.is_empty() {
        let fns: Vec<String> = temporal
            .dependencies
            .iter()
            .flat_map(|d| vec![d.predecessor.clone(), d.successor.clone()])
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        nodes.push(CapabilityNode {
            capability_id: "cap:split_transactions".into(),
            kind: CapabilityKind::CanSplitAcrossTransactions,
            functions: fns,
            state_vars: vec![],
            detected_by: "cap:split_transactions".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:split_transactions".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
        trace.entries.push(trace_entry(
            "cap:split_transactions",
            RuleKind::CapabilityDetection,
            vec!["TemporalDependency"],
            vec!["CanSplitAcrossTransactions"],
            true,
        ));
    }

    // ── CanControlGovernance ──
    if let Some(gov) = actors
        .actors
        .iter()
        .find(|a| a.role == ActorRole::Governance)
    {
        nodes.push(CapabilityNode {
            capability_id: "cap:control_governance".into(),
            kind: CapabilityKind::CanControlGovernance,
            functions: gov.callable_functions.clone(),
            state_vars: gov.affected_state.clone(),
            detected_by: "cap:control_governance".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:control_governance".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
        trace.entries.push(trace_entry(
            "cap:control_governance",
            RuleKind::CapabilityDetection,
            vec!["Actor.role"],
            vec!["CanControlGovernance"],
            true,
        ));
    }

    // ── CanManipulatePrice ──
    let price_actor_fns: Vec<String> = actors
        .interactions
        .iter()
        .filter(|i| matches!(i.kind, InteractionKind::PriceManipulation))
        .map(|i| i.function.clone())
        .collect();
    let price_trans_fns: Vec<String> = transitions
        .transitions
        .iter()
        .filter(|t| t.external_between_read_write)
        .filter(|t| {
            t.state_var.contains("price")
                || t.state_var.contains("oracle")
                || t.state_var.contains("spot")
                || t.state_var.contains("rate")
                || t.state_var.contains("feed")
        })
        .map(|t| t.function.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut price_fns = price_actor_fns;
    price_fns.extend(price_trans_fns);
    price_fns.sort();
    price_fns.dedup();
    if !price_fns.is_empty() {
        nodes.push(CapabilityNode {
            capability_id: "cap:manipulate_price".into(),
            kind: CapabilityKind::CanManipulatePrice,
            functions: price_fns,
            state_vars: vec![],
            detected_by: "cap:manipulate_price".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:manipulate_price".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
        trace.entries.push(trace_entry(
            "cap:manipulate_price",
            RuleKind::CapabilityDetection,
            vec!["ActorInteraction", "StateTransition"],
            vec!["CanManipulatePrice"],
            true,
        ));
    }

    // ── CanDelaySettlement ──
    let reordering_fns: Vec<String> = temporal
        .anomalies
        .iter()
        .filter(|a| matches!(a.kind, digger_temporal::AnomalyKind::ReorderingAttack))
        .map(|a| a.predecessor.clone())
        .collect();
    let settlement_fns: Vec<String> = lifecycles
        .lifecycles
        .iter()
        .filter(|lc| {
            lc.phases.iter().any(|p| {
                matches!(p.kind, digger_resource_lifecycle::PhaseKind::Settlement)
                    && !p.authority_enforced
            })
        })
        .map(|lc| lc.function.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut delay_fns = reordering_fns;
    delay_fns.extend(settlement_fns);
    delay_fns.sort();
    delay_fns.dedup();
    if !delay_fns.is_empty() {
        nodes.push(CapabilityNode {
            capability_id: "cap:delay_settlement".into(),
            kind: CapabilityKind::CanDelaySettlement,
            functions: delay_fns,
            state_vars: vec![],
            detected_by: "cap:delay_settlement".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:delay_settlement".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
    }

    // ── CanTriggerCallback ──
    let callback_fns: Vec<String> = transitions
        .transitions
        .iter()
        .filter(|t| t.external_between_read_write)
        .map(|t| t.function.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !callback_fns.is_empty() {
        nodes.push(CapabilityNode {
            capability_id: "cap:trigger_callback".into(),
            kind: CapabilityKind::CanTriggerCallback,
            functions: callback_fns,
            state_vars: vec![],
            detected_by: "cap:trigger_callback".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:trigger_callback".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
    }

    // ── CanDeployContract ──
    let deploy_fns: Vec<String> = program
        .operations
        .iter()
        .filter(|op| {
            op.kind == OperationKind::ExternalCall
                && (op.target == "create" || op.target == "create2")
        })
        .map(|op| op.function.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !deploy_fns.is_empty() {
        nodes.push(CapabilityNode {
            capability_id: "cap:deploy_contract".into(),
            kind: CapabilityKind::CanDeployContract,
            functions: deploy_fns,
            state_vars: vec![],
            detected_by: "cap:deploy_contract".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:deploy_contract".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
    }

    // ── CanControlTransactionOrdering ──
    let unenforced_fns: Vec<String> = temporal
        .dependencies
        .iter()
        .filter(|d| !d.is_enforced)
        .flat_map(|d| vec![d.predecessor.clone(), d.successor.clone()])
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !unenforced_fns.is_empty() {
        nodes.push(CapabilityNode {
            capability_id: "cap:control_ordering".into(),
            kind: CapabilityKind::CanControlTransactionOrdering,
            functions: unenforced_fns,
            state_vars: vec![],
            detected_by: "cap:control_ordering".into(),
        });
        edges.push(CapabilityEdge {
            from: "cap:control_ordering".into(),
            to: "cap:call_public".into(),
            kind: CapabilityEdgeKind::PrerequisiteOf,
        });
    }

    // ── Cross-contract capabilities from ProtocolIR ──
    if let Some(protocol_ir) = protocol {
        // CanCallCrossContract — protocol has cross-program calls
        if !protocol_ir.cross_program_calls.is_empty() {
            let cross_fns: Vec<String> = protocol_ir
                .cross_program_calls
                .iter()
                .map(|c| c.from_function.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            nodes.push(CapabilityNode {
                capability_id: "cap:cross_contract".into(),
                kind: CapabilityKind::CanCallCrossContract,
                functions: cross_fns,
                state_vars: vec![],
                detected_by: "cap:cross_contract".into(),
            });
            edges.push(CapabilityEdge {
                from: "cap:cross_contract".into(),
                to: "cap:call_public".into(),
                kind: CapabilityEdgeKind::PrerequisiteOf,
            });
        }

        // CanExploitStorageCollision — protocol has proxy with storage collisions
        for vuln in &protocol_ir.vulnerabilities {
            if vuln.vuln_type == "ProxyStorageCollision" {
                nodes.push(CapabilityNode {
                    capability_id: "cap:storage_collision".into(),
                    kind: CapabilityKind::CanExploitStorageCollision,
                    functions: vuln.affected_contracts.clone(),
                    state_vars: vec![],
                    detected_by: "cap:storage_collision".into(),
                });
                edges.push(CapabilityEdge {
                    from: "cap:storage_collision".into(),
                    to: "cap:call_public".into(),
                    kind: CapabilityEdgeKind::PrerequisiteOf,
                });
            }
        }

        // CanUpgradeProxy — protocol has proxy patterns
        for proxy in &protocol_ir.proxy_patterns {
            if proxy.pattern_type == "transparent_proxy" || proxy.pattern_type == "uups" {
                nodes.push(CapabilityNode {
                    capability_id: format!("cap:upgrade_proxy:{}", proxy.proxy_contract),
                    kind: CapabilityKind::CanUpgradeProxy,
                    functions: vec![proxy.proxy_contract.clone()],
                    state_vars: vec![],
                    detected_by: "cap:upgrade_proxy".into(),
                });
                edges.push(CapabilityEdge {
                    from: format!("cap:upgrade_proxy:{}", proxy.proxy_contract),
                    to: "cap:call_public".into(),
                    kind: CapabilityEdgeKind::PrerequisiteOf,
                });
            }
        }

        // CanExploitDelegatecall — protocol uses delegatecall
        for contract in &protocol_ir.contracts {
            if contract.uses_delegatecall {
                nodes.push(CapabilityNode {
                    capability_id: format!("cap:delegatecall:{}", contract.name),
                    kind: CapabilityKind::CanExploitDelegatecall,
                    functions: vec![contract.name.clone()],
                    state_vars: vec![],
                    detected_by: "cap:delegatecall".into(),
                });
                edges.push(CapabilityEdge {
                    from: format!("cap:delegatecall:{}", contract.name),
                    to: "cap:call_public".into(),
                    kind: CapabilityEdgeKind::PrerequisiteOf,
                });
            }
        }
    }

    nodes.sort_by(|a, b| a.capability_id.cmp(&b.capability_id));
    nodes.truncate(MAX_CAPABILITIES);

    CapabilityGraph {
        nodes,
        edges,
        compositions: vec![],
    }
}

// ═══════════════════════════════════════════════════════════════
// Capability Composition — semantic primitive
// ═══════════════════════════════════════════════════════════════

fn discover_compositions(
    cap_graph: &CapabilityGraph,
    trace: &mut ReasoningTrace,
    rules: &mut Vec<ReasoningRule>,
) -> Vec<CapabilityComposition> {
    rules.push(make_rule(
        "comp:discover",
        RuleKind::CapabilityComposition,
        "Discover capability compositions",
        vec!["CapabilityGraph"],
        vec![],
        vec!["CapabilityComposition"],
        1.0,
    ));

    let cap_kinds = cap_graph.kinds();
    let mut compositions = Vec::new();

    // Multi-transaction reentrancy: CanReenter + CanSplitAcrossTransactions
    if cap_kinds.contains(&CapabilityKind::CanReenter)
        && cap_kinds.contains(&CapabilityKind::CanSplitAcrossTransactions)
    {
        compositions.push(CapabilityComposition {
            composition_id: "comp:reenter:split".into(),
            capabilities: vec![CapabilityKind::CanReenter, CapabilityKind::CanSplitAcrossTransactions],
            composite: CompositeCapabilityKind::MultiTransactionReentrancy,
            reason: "Reentrancy across multiple transactions enables state corruption between transactions".into(),
            discovered_by: "comp:discover".into(),
        });
        // Add composition edge
        // (edges are immutable here, but compositions are recorded)
    }

    // MEV extraction: CanObserveState + CanControlTransactionOrdering
    if cap_kinds.contains(&CapabilityKind::CanObserveState)
        && cap_kinds.contains(&CapabilityKind::CanControlTransactionOrdering)
    {
        compositions.push(CapabilityComposition {
            composition_id: "comp:observe:order".into(),
            capabilities: vec![
                CapabilityKind::CanObserveState,
                CapabilityKind::CanControlTransactionOrdering,
            ],
            composite: CompositeCapabilityKind::MevExtraction,
            reason: "Observing state then controlling transaction ordering enables MEV extraction"
                .into(),
            discovered_by: "comp:discover".into(),
        });
    }

    // Flash loan price manipulation: CanBorrowLiquidity + CanManipulatePrice
    if cap_kinds.contains(&CapabilityKind::CanBorrowLiquidity)
        && cap_kinds.contains(&CapabilityKind::CanManipulatePrice)
    {
        compositions.push(CapabilityComposition {
            composition_id: "comp:borrow:price".into(),
            capabilities: vec![
                CapabilityKind::CanBorrowLiquidity,
                CapabilityKind::CanManipulatePrice,
            ],
            composite: CompositeCapabilityKind::FlashLoanPriceManipulation,
            reason: "Borrowing liquidity enables price manipulation via large trades".into(),
            discovered_by: "comp:discover".into(),
        });
    }

    // Cross-function state corruption: CanReenter + CanObserveState
    if cap_kinds.contains(&CapabilityKind::CanReenter)
        && cap_kinds.contains(&CapabilityKind::CanObserveState)
    {
        compositions.push(CapabilityComposition {
            composition_id: "comp:reenter:observe".into(),
            capabilities: vec![CapabilityKind::CanReenter, CapabilityKind::CanObserveState],
            composite: CompositeCapabilityKind::CrossFunctionCorruption,
            reason: "Reentrancy with state observation enables cross-function state corruption"
                .into(),
            discovered_by: "comp:discover".into(),
        });
    }

    let fired = !compositions.is_empty();
    trace.entries.push(trace_entry(
        "comp:discover",
        RuleKind::CapabilityComposition,
        vec!["CapabilityGraph"],
        vec![&format!("{} compositions", compositions.len())],
        fired,
    ));

    compositions
}

// ═══════════════════════════════════════════════════════════════
// Goal Derivation
// ═══════════════════════════════════════════════════════════════

fn derive_goals(
    economics: &EconomicReport,
    verification: &VerificationReport,
    temporal: &TemporalReport,
    lifecycles: &ResourceLifecycleReport,
    actors: &MultiActorReport,
    trace: &mut ReasoningTrace,
    rules: &mut Vec<ReasoningRule>,
) -> Vec<AttackGoal> {
    rules.push(make_rule(
        "goal:derive",
        RuleKind::GoalDerivation,
        "Derive attack goals from semantic constraints",
        vec![
            "EconomicReport",
            "VerificationReport",
            "TemporalReport",
            "ResourceLifecycle",
            "MultiActorReport",
        ],
        vec![],
        vec!["AttackGoal"],
        1.0,
    ));

    let mut goals = std::collections::BTreeSet::new();

    for relation in &economics.relations {
        match &relation.kind {
            EconomicRelationKind::Conservation(_) => {
                goals.insert(AttackGoal::DrainAssets);
                goals.insert(AttackGoal::BreakEconomicInvariant);
            }
            EconomicRelationKind::Collateral(_) => {
                goals.insert(AttackGoal::BreakEconomicInvariant);
                goals.insert(AttackGoal::CreateBadDebt);
            }
            EconomicRelationKind::Debt(_) => {
                goals.insert(AttackGoal::CreateBadDebt);
                goals.insert(AttackGoal::BreakEconomicInvariant);
            }
            EconomicRelationKind::Dependency(_) => {
                goals.insert(AttackGoal::ManipulatePrice);
            }
        }
    }
    for invariant in &economics.invariants {
        match invariant.kind {
            InvariantKind::Conservation => {
                goals.insert(AttackGoal::DrainAssets);
            }
            InvariantKind::Solvency => {
                goals.insert(AttackGoal::CreateBadDebt);
            }
            InvariantKind::Collateralization => {
                goals.insert(AttackGoal::BreakEconomicInvariant);
            }
            InvariantKind::Accounting => {
                goals.insert(AttackGoal::CorruptAccounting);
            }
        }
    }
    for property in &verification.properties {
        match property.kind {
            PropertyKind::AuthorityInvariant => {
                goals.insert(AttackGoal::BypassAuthority);
                goals.insert(AttackGoal::GainUnauthorizedControl);
            }
            PropertyKind::AccountingInvariant => {
                goals.insert(AttackGoal::CorruptAccounting);
            }
            PropertyKind::OrderingConstraint => {
                goals.insert(AttackGoal::PreventSettlement);
            }
            PropertyKind::ConservationLaw => {
                goals.insert(AttackGoal::DrainAssets);
            }
            PropertyKind::AccessControlRequirement => {
                goals.insert(AttackGoal::BypassAuthority);
                goals.insert(AttackGoal::GainUnauthorizedControl);
            }
            PropertyKind::Custom => {}
        }
    }
    if !temporal.dependencies.is_empty() {
        goals.insert(AttackGoal::PreventSettlement);
    }
    // TemporalSequence integration: sequences with invalid ordering indicate settlement risk
    for seq in &temporal.sequences {
        if !seq.is_valid {
            goals.insert(AttackGoal::PreventSettlement);
        }
    }
    for anomaly in &temporal.anomalies {
        match anomaly.kind {
            digger_temporal::AnomalyKind::ReorderingAttack => {
                goals.insert(AttackGoal::PreventSettlement);
                goals.insert(AttackGoal::ManipulatePrice);
            }
            digger_temporal::AnomalyKind::StateInconsistency => {
                goals.insert(AttackGoal::CorruptAccounting);
            }
            digger_temporal::AnomalyKind::OrderingViolation => {
                goals.insert(AttackGoal::PreventSettlement);
            }
        }
    }
    for lc in &lifecycles.lifecycles {
        for anomaly in &lc.anomalies {
            match anomaly.kind {
                digger_resource_lifecycle::AnomalyKind::UnauthorizedEgress => {
                    goals.insert(AttackGoal::DrainAssets);
                    goals.insert(AttackGoal::BypassAuthority);
                }
                digger_resource_lifecycle::AnomalyKind::EgressWithoutAccountingDecrease => {
                    goals.insert(AttackGoal::CorruptAccounting);
                    goals.insert(AttackGoal::DrainAssets);
                }
                digger_resource_lifecycle::AnomalyKind::AccountingIntegrityRisk => {
                    goals.insert(AttackGoal::CorruptAccounting);
                }
                digger_resource_lifecycle::AnomalyKind::IngressWithoutAccounting => {
                    goals.insert(AttackGoal::CorruptAccounting);
                }
                digger_resource_lifecycle::AnomalyKind::UntrackedMovement => {
                    goals.insert(AttackGoal::CorruptAccounting);
                }
            }
        }
    }
    for interaction in &actors.interactions {
        if interaction.is_adversarial {
            goals.insert(AttackGoal::GainUnauthorizedControl);
        }
        // ActorInteraction.affected_actors integration
        if !interaction.affected_actors.is_empty() && interaction.is_adversarial {
            goals.insert(AttackGoal::GainUnauthorizedControl);
        }
        match interaction.kind {
            InteractionKind::PriceManipulation => {
                goals.insert(AttackGoal::ManipulatePrice);
            }
            InteractionKind::Liquidation => {
                goals.insert(AttackGoal::CreateBadDebt);
            }
            InteractionKind::ConfigurationChange => {
                goals.insert(AttackGoal::GainUnauthorizedControl);
            }
            _ => {}
        }
    }
    for pattern in &actors.adversarial_patterns {
        match pattern.kind {
            AdversarialKind::FrontRunning | AdversarialKind::SandwichAttack => {
                goals.insert(AttackGoal::ManipulatePrice);
                goals.insert(AttackGoal::ExhaustResources);
            }
            AdversarialKind::Griefing => {
                goals.insert(AttackGoal::FreezeFunds);
                goals.insert(AttackGoal::ExhaustResources);
            }
            AdversarialKind::StateManipulation => {
                goals.insert(AttackGoal::CorruptAccounting);
                goals.insert(AttackGoal::GainUnauthorizedControl);
            }
        }
    }

    let goal_list: Vec<AttackGoal> = goals.into_iter().collect();
    let goal_names: Vec<String> = goal_list.iter().map(|g| g.to_string()).collect();
    trace.entries.push(trace_entry(
        "goal:derive",
        RuleKind::GoalDerivation,
        vec!["5 semantic models"],
        goal_names.iter().map(|s| s.as_str()).collect(),
        !goal_list.is_empty(),
    ));

    goal_list
}

// ═══════════════════════════════════════════════════════════════
// Goal Preconditions
// ═══════════════════════════════════════════════════════════════

fn goal_precondition_specs() -> Vec<GoalPrecondition> {
    vec![
        GoalPrecondition {
            goal: AttackGoal::DrainAssets,
            required_capabilities: vec![],
            required_relations: vec!["conservation".into()],
            required_anomalies: vec!["unauthorized_egress".into()],
            derived_by: "goal:precondition:drain".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::BreakEconomicInvariant,
            required_capabilities: vec![],
            required_relations: vec!["collateral".into(), "conservation".into()],
            required_anomalies: vec![],
            derived_by: "goal:precondition:invariant".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::CorruptAccounting,
            required_capabilities: vec![],
            required_relations: vec!["accounting".into()],
            required_anomalies: vec![
                "egress_without_accounting".into(),
                "accounting_integrity_risk".into(),
            ],
            derived_by: "goal:precondition:accounting".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::CreateBadDebt,
            required_capabilities: vec![CapabilityKind::CanBorrowLiquidity],
            required_relations: vec!["debt".into()],
            required_anomalies: vec![],
            derived_by: "goal:precondition:bad_debt".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::GainUnauthorizedControl,
            required_capabilities: vec![],
            required_relations: vec![],
            required_anomalies: vec![],
            derived_by: "goal:precondition:control".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::BypassAuthority,
            required_capabilities: vec![],
            required_relations: vec![],
            required_anomalies: vec![],
            derived_by: "goal:precondition:bypass".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::FreezeFunds,
            required_capabilities: vec![],
            required_relations: vec![],
            required_anomalies: vec![],
            derived_by: "goal:precondition:freeze".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::PreventSettlement,
            required_capabilities: vec![],
            required_relations: vec![],
            required_anomalies: vec![],
            derived_by: "goal:precondition:settlement".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::ManipulatePrice,
            required_capabilities: vec![],
            required_relations: vec![],
            required_anomalies: vec![],
            derived_by: "goal:precondition:price".into(),
        },
        GoalPrecondition {
            goal: AttackGoal::ExhaustResources,
            required_capabilities: vec![],
            required_relations: vec![],
            required_anomalies: vec![],
            derived_by: "goal:precondition:exhaust".into(),
        },
    ]
}

fn check_goal_preconditions(
    goals: &[AttackGoal],
    cap_graph: &CapabilityGraph,
    economics: &EconomicReport,
    lifecycles: &ResourceLifecycleReport,
    temporal: &TemporalReport,
    trace: &mut ReasoningTrace,
) -> Vec<GoalPreconditionResult> {
    let specs = goal_precondition_specs();
    let cap_kinds = cap_graph.kinds();

    let relation_kinds: std::collections::BTreeSet<String> = economics
        .relations
        .iter()
        .map(|r| {
            match &r.kind {
                EconomicRelationKind::Conservation(_) => "conservation",
                EconomicRelationKind::Collateral(_) => "collateral",
                EconomicRelationKind::Debt(_) => "debt",
                EconomicRelationKind::Dependency(_) => "dependency",
            }
            .into()
        })
        .collect();

    let anomaly_kinds: std::collections::BTreeSet<String> = lifecycles
        .lifecycles
        .iter()
        .flat_map(|lc| lc.anomalies.iter().map(|a| a.kind.to_string()))
        .collect();

    let temporal_kinds: std::collections::BTreeSet<String> = temporal
        .anomalies
        .iter()
        .map(|a| a.kind.to_string())
        .collect();

    let mut results = Vec::new();
    for goal in goals {
        let spec = specs.iter().find(|s| s.goal == *goal);
        if let Some(spec) = spec {
            let missing_caps: Vec<CapabilityKind> = spec
                .required_capabilities
                .iter()
                .filter(|c| !cap_kinds.contains(c))
                .cloned()
                .collect();

            let mut missing_rels: Vec<String> = spec
                .required_relations
                .iter()
                .filter(|r| {
                    !relation_kinds.contains(*r)
                        && !temporal_kinds.iter().any(|t| t.contains(r.as_str()))
                })
                .cloned()
                .collect();
            missing_rels.extend(
                spec.required_anomalies
                    .iter()
                    .filter(|a| {
                        !anomaly_kinds.iter().any(|ac| ac.contains(a.as_str()))
                            && !temporal_kinds.iter().any(|t| t.contains(a.as_str()))
                    })
                    .cloned(),
            );

            let satisfied = missing_caps.is_empty() && missing_rels.is_empty();

            trace.entries.push(trace_entry(
                &spec.derived_by,
                RuleKind::GoalPreconditionCheck,
                vec![&goal.to_string()],
                vec![if satisfied { "feasible" } else { "infeasible" }],
                true,
            ));

            results.push(GoalPreconditionResult {
                goal: goal.clone(),
                satisfied,
                missing_capabilities: missing_caps,
                missing_relations: missing_rels,
                missing_anomalies: vec![],
            });
        } else {
            results.push(GoalPreconditionResult {
                goal: goal.clone(),
                satisfied: true,
                missing_capabilities: vec![],
                missing_relations: vec![],
                missing_anomalies: vec![],
            });
        }
    }
    results
}

// ═══════════════════════════════════════════════════════════════
// Reusable Search Primitives
// ═══════════════════════════════════════════════════════════════

struct SearchHit {
    path_id_suffix: String,
    steps: Vec<AttackStep>,
    required: Vec<CapabilityKind>,
    violated_constraint: String,
    violated_invariant: String,
    evidence: EvidenceGraph,
    severity: digger_ir::Severity,
    rule_id: String,
}

fn search_relations<F>(
    economics: &EconomicReport,
    cap_graph: &CapabilityGraph,
    _goal: &AttackGoal,
    filter: F,
) -> Vec<SearchHit>
where
    F: Fn(&EconomicRelationKind, &CapabilityGraph) -> Option<SearchHit>,
{
    let mut hits = Vec::new();
    for relation in &economics.relations {
        if let Some(hit) = filter(&relation.kind, cap_graph) {
            let mut evidence = hit.evidence;
            evidence.nodes.push(EvidenceNode {
                node_id: format!("econ:{}", relation.relation_id),
                source_model: EvidenceSource::EconomicRelation,
                model_id: relation.relation_id.clone(),
                description: format!("Economic relation violated: {}", relation.relation_id),
            });
            hits.push(SearchHit { evidence, ..hit });
        }
    }
    hits
}

fn search_lifecycle_anomalies<F>(
    lifecycles: &ResourceLifecycleReport,
    cap_graph: &CapabilityGraph,
    _goal: &AttackGoal,
    filter: F,
) -> Vec<SearchHit>
where
    F: Fn(
        &digger_resource_lifecycle::AnomalyKind,
        &ResourceLifecycle,
        &digger_resource_lifecycle::LifecycleAnomaly,
        &CapabilityGraph,
    ) -> Option<SearchHit>,
{
    let mut hits = Vec::new();
    for lc in &lifecycles.lifecycles {
        for anomaly in &lc.anomalies {
            if let Some(mut hit) = filter(&anomaly.kind, lc, anomaly, cap_graph) {
                hit.evidence.nodes.push(EvidenceNode {
                    node_id: format!("lifecycle:{}:{}", lc.function, anomaly.operation_index),
                    source_model: EvidenceSource::ResourceLifecycle,
                    model_id: format!("{}:{}", lc.function, anomaly.operation_index),
                    description: format!(
                        "Lifecycle anomaly: {:?} in {}",
                        anomaly.kind, lc.function
                    ),
                });
                hits.push(hit);
            }
        }
    }
    hits
}

fn search_temporal<F>(
    temporal: &TemporalReport,
    cap_graph: &CapabilityGraph,
    _goal: &AttackGoal,
    filter: F,
) -> Vec<SearchHit>
where
    F: Fn(&TemporalDependency, &CapabilityGraph) -> Option<SearchHit>,
{
    let mut hits = Vec::new();
    for dep in &temporal.dependencies {
        if let Some(mut hit) = filter(dep, cap_graph) {
            hit.evidence.nodes.push(EvidenceNode {
                node_id: format!("temporal:{}:{}", dep.predecessor, dep.successor),
                source_model: EvidenceSource::TemporalDependency,
                model_id: format!("{}:{}", dep.predecessor, dep.successor),
                description: format!(
                    "Temporal dependency: {} → {}",
                    dep.predecessor, dep.successor
                ),
            });
            hits.push(hit);
        }
    }
    hits
}

/// Search temporal sequences for paths satisfying a goal.
fn search_sequences<F>(
    temporal: &TemporalReport,
    cap_graph: &CapabilityGraph,
    _goal: &AttackGoal,
    filter: F,
) -> Vec<SearchHit>
where
    F: Fn(&digger_temporal::TransactionSequence, &CapabilityGraph) -> Option<SearchHit>,
{
    let mut hits = Vec::new();
    for seq in &temporal.sequences {
        if let Some(mut hit) = filter(seq, cap_graph) {
            let step_names: Vec<String> = seq.steps.iter().map(|s| s.function.clone()).collect();
            hit.evidence.nodes.push(EvidenceNode {
                node_id: format!("seq:{}", seq.sequence_id),
                source_model: EvidenceSource::TemporalSequence,
                model_id: seq.sequence_id.clone(),
                description: format!("Temporal sequence: {}", step_names.join(" → ")),
            });
            hits.push(hit);
        }
    }
    hits
}

fn search_patterns<F>(
    patterns: &[AdversarialPattern],
    cap_graph: &CapabilityGraph,
    _goal: &AttackGoal,
    filter: F,
) -> Vec<SearchHit>
where
    F: Fn(&AdversarialPattern, &CapabilityGraph) -> Option<SearchHit>,
{
    let mut hits = Vec::new();
    for pattern in patterns {
        if let Some(mut hit) = filter(pattern, cap_graph) {
            hit.evidence.nodes.push(EvidenceNode {
                node_id: format!("pattern:{}:{}", pattern.attacker, pattern.victim),
                source_model: EvidenceSource::ActorInteraction,
                model_id: format!("{}:{}", pattern.attacker, pattern.victim),
                description: format!(
                    "Adversarial pattern: {:?} {}→{}",
                    pattern.kind, pattern.attacker, pattern.victim
                ),
            });
            hits.push(hit);
        }
    }
    hits
}

fn search_verification<F>(
    verification: &VerificationReport,
    cap_graph: &CapabilityGraph,
    _goal: &AttackGoal,
    filter: F,
) -> Vec<SearchHit>
where
    F: Fn(&VerificationProperty, &CapabilityGraph) -> Option<SearchHit>,
{
    let mut hits = Vec::new();
    for property in &verification.properties {
        if let Some(hit) = filter(property, cap_graph) {
            // Feed VerificationProperty evidence into EvidenceGraph
            let mut evidence = hit.evidence;
            evidence.nodes.push(EvidenceNode {
                node_id: format!("verif:{}", property.property_id),
                source_model: EvidenceSource::VerificationProperty,
                model_id: property.property_id.clone(),
                description: format!("Verification property violated: {}", property.property_id),
            });
            // Also add evidence references from the property
            for ev_ref in &property.evidence {
                let ev_id = match ev_ref {
                    EvidenceRef::Authority { function, source } => {
                        format!("verif_ev:auth:{}:{}", function, source)
                    }
                    EvidenceRef::StateTransition {
                        function,
                        state_var,
                        kind,
                    } => format!("verif_ev:st:{}:{}:{}", function, state_var, kind),
                    EvidenceRef::LifecyclePhase {
                        function,
                        kind,
                        index,
                    } => format!("verif_ev:lc:{}:{}:{}", function, kind, index),
                    EvidenceRef::Operation {
                        function,
                        index,
                        kind,
                    } => format!("verif_ev:op:{}:{}:{}", function, index, kind),
                    EvidenceRef::Custom(s) => format!("verif_ev:custom:{}", s),
                };
                evidence.nodes.push(EvidenceNode {
                    node_id: ev_id.clone(),
                    source_model: EvidenceSource::VerificationProperty,
                    model_id: ev_id,
                    description: "Verification evidence reference".to_string(),
                });
            }
            hits.push(SearchHit { evidence, ..hit });
        }
    }
    hits
}

// ═══════════════════════════════════════════════════════════════
// Goal-Specific Search Functions
// ═══════════════════════════════════════════════════════════════

#[allow(clippy::too_many_arguments)]
fn search_paths_for_goal(
    goal: &AttackGoal,
    cap_graph: &CapabilityGraph,
    economics: &EconomicReport,
    temporal: &TemporalReport,
    actors: &MultiActorReport,
    lifecycles: &ResourceLifecycleReport,
    verification: &VerificationReport,
    _transitions: &StateTransitionReport,
    confidence_weights: &ConfidenceWeights,
    trace: &mut ReasoningTrace,
    rules: &mut Vec<ReasoningRule>,
) -> Vec<AttackPath> {
    let rule_id = format!("search:{}", goal);
    rules.push(make_rule(
        &rule_id,
        RuleKind::PathSearch,
        &format!("Search paths for goal {}", goal),
        vec!["CapabilityGraph", "6 semantic models"],
        vec!["goal preconditions satisfied"],
        vec!["AttackPath"],
        1.0,
    ));

    let hits = match goal {
        AttackGoal::DrainAssets => {
            let mut h = search_relations(economics, cap_graph, goal, |kind, caps| {
                if let EconomicRelationKind::Conservation(c) = kind {
                    if caps.has(&CapabilityKind::CanReenter)
                        && caps.has(&CapabilityKind::CanSplitAcrossTransactions)
                    {
                        let inflow = c.inflow_functions.first().cloned().unwrap_or_default();
                        let outflow = c.outflow_functions.first().cloned().unwrap_or_default();
                        if !inflow.is_empty() && !outflow.is_empty() {
                            let mut evidence = EvidenceGraph::empty();
                            evidence.edges.push(EvidenceEdge {
                                from: "cap:reenter".into(),
                                to: format!("conservation:{}", c.conserved_var),
                                kind: EvidenceEdgeKind::Violates,
                            });
                            return Some(SearchHit {
                                path_id_suffix: format!("drain:conservation:{}", c.conserved_var),
                                steps: vec![
                                    mk_step(
                                        0,
                                        CapabilityKind::CanReenter,
                                        &inflow,
                                        &c.conserved_var,
                                        "conservation",
                                    ),
                                    mk_step(
                                        1,
                                        CapabilityKind::CanReenter,
                                        &outflow,
                                        &c.conserved_var,
                                        "conservation",
                                    ),
                                ],
                                required: vec![
                                    CapabilityKind::CanReenter,
                                    CapabilityKind::CanSplitAcrossTransactions,
                                ],
                                violated_constraint: "conservation".into(),
                                violated_invariant: format!("conservation:{}", c.conserved_var),
                                evidence,
                                severity: digger_ir::Severity::Critical,
                                rule_id: "search:drain_assets".into(),
                            });
                        }
                    }
                }
                None
            });
            h.extend(search_lifecycle_anomalies(
                lifecycles,
                cap_graph,
                goal,
                |kind, lc, anomaly, caps| {
                    if matches!(
                        kind,
                        digger_resource_lifecycle::AnomalyKind::UnauthorizedEgress
                    ) && caps.has(&CapabilityKind::CanCallPublicFunction)
                    {
                        let var = lc.tracking_vars.first().cloned().unwrap_or_default();
                        let mut evidence = EvidenceGraph::empty();
                        evidence.edges.push(EvidenceEdge {
                            from: "cap:call_public".into(),
                            to: format!("lifecycle:{}:{}", lc.function, anomaly.operation_index),
                            kind: EvidenceEdgeKind::Enables,
                        });
                        return Some(SearchHit {
                            path_id_suffix: format!(
                                "drain:unauth:{}:{}",
                                lc.function, anomaly.operation_index
                            ),
                            steps: vec![mk_step(
                                0,
                                CapabilityKind::CanCallPublicFunction,
                                &lc.function,
                                &var,
                                "authorization",
                            )],
                            required: vec![CapabilityKind::CanCallPublicFunction],
                            violated_constraint: "authorization".into(),
                            violated_invariant: format!(
                                "unauth_egress:{}:{}",
                                lc.function, anomaly.operation_index
                            ),
                            evidence,
                            severity: anomaly.severity.clone(),
                            rule_id: "search:drain_assets".into(),
                        });
                    }
                    None
                },
            ));
            h
        }
        AttackGoal::BreakEconomicInvariant => {
            let h = search_relations(economics, cap_graph, goal, |kind, caps| {
                if let EconomicRelationKind::Collateral(c) = kind {
                    if caps.has(&CapabilityKind::CanManipulatePrice) {
                        let fn_name = c.enforcing_functions.first().cloned().unwrap_or_default();
                        let mut evidence = EvidenceGraph::empty();
                        evidence.edges.push(EvidenceEdge {
                            from: "cap:manipulate_price".into(),
                            to: format!("collateral:{}:{}", c.collateral_var, c.constrained_var),
                            kind: EvidenceEdgeKind::Violates,
                        });
                        return Some(SearchHit {
                            path_id_suffix: format!(
                                "invariant:collateral:{}:{}",
                                c.collateral_var, c.constrained_var
                            ),
                            steps: vec![
                                mk_step(
                                    0,
                                    CapabilityKind::CanManipulatePrice,
                                    &fn_name,
                                    &c.collateral_var,
                                    "collateralization",
                                ),
                                mk_step(
                                    1,
                                    CapabilityKind::CanCallPublicFunction,
                                    &fn_name,
                                    &c.constrained_var,
                                    "collateralization",
                                ),
                            ],
                            required: vec![CapabilityKind::CanManipulatePrice],
                            violated_constraint: "collateralization".into(),
                            violated_invariant: format!(
                                "collateral:{}:{}",
                                c.collateral_var, c.constrained_var
                            ),
                            evidence,
                            severity: digger_ir::Severity::Critical,
                            rule_id: "search:break_invariant".into(),
                        });
                    }
                }
                if let EconomicRelationKind::Conservation(c) = kind {
                    if caps.has(&CapabilityKind::CanReenter) {
                        let inflow = c.inflow_functions.first().cloned().unwrap_or_default();
                        let outflow = c.outflow_functions.first().cloned().unwrap_or_default();
                        if !inflow.is_empty() && !outflow.is_empty() {
                            let evidence = EvidenceGraph::empty();
                            return Some(SearchHit {
                                path_id_suffix: format!(
                                    "invariant:conservation:{}",
                                    c.conserved_var
                                ),
                                steps: vec![
                                    mk_step(
                                        0,
                                        CapabilityKind::CanReenter,
                                        &inflow,
                                        &c.conserved_var,
                                        "conservation",
                                    ),
                                    mk_step(
                                        1,
                                        CapabilityKind::CanReenter,
                                        &outflow,
                                        &c.conserved_var,
                                        "conservation",
                                    ),
                                ],
                                required: vec![CapabilityKind::CanReenter],
                                violated_constraint: "conservation".into(),
                                violated_invariant: format!("conservation:{}", c.conserved_var),
                                evidence,
                                severity: digger_ir::Severity::Critical,
                                rule_id: "search:break_invariant".into(),
                            });
                        }
                    }
                }
                None
            });
            h
        }
        AttackGoal::CorruptAccounting => {
            let mut h = search_relations(economics, cap_graph, goal, |kind, caps| {
                if let EconomicRelationKind::Conservation(c) = kind {
                    if caps.has(&CapabilityKind::CanReenter) {
                        let inflow = c.inflow_functions.first().cloned().unwrap_or_default();
                        let outflow = c.outflow_functions.first().cloned().unwrap_or_default();
                        if !inflow.is_empty() && !outflow.is_empty() {
                            let evidence = EvidenceGraph::empty();
                            return Some(SearchHit {
                                path_id_suffix: format!(
                                    "accounting:conservation:{}",
                                    c.conserved_var
                                ),
                                steps: vec![
                                    mk_step(
                                        0,
                                        CapabilityKind::CanReenter,
                                        &inflow,
                                        &c.conserved_var,
                                        "accounting",
                                    ),
                                    mk_step(
                                        1,
                                        CapabilityKind::CanReenter,
                                        &outflow,
                                        &c.conserved_var,
                                        "accounting",
                                    ),
                                ],
                                required: vec![CapabilityKind::CanReenter],
                                violated_constraint: "accounting".into(),
                                violated_invariant: format!("accounting:{}", c.conserved_var),
                                evidence,
                                severity: digger_ir::Severity::High,
                                rule_id: "search:corrupt_accounting".into(),
                            });
                        }
                    }
                }
                None
            });
            h.extend(search_lifecycle_anomalies(
                lifecycles,
                cap_graph,
                goal,
                |kind, lc, anomaly, caps| {
                    if matches!(
                        kind,
                        digger_resource_lifecycle::AnomalyKind::EgressWithoutAccountingDecrease
                    ) && caps.has(&CapabilityKind::CanReenter)
                    {
                        let var = lc.tracking_vars.first().cloned().unwrap_or_default();
                        let evidence = EvidenceGraph::empty();
                        return Some(SearchHit {
                            path_id_suffix: format!(
                                "accounting:egress:{}:{}",
                                lc.function, anomaly.operation_index
                            ),
                            steps: vec![mk_step(
                                0,
                                CapabilityKind::CanReenter,
                                &lc.function,
                                &var,
                                "accounting_integrity",
                            )],
                            required: vec![CapabilityKind::CanReenter],
                            violated_constraint: "accounting_integrity".into(),
                            violated_invariant: format!(
                                "accounting_risk:{}:{}",
                                lc.function, anomaly.operation_index
                            ),
                            evidence,
                            severity: anomaly.severity.clone(),
                            rule_id: "search:corrupt_accounting".into(),
                        });
                    }
                    None
                },
            ));
            h
        }
        AttackGoal::CreateBadDebt => search_relations(economics, cap_graph, goal, |kind, caps| {
            if let EconomicRelationKind::Debt(d) = kind {
                if caps.has(&CapabilityKind::CanBorrowLiquidity)
                    && caps.has(&CapabilityKind::CanSplitAcrossTransactions)
                {
                    let borrow_fn = d.borrowing_functions.first().cloned().unwrap_or_default();
                    let repay_fn = d.repayment_functions.first().cloned().unwrap_or_default();
                    if !borrow_fn.is_empty() {
                        let evidence = EvidenceGraph::empty();
                        return Some(SearchHit {
                            path_id_suffix: format!("bad_debt:{}", d.debt_var),
                            steps: vec![
                                mk_step(
                                    0,
                                    CapabilityKind::CanBorrowLiquidity,
                                    &borrow_fn,
                                    &d.debt_var,
                                    "solvency",
                                ),
                                mk_step(
                                    1,
                                    CapabilityKind::CanSplitAcrossTransactions,
                                    &repay_fn,
                                    &d.debt_var,
                                    "solvency",
                                ),
                            ],
                            required: vec![
                                CapabilityKind::CanBorrowLiquidity,
                                CapabilityKind::CanSplitAcrossTransactions,
                            ],
                            violated_constraint: "solvency".into(),
                            violated_invariant: format!("solvency:{}", d.debt_var),
                            evidence,
                            severity: digger_ir::Severity::Critical,
                            rule_id: "search:create_bad_debt".into(),
                        });
                    }
                }
            }
            None
        }),
        AttackGoal::GainUnauthorizedControl => {
            let mut h = search_verification(verification, cap_graph, goal, |prop, caps| {
                if matches!(prop.kind, PropertyKind::AuthorityInvariant)
                    && caps.has(&CapabilityKind::CanReenter)
                {
                    let evidence = EvidenceGraph::empty();
                    return Some(SearchHit {
                        path_id_suffix: format!("control:prop:{}", prop.property_id),
                        steps: vec![mk_step(
                            0,
                            CapabilityKind::CanReenter,
                            &prop.scope.first().cloned().unwrap_or_default(),
                            &prop.state_vars.first().cloned().unwrap_or_default(),
                            &prop.kind.to_string(),
                        )],
                        required: vec![CapabilityKind::CanReenter],
                        violated_constraint: prop.kind.to_string(),
                        violated_invariant: prop.property_id.clone(),
                        evidence,
                        severity: prop.severity.clone(),
                        rule_id: "search:gain_control".into(),
                    });
                }
                None
            });
            h.extend(search_patterns(
                &actors.adversarial_patterns,
                cap_graph,
                goal,
                |pattern, caps| {
                    if matches!(pattern.kind, AdversarialKind::StateManipulation)
                        && (caps.has(&CapabilityKind::CanReenter)
                            || caps.has(&CapabilityKind::CanSplitAcrossTransactions))
                    {
                        let cap = if caps.has(&CapabilityKind::CanReenter) {
                            CapabilityKind::CanReenter
                        } else {
                            CapabilityKind::CanSplitAcrossTransactions
                        };
                        let evidence = EvidenceGraph::empty();
                        return Some(SearchHit {
                            path_id_suffix: format!(
                                "control:state_manip:{}:{}",
                                pattern.attacker, pattern.victim
                            ),
                            steps: vec![mk_step(
                                0,
                                cap.clone(),
                                &pattern.function,
                                &pattern.state_var,
                                "state_integrity",
                            )],
                            required: vec![cap],
                            violated_constraint: "state_integrity".into(),
                            violated_invariant: format!(
                                "state_manip:{}:{}",
                                pattern.attacker, pattern.victim
                            ),
                            evidence,
                            severity: pattern.severity.clone(),
                            rule_id: "search:gain_control".into(),
                        });
                    }
                    None
                },
            ));
            h
        }
        AttackGoal::BypassAuthority => {
            search_verification(verification, cap_graph, goal, |prop, caps| {
                if matches!(prop.kind, PropertyKind::AccessControlRequirement)
                    && caps.has(&CapabilityKind::CanReenter)
                {
                    let evidence = EvidenceGraph::empty();
                    return Some(SearchHit {
                        path_id_suffix: format!("bypass:{}", prop.property_id),
                        steps: vec![mk_step(
                            0,
                            CapabilityKind::CanReenter,
                            &prop.scope.first().cloned().unwrap_or_default(),
                            &prop.state_vars.first().cloned().unwrap_or_default(),
                            &prop.kind.to_string(),
                        )],
                        required: vec![CapabilityKind::CanReenter],
                        violated_constraint: prop.kind.to_string(),
                        violated_invariant: prop.property_id.clone(),
                        evidence,
                        severity: prop.severity.clone(),
                        rule_id: "search:bypass_authority".into(),
                    });
                }
                None
            })
        }
        AttackGoal::FreezeFunds => {
            let mut h = search_patterns(
                &actors.adversarial_patterns,
                cap_graph,
                goal,
                |pattern, caps| {
                    if matches!(pattern.kind, AdversarialKind::Griefing)
                        && caps.has(&CapabilityKind::CanCallPublicFunction)
                    {
                        let evidence = EvidenceGraph::empty();
                        return Some(SearchHit {
                            path_id_suffix: format!(
                                "freeze:grief:{}:{}",
                                pattern.attacker, pattern.victim
                            ),
                            steps: vec![mk_step(
                                0,
                                CapabilityKind::CanCallPublicFunction,
                                &pattern.function,
                                &pattern.state_var,
                                "liveness",
                            )],
                            required: vec![CapabilityKind::CanCallPublicFunction],
                            violated_constraint: "liveness".into(),
                            violated_invariant: format!(
                                "grief:{}:{}",
                                pattern.attacker, pattern.victim
                            ),
                            evidence,
                            severity: pattern.severity.clone(),
                            rule_id: "search:freeze_funds".into(),
                        });
                    }
                    None
                },
            );
            h.extend(search_temporal(temporal, cap_graph, goal, |dep, caps| {
                if !dep.is_enforced && caps.has(&CapabilityKind::CanControlTransactionOrdering) {
                    let evidence = EvidenceGraph::empty();
                    return Some(SearchHit {
                        path_id_suffix: format!(
                            "freeze:temporal:{}:{}",
                            dep.predecessor, dep.successor
                        ),
                        steps: vec![mk_step(
                            0,
                            CapabilityKind::CanControlTransactionOrdering,
                            &dep.predecessor,
                            &dep.state_var,
                            "temporal_ordering",
                        )],
                        required: vec![CapabilityKind::CanControlTransactionOrdering],
                        violated_constraint: "temporal_ordering".into(),
                        violated_invariant: format!("dep:{}:{}", dep.predecessor, dep.successor),
                        evidence,
                        severity: digger_ir::Severity::High,
                        rule_id: "search:freeze_funds".into(),
                    });
                }
                None
            }));
            h
        }
        AttackGoal::PreventSettlement => {
            let mut h = search_temporal(temporal, cap_graph, goal, |dep, caps| {
                if caps.has(&CapabilityKind::CanObserveState)
                    && caps.has(&CapabilityKind::CanSplitAcrossTransactions)
                {
                    let evidence = EvidenceGraph::empty();
                    return Some(SearchHit {
                        path_id_suffix: format!(
                            "settlement:temporal:{}:{}",
                            dep.predecessor, dep.successor
                        ),
                        steps: vec![
                            mk_step(
                                0,
                                CapabilityKind::CanObserveState,
                                &dep.predecessor,
                                &dep.state_var,
                                "temporal_ordering",
                            ),
                            mk_step(
                                1,
                                CapabilityKind::CanCallPublicFunction,
                                &dep.successor,
                                &dep.state_var,
                                "temporal_ordering",
                            ),
                        ],
                        required: vec![
                            CapabilityKind::CanObserveState,
                            CapabilityKind::CanSplitAcrossTransactions,
                        ],
                        violated_constraint: "temporal_ordering".into(),
                        violated_invariant: format!("dep:{}:{}", dep.predecessor, dep.successor),
                        evidence,
                        severity: digger_ir::Severity::High,
                        rule_id: "search:prevent_settlement".into(),
                    });
                }
                None
            });
            // TemporalSequence integration: invalid sequences indicate settlement risk
            h.extend(search_sequences(temporal, cap_graph, goal, |seq, caps| {
                if !seq.is_valid && caps.has(&CapabilityKind::CanSplitAcrossTransactions) {
                    let step_names: Vec<String> =
                        seq.steps.iter().map(|s| s.function.clone()).collect();
                    let evidence = EvidenceGraph::empty();
                    return Some(SearchHit {
                        path_id_suffix: format!("settlement:seq:{}", seq.sequence_id),
                        steps: vec![mk_step(
                            0,
                            CapabilityKind::CanSplitAcrossTransactions,
                            &step_names.first().cloned().unwrap_or_default(),
                            "",
                            "sequence_ordering",
                        )],
                        required: vec![CapabilityKind::CanSplitAcrossTransactions],
                        violated_constraint: "sequence_ordering".into(),
                        violated_invariant: format!("seq:{}", seq.sequence_id),
                        evidence,
                        severity: digger_ir::Severity::High,
                        rule_id: "search:prevent_settlement".into(),
                    });
                }
                None
            }));
            h.extend(search_lifecycle_anomalies(
                lifecycles,
                cap_graph,
                goal,
                |kind, lc, _anomaly, caps| {
                    if matches!(
                        kind,
                        digger_resource_lifecycle::AnomalyKind::AccountingIntegrityRisk
                    ) && caps.has(&CapabilityKind::CanDelaySettlement)
                    {
                        let var = lc.tracking_vars.first().cloned().unwrap_or_default();
                        let has_settlement = lc.phases.iter().any(|p| {
                            matches!(p.kind, digger_resource_lifecycle::PhaseKind::Settlement)
                                && !p.authority_enforced
                        });
                        if has_settlement {
                            let evidence = EvidenceGraph::empty();
                            return Some(SearchHit {
                                path_id_suffix: format!("settlement:delay:{}", lc.function),
                                steps: vec![mk_step(
                                    0,
                                    CapabilityKind::CanDelaySettlement,
                                    &lc.function,
                                    &var,
                                    "settlement",
                                )],
                                required: vec![CapabilityKind::CanDelaySettlement],
                                violated_constraint: "settlement".into(),
                                violated_invariant: format!("delay_settlement:{}", lc.function),
                                evidence,
                                severity: digger_ir::Severity::High,
                                rule_id: "search:prevent_settlement".into(),
                            });
                        }
                    }
                    None
                },
            ));
            h
        }
        AttackGoal::ManipulatePrice => {
            let mut h = search_relations(economics, cap_graph, goal, |kind, caps| {
                if let EconomicRelationKind::Dependency(d) = kind {
                    if caps.has(&CapabilityKind::CanManipulatePrice) {
                        let evidence = EvidenceGraph::empty();
                        return Some(SearchHit {
                            path_id_suffix: format!("price:dep:{}:{}", d.influencer, d.influenced),
                            steps: vec![mk_step(
                                0,
                                CapabilityKind::CanManipulatePrice,
                                &d.functions.first().cloned().unwrap_or_default(),
                                &d.influencer,
                                "price_integrity",
                            )],
                            required: vec![CapabilityKind::CanManipulatePrice],
                            violated_constraint: "price_integrity".into(),
                            violated_invariant: format!(
                                "dependency:{}:{}",
                                d.influencer, d.influenced
                            ),
                            evidence,
                            severity: digger_ir::Severity::High,
                            rule_id: "search:manipulate_price".into(),
                        });
                    }
                }
                None
            });
            h.extend(search_patterns(
                &actors.adversarial_patterns,
                cap_graph,
                goal,
                |pattern, caps| {
                    if matches!(
                        pattern.kind,
                        AdversarialKind::FrontRunning | AdversarialKind::SandwichAttack
                    ) && caps.has(&CapabilityKind::CanObserveState)
                        && caps.has(&CapabilityKind::CanControlTransactionOrdering)
                    {
                        let evidence = EvidenceGraph::empty();
                        let steps = if matches!(pattern.kind, AdversarialKind::SandwichAttack) {
                            vec![
                                mk_step(
                                    0,
                                    CapabilityKind::CanControlTransactionOrdering,
                                    &pattern.function,
                                    &pattern.state_var,
                                    "fairness",
                                ),
                                mk_step(
                                    1,
                                    CapabilityKind::CanObserveState,
                                    &pattern.function,
                                    &pattern.state_var,
                                    "fairness",
                                ),
                                mk_step(
                                    2,
                                    CapabilityKind::CanControlTransactionOrdering,
                                    &pattern.function,
                                    &pattern.state_var,
                                    "fairness",
                                ),
                            ]
                        } else {
                            vec![
                                mk_step(
                                    0,
                                    CapabilityKind::CanObserveState,
                                    &pattern.function,
                                    &pattern.state_var,
                                    "fairness",
                                ),
                                mk_step(
                                    1,
                                    CapabilityKind::CanControlTransactionOrdering,
                                    &pattern.function,
                                    &pattern.state_var,
                                    "fairness",
                                ),
                            ]
                        };
                        return Some(SearchHit {
                            path_id_suffix: format!(
                                "price:{}:{}:{}",
                                pattern.kind, pattern.attacker, pattern.victim
                            ),
                            steps,
                            required: vec![
                                CapabilityKind::CanObserveState,
                                CapabilityKind::CanControlTransactionOrdering,
                            ],
                            violated_constraint: "fairness".into(),
                            violated_invariant: format!(
                                "{}:{}:{}",
                                pattern.kind, pattern.attacker, pattern.victim
                            ),
                            evidence,
                            severity: pattern.severity.clone(),
                            rule_id: "search:manipulate_price".into(),
                        });
                    }
                    None
                },
            ));
            h
        }
        AttackGoal::ExhaustResources => search_temporal(temporal, cap_graph, goal, |dep, caps| {
            if !dep.is_enforced && caps.has(&CapabilityKind::CanSplitAcrossTransactions) {
                let evidence = EvidenceGraph::empty();
                return Some(SearchHit {
                    path_id_suffix: format!(
                        "exhaust:temporal:{}:{}",
                        dep.predecessor, dep.successor
                    ),
                    steps: vec![mk_step(
                        0,
                        CapabilityKind::CanSplitAcrossTransactions,
                        &dep.predecessor,
                        &dep.state_var,
                        "resource_exhaustion",
                    )],
                    required: vec![CapabilityKind::CanSplitAcrossTransactions],
                    violated_constraint: "resource_exhaustion".into(),
                    violated_invariant: format!("exhaust:{}:{}", dep.predecessor, dep.successor),
                    evidence,
                    severity: digger_ir::Severity::Medium,
                    rule_id: "search:exhaust_resources".into(),
                });
            }
            None
        }),
    };

    let fired = !hits.is_empty();
    trace.entries.push(trace_entry(
        &rule_id,
        RuleKind::PathSearch,
        vec!["CapabilityGraph", "semantic models"],
        vec![&format!("{} paths", hits.len())],
        fired,
    ));

    hits.into_iter()
        .map(|hit| {
            let flat = hit.evidence.to_flat_evidence();
            let conf = compute_structural_confidence(
                &hit.evidence,
                &hit.required,
                cap_graph,
                confidence_weights,
            );
            AttackPath {
                path_id: format!("path:{}", hit.path_id_suffix),
                goal: goal.clone(),
                steps: hit.steps,
                required_capabilities: hit.required,
                violated_constraint: hit.violated_constraint,
                violated_invariant: hit.violated_invariant,
                evidence_graph: hit.evidence,
                evidence: flat,
                confidence: conf,
                severity: hit.severity,
                rules_applied: vec![hit.rule_id],
            }
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════
// Structural Confidence — configurable weights
// ═══════════════════════════════════════════════════════════════

fn compute_structural_confidence(
    evidence: &EvidenceGraph,
    required_caps: &[CapabilityKind],
    cap_graph: &CapabilityGraph,
    weights: &ConfidenceWeights,
) -> f64 {
    let diversity = evidence.model_diversity() as f64 / 7.0; // 7 source models now

    let prereq_score = if required_caps.is_empty() {
        1.0
    } else {
        let satisfied = required_caps
            .iter()
            .filter(|c| {
                cap_graph.nodes.iter().any(|n| n.kind == **c)
                    && cap_graph.prerequisites_satisfied(
                        &cap_graph
                            .nodes
                            .iter()
                            .find(|n| n.kind == **c)
                            .map(|n| n.capability_id.clone())
                            .unwrap_or_default(),
                    )
            })
            .count();
        satisfied as f64 / required_caps.len() as f64
    };

    let parsimony = if evidence.total_nodes() == 0 {
        0.5
    } else {
        1.0 / (1.0 + evidence.total_nodes() as f64 * 0.1)
    };

    let edge_density = if evidence.nodes.is_empty() {
        0.0
    } else {
        (evidence.edges.len() as f64 / evidence.nodes.len() as f64).min(1.0)
    };

    (diversity * weights.model_diversity
        + prereq_score * weights.prerequisite_satisfaction
        + parsimony * weights.path_parsimony
        + edge_density * weights.evidence_edge_density)
        .min(1.0)
}

// ═══════════════════════════════════════════════════════════════
// Hypothesis Construction
// ═══════════════════════════════════════════════════════════════

fn build_hypotheses(
    goals: &[AttackGoal],
    paths: &[AttackPath],
    precondition_results: &[GoalPreconditionResult],
) -> Vec<GoalHypothesis> {
    let mut hypotheses = Vec::new();

    for (goal, precond) in goals.iter().zip(precondition_results.iter()) {
        let goal_paths: Vec<AttackPath> =
            paths.iter().filter(|p| p.goal == *goal).cloned().collect();

        if goal_paths.is_empty() && !precond.satisfied {
            continue;
        }

        let mut combined_graph = EvidenceGraph::empty();
        for path in &goal_paths {
            combined_graph.merge(&path.evidence_graph);
        }

        let combined_flat = combined_graph.to_flat_evidence();

        let has_paths = !goal_paths.is_empty();
        let confidence = if goal_paths.is_empty() {
            0.0
        } else {
            let avg =
                goal_paths.iter().map(|p| p.confidence).sum::<f64>() / goal_paths.len() as f64;
            let diversity_bonus = combined_graph.model_diversity() as f64 / 7.0 * 0.1;
            (avg + diversity_bonus).min(1.0)
        };

        hypotheses.push(GoalHypothesis {
            goal: goal.clone(),
            paths: goal_paths,
            evidence_graph: combined_graph,
            evidence: combined_flat,
            confidence,
            is_feasible: !precond.satisfied || has_paths,
            precondition_result: precond.clone(),
        });
    }

    hypotheses
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn mk_step(
    index: usize,
    capability: CapabilityKind,
    function: &str,
    state_var: &str,
    violated_constraint: &str,
) -> AttackStep {
    AttackStep {
        index,
        capability,
        function: function.into(),
        state_var: state_var.into(),
        violated_constraint: violated_constraint.into(),
    }
}

pub fn report_to_json(report: &CapabilityReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

pub fn report_from_json(json: &str) -> Result<CapabilityReport, crate::models::AnalysisError> {
    Ok(serde_json::from_str(json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_parser::parse_program;

    fn empty_verification() -> VerificationReport {
        VerificationReport {
            protocol_id: "test".into(),
            properties: vec![],
            summary: VerificationSummary {
                total_properties: 0,
                by_kind: std::collections::BTreeMap::new(),
                by_origin: std::collections::BTreeMap::new(),
                by_severity: std::collections::BTreeMap::new(),
            },
        }
    }

    #[test]
    fn test_low_evidence_adversarial_path_below_graduated_threshold() {
        let mut evidence = EvidenceGraph::empty();
        for i in 0..50 {
            evidence.nodes.push(EvidenceNode {
                node_id: format!("node_{}", i),
                source_model: EvidenceSource::StateTransition,
                model_id: format!("model_{}", i),
                description: format!("evidence {}", i),
            });
        }
        evidence.edges.push(EvidenceEdge {
            from: "node_0".into(),
            to: "node_1".into(),
            kind: EvidenceEdgeKind::Enables,
        });

        let cap_graph = CapabilityGraph {
            nodes: vec![CapabilityNode {
                capability_id: "cap_reenter".into(),
                kind: CapabilityKind::CanReenter,
                functions: vec![],
                state_vars: vec![],
                detected_by: "test".into(),
            }],
            edges: vec![CapabilityEdge {
                from: "cap_reenter".into(),
                to: "cap_trigger".into(),
                kind: CapabilityEdgeKind::PrerequisiteOf,
            }],
            compositions: vec![],
        };

        let required_caps = vec![CapabilityKind::CanReenter];
        let weights = ConfidenceWeights::default();

        let confidence =
            compute_structural_confidence(&evidence, &required_caps, &cap_graph, &weights);

        // diversity = 1/7 ≈ 0.1429, prereq_score = 0.0 (cap_trigger missing),
        // parsimony = 1/(1+50*0.1) ≈ 0.1667, edge_density = 1/50 = 0.02
        // result ≈ 0.0571 + 0.0 + 0.0333 + 0.002 = 0.0924
        assert!(
            confidence < 0.7,
            "confidence {} must be below graduated threshold 0.7",
            confidence
        );
    }

    #[test]
    fn test_adversarial_engine_determinism() {
        let source = r#"
contract Test {
    mapping(address => uint256) public balances;
    function withdraw() external {
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
"#;
        let program = parse_program(source, "solidity");
        let transitions = digger_state_transitions::analyze_transitions(
            &digger_expansion::expand_program(&program, "test"),
            "test",
        );
        let lifecycles = digger_resource_lifecycle::analyze_lifecycles(
            &digger_expansion::expand_program(&program, "test"),
            "test",
        );
        let temporal = digger_temporal::analyze_temporal(&program, &transitions, "test");
        let actors = digger_actors::analyze_actors(&program, &transitions, &temporal, "test");
        let economics = digger_economics::analyze_economics(
            &program,
            &transitions,
            &lifecycles,
            &temporal,
            "test",
        );
        let verification = empty_verification();

        let r1 = analyze_adversarial(
            &program,
            &transitions,
            &lifecycles,
            &temporal,
            &actors,
            &economics,
            &verification,
            None,
            "test",
        );
        let j1 = report_to_json(&r1);

        let r2 = analyze_adversarial(
            &program,
            &transitions,
            &lifecycles,
            &temporal,
            &actors,
            &economics,
            &verification,
            None,
            "test",
        );
        let j2 = report_to_json(&r2);

        assert_eq!(j1, j2, "JSON output must be identical across runs");
        assert_eq!(
            j1.as_bytes(),
            j2.as_bytes(),
            "JSON output must be byte-identical"
        );
    }
}
