/// Exploit chain synthesis — combines Gen 1/2 findings into complete attack chains.
use crate::engine::SynthesisConfig;
use crate::models::*;
use std::collections::BTreeSet;

/// Build the attacker capability graph from Gen 2 outputs.
pub fn build_capability_graph(inputs: &crate::engine::SynthesisInputs) -> SynthesisCapabilityGraph {
    let mut graph = SynthesisCapabilityGraph::empty();

    // Extract capabilities from adversarial analysis
    if let Some(adv) = inputs.adversarial {
        for cap in &adv.capabilities {
            let mapped = match cap.kind {
                digger_adversarial::CapabilityKind::CanBorrowLiquidity => {
                    Some(ExploitCapability::BorrowLiquidity)
                }
                digger_adversarial::CapabilityKind::CanManipulatePrice => {
                    Some(ExploitCapability::OracleInfluence)
                }
                digger_adversarial::CapabilityKind::CanReenter => {
                    Some(ExploitCapability::WriteState)
                }
                digger_adversarial::CapabilityKind::CanControlGovernance => {
                    Some(ExploitCapability::GovernanceInfluence)
                }
                digger_adversarial::CapabilityKind::CanExploitStorageCollision => {
                    Some(ExploitCapability::StorageCollision)
                }
                digger_adversarial::CapabilityKind::CanUpgradeProxy => {
                    Some(ExploitCapability::UpgradeProxy)
                }
                digger_adversarial::CapabilityKind::CanCallCrossContract => {
                    Some(ExploitCapability::CrossContractCall)
                }
                digger_adversarial::CapabilityKind::CanExploitDelegatecall => {
                    Some(ExploitCapability::DelegatecallExploit)
                }
                digger_adversarial::CapabilityKind::CanSplitAcrossTransactions => {
                    Some(ExploitCapability::MultiTransaction)
                }
                digger_adversarial::CapabilityKind::CanControlTransactionOrdering => {
                    Some(ExploitCapability::TransactionOrdering)
                }
                digger_adversarial::CapabilityKind::CanObserveState => {
                    Some(ExploitCapability::ReadState)
                }
                digger_adversarial::CapabilityKind::CanCallPublicFunction => {
                    Some(ExploitCapability::ReadState)
                }
                digger_adversarial::CapabilityKind::CanTriggerCallback => {
                    Some(ExploitCapability::CrossContractCall)
                }
                digger_adversarial::CapabilityKind::CanDeployContract => {
                    Some(ExploitCapability::DeployContract)
                }
                digger_adversarial::CapabilityKind::CanDelaySettlement => {
                    Some(ExploitCapability::MultiTransaction)
                }
            };

            if let Some(capability) = mapped {
                if !graph.capabilities.contains(&capability) {
                    graph.capabilities.push(capability.clone());
                    graph.evidence.insert(
                        capability,
                        cap.functions
                            .iter()
                            .map(|f| format!("function:{}", f))
                            .collect(),
                    );
                }
            }
        }
    }

    // Add structural capabilities from IR analysis
    if let Some(ir) = inputs.ir {
        for func in &ir.functions {
            let effects = &func.effects;
            if effects.state_mutation && !graph.has(&ExploitCapability::WriteState) {
                graph.capabilities.push(ExploitCapability::WriteState);
                graph.evidence.insert(
                    ExploitCapability::WriteState,
                    vec![format!("ir:{}", func.name)],
                );
            }
            if effects.external_call && !graph.has(&ExploitCapability::CrossContractCall) {
                graph
                    .capabilities
                    .push(ExploitCapability::CrossContractCall);
                graph.evidence.insert(
                    ExploitCapability::CrossContractCall,
                    vec![format!("ir:{}", func.name)],
                );
            }
            if effects.value_transfer && !graph.has(&ExploitCapability::TransferAssets) {
                graph.capabilities.push(ExploitCapability::TransferAssets);
                graph.evidence.insert(
                    ExploitCapability::TransferAssets,
                    vec![format!("ir:{}", func.name)],
                );
            }
        }
    }

    // Add trust-boundary crossings from cross-program analysis
    if let Some(ir) = inputs.ir {
        for edge in &ir.edges {
            if let digger_ir::Edge::External(e) = edge {
                if !graph.has(&ExploitCapability::CrossContractCall) {
                    graph
                        .capabilities
                        .push(ExploitCapability::CrossContractCall);
                }
                if e.risk_flags.contains(&"cpi".to_string())
                    && !graph.has(&ExploitCapability::CrossProgramInvocation)
                {
                    graph
                        .capabilities
                        .push(ExploitCapability::CrossProgramInvocation);
                }
            }
        }
    }

    // Add authority escalation from authority boundary analysis
    if let Some(ir) = inputs.ir {
        for edge in &ir.edges {
            if let digger_ir::Edge::Authority(a) = edge {
                if a.check_type == "missing" && !graph.has(&ExploitCapability::AuthorityEscalation)
                {
                    graph
                        .capabilities
                        .push(ExploitCapability::AuthorityEscalation);
                    graph.evidence.insert(
                        ExploitCapability::AuthorityEscalation,
                        vec![format!("authority_gap:{}", a.function)],
                    );
                }
            }
        }
    }

    // Add prerequisite links
    let links = build_capability_links(&graph);
    graph.links = links;

    graph
}

/// Build prerequisite and composition links between capabilities.
fn build_capability_links(graph: &SynthesisCapabilityGraph) -> Vec<CapabilityLink> {
    let mut links = Vec::new();

    // Flash loan requires liquidity
    if graph.has(&ExploitCapability::FlashLoan) {
        links.push(CapabilityLink {
            from: ExploitCapability::BorrowLiquidity,
            to: ExploitCapability::FlashLoan,
            kind: CapabilityLinkKind::Prerequisite,
        });
    }

    // Authority escalation enables write
    if graph.has(&ExploitCapability::AuthorityEscalation) {
        links.push(CapabilityLink {
            from: ExploitCapability::AuthorityEscalation,
            to: ExploitCapability::WriteState,
            kind: CapabilityLinkKind::Enables,
        });
    }

    // Multi-transaction enables ordering control
    if graph.has(&ExploitCapability::MultiTransaction) {
        links.push(CapabilityLink {
            from: ExploitCapability::MultiTransaction,
            to: ExploitCapability::TransactionOrdering,
            kind: CapabilityLinkKind::Enables,
        });
    }

    // Flash loan + price manipulation compose into flash loan price attack
    if graph.has(&ExploitCapability::FlashLoan) && graph.has(&ExploitCapability::OracleInfluence) {
        links.push(CapabilityLink {
            from: ExploitCapability::FlashLoan,
            to: ExploitCapability::OracleInfluence,
            kind: CapabilityLinkKind::Composes,
        });
    }

    // Cross-contract + authority escalation compose
    if graph.has(&ExploitCapability::CrossContractCall)
        && graph.has(&ExploitCapability::AuthorityEscalation)
    {
        links.push(CapabilityLink {
            from: ExploitCapability::CrossContractCall,
            to: ExploitCapability::AuthorityEscalation,
            kind: CapabilityLinkKind::Composes,
        });
    }

    links
}

/// Synthesize candidate exploit chains from Gen 1/2 evidence.
pub fn synthesize_chains(
    inputs: &crate::engine::SynthesisInputs,
    capability_graph: &SynthesisCapabilityGraph,
    config: &SynthesisConfig,
) -> Vec<ExploitChain> {
    let mut chains = Vec::new();

    // Strategy 1: Build chains from hypothesis evidence
    if let Some(adv) = inputs.adversarial {
        for hypothesis in &adv.hypotheses {
            if let Some(chain) = chain_from_hypothesis(hypothesis, capability_graph, inputs) {
                if chain.confidence >= config.min_confidence {
                    chains.push(chain);
                }
            }
        }
    }

    // Strategy 2: Build chains from vulnerability paths
    if let Some(ir) = inputs.ir {
        for edge in &ir.edges {
            if let digger_ir::Edge::Authority(a) = edge {
                if a.check_type == "missing" {
                    if let Some(chain) = chain_from_authority_gap(a, capability_graph, inputs) {
                        if chain.confidence >= config.min_confidence {
                            chains.push(chain);
                        }
                    }
                }
            }
        }
    }

    // Strategy 3: Build chains from economic invariant violations
    if let Some(econ) = inputs.economics {
        for invariant in &econ.invariants {
            if !invariant.is_satisfied {
                if let Some(chain) =
                    chain_from_economic_violation(invariant, capability_graph, inputs)
                {
                    if chain.confidence >= config.min_confidence {
                        chains.push(chain);
                    }
                }
            }
        }
    }

    // Strategy 4: Build chains from state corruption candidates
    if let Some(transitions) = inputs.transitions {
        for missing in &transitions.missing_transitions {
            if let Some(chain) = chain_from_state_corruption(missing, capability_graph, inputs) {
                if chain.confidence >= config.min_confidence {
                    chains.push(chain);
                }
            }
        }
    }

    // Strategy 5: Build chains from temporal anomalies
    if let Some(temporal) = inputs.temporal {
        for anomaly in &temporal.anomalies {
            if let Some(chain) = chain_from_temporal_anomaly(anomaly, capability_graph, inputs) {
                if chain.confidence >= config.min_confidence {
                    chains.push(chain);
                }
            }
        }
    }

    // Strategy 6: Build chains from resource lifecycle anomalies
    if let Some(lifecycles) = inputs.lifecycles {
        for lifecycle in &lifecycles.lifecycles {
            for anomaly in &lifecycle.anomalies {
                if let Some(chain) =
                    chain_from_lifecycle_anomaly(anomaly, lifecycle, capability_graph, inputs)
                {
                    if chain.confidence >= config.min_confidence {
                        chains.push(chain);
                    }
                }
            }
        }
    }

    // Limit total chains
    chains.truncate(config.max_chains);

    // Deduplicate by chain_id
    let mut seen = BTreeSet::new();
    chains.retain(|c| seen.insert(c.chain_id.clone()));

    chains
}

/// Build a chain from a Gen 2 hypothesis.
fn chain_from_hypothesis(
    hypothesis: &digger_adversarial::GoalHypothesis,
    _capability_graph: &SynthesisCapabilityGraph,
    _inputs: &crate::engine::SynthesisInputs,
) -> Option<ExploitChain> {
    if hypothesis.paths.is_empty() {
        return None;
    }

    let mut steps = Vec::new();
    let mut required_caps = BTreeSet::new();

    for (i, path) in hypothesis.paths.iter().enumerate() {
        for (j, step) in path.steps.iter().enumerate() {
            let cap = capability_from_function(&step.function, &step.state_var);
            required_caps.insert(cap.clone());

            steps.push(ExploitStep {
                index: i * 100 + j,
                state_transition: step_index_to_state(j),
                function: step.function.clone(),
                action: format!("Execute {} on {}", step.capability, step.function),
                required_capability: cap,
                affected_state: vec![step.state_var.clone()],
                affected_assets: vec![],
                prerequisites: vec![format!("Step {} must succeed", j)],
                mutations: vec![format!("Modify {} via {}", step.state_var, step.function)],
                evidence_refs: vec![format!("adversarial:{}", path.path_id)],
                confidence: hypothesis.confidence,
                explanation: format!(
                    "Step {} of attack path: {}",
                    j + 1,
                    step.violated_constraint
                ),
            });
        }
    }

    if steps.is_empty() {
        return None;
    }

    let goal_str = format!("{:?}", hypothesis.goal);
    let chain_id = compute_chain_id("hyp", &goal_str, &steps);

    Some(ExploitChain {
        chain_id,
        goal: goal_str,
        steps,
        required_capabilities: required_caps.into_iter().collect(),
        assumptions: vec!["Attacker has required capabilities".into()],
        violated_invariants: hypothesis
            .paths
            .iter()
            .map(|p| p.violated_invariant.clone())
            .collect(),
        evidence_provenance: vec![EvidenceReference {
            kind: EvidenceRefKind::Hypothesis,
            ref_id: hypothesis.goal.to_string(),
            source: "digger-adversarial".into(),
            derivation: "Capability analysis + path search".into(),
        }],
        confidence: hypothesis.confidence,
        severity: digger_ir::Severity::High,
        historical_similarity: vec![],
        rank: None,
        explanation: format!(
            "Exploit chain achieving {:?} through {} attack path(s)",
            hypothesis.goal,
            hypothesis.paths.len()
        ),
    })
}

/// Build a chain from an authority gap.
fn chain_from_authority_gap(
    authority: &digger_ir::AuthorityEdge,
    _capability_graph: &SynthesisCapabilityGraph,
    _inputs: &crate::engine::SynthesisInputs,
) -> Option<ExploitChain> {
    if authority.check_type != "missing" {
        return None;
    }

    let steps = vec![ExploitStep {
        index: 0,
        state_transition: ExploitState::Execution,
        function: authority.function.clone(),
        action: format!("Call {} without authority check", authority.function),
        required_capability: ExploitCapability::AuthorityEscalation,
        affected_state: vec![],
        affected_assets: vec![],
        prerequisites: vec![],
        mutations: vec![format!(
            "Execute {} without authorization",
            authority.function
        )],
        evidence_refs: vec![format!("authority:{}", authority.function)],
        confidence: 0.7,
        explanation: format!(
            "Function {} has no authority check (source: {})",
            authority.function, authority.authority_source
        ),
    }];

    let chain_id = compute_chain_id("auth", &authority.function, &steps);

    Some(ExploitChain {
        chain_id,
        goal: "GainUnauthorizedControl".into(),
        steps,
        required_capabilities: vec![ExploitCapability::AuthorityEscalation],
        assumptions: vec!["Attacker can call public function".into()],
        violated_invariants: vec!["Authority enforcement".into()],
        evidence_provenance: vec![EvidenceReference {
            kind: EvidenceRefKind::GraphAnalysis,
            ref_id: authority.function.clone(),
            source: "digger-graph:authority_analyzer".into(),
            derivation: "Missing authority check on public function".into(),
        }],
        confidence: 0.7,
        severity: digger_ir::Severity::High,
        historical_similarity: vec![],
        rank: None,
        explanation: format!(
            "Authority bypass: {} lacks authority enforcement",
            authority.function
        ),
    })
}

/// Build a chain from an economic invariant violation.
fn chain_from_economic_violation(
    invariant: &digger_economics::EconomicInvariant,
    _capability_graph: &SynthesisCapabilityGraph,
    _inputs: &crate::engine::SynthesisInputs,
) -> Option<ExploitChain> {
    let invariant_desc = format!("{}: {:?}", invariant.invariant_id, invariant.kind);
    let steps: Vec<ExploitStep> = invariant
        .functions
        .iter()
        .enumerate()
        .map(|(i, func)| ExploitStep {
            index: i,
            state_transition: ExploitState::StateCorruption,
            function: func.clone(),
            action: format!("Exploit via {}", func),
            required_capability: ExploitCapability::WriteState,
            affected_state: invariant.state_vars.clone(),
            affected_assets: vec![],
            prerequisites: vec![],
            mutations: vec![format!("Violate {} invariant", invariant.kind)],
            evidence_refs: vec![format!("economic:{}", invariant.invariant_id)],
            confidence: 0.6,
            explanation: format!("Function {} can violate {} invariant", func, invariant.kind),
        })
        .collect();

    if steps.is_empty() {
        return None;
    }

    let chain_id = compute_chain_id("econ", &invariant.invariant_id, &steps);

    Some(ExploitChain {
        chain_id,
        goal: "BreakEconomicInvariant".into(),
        steps,
        required_capabilities: vec![ExploitCapability::WriteState],
        assumptions: vec!["Attacker can interact with economic functions".into()],
        violated_invariants: vec![invariant_desc.clone()],
        evidence_provenance: vec![EvidenceReference {
            kind: EvidenceRefKind::EconomicInvariant,
            ref_id: invariant.invariant_id.clone(),
            source: "digger-economics".into(),
            derivation: "Economic invariant analysis".into(),
        }],
        confidence: 0.6,
        severity: digger_ir::Severity::High,
        historical_similarity: vec![],
        rank: None,
        explanation: format!("Economic invariant violation: {}", invariant_desc),
    })
}

/// Build a chain from a state corruption (missing transition).
fn chain_from_state_corruption(
    missing: &digger_state_transitions::MissingTransition,
    _capability_graph: &SynthesisCapabilityGraph,
    _inputs: &crate::engine::SynthesisInputs,
) -> Option<ExploitChain> {
    let steps = vec![ExploitStep {
        index: 0,
        state_transition: ExploitState::StateCorruption,
        function: missing.function.clone(),
        action: format!(
            "Exploit missing transition on {}",
            missing.expected_state_var
        ),
        required_capability: ExploitCapability::WriteState,
        affected_state: vec![missing.expected_state_var.clone()],
        affected_assets: vec![],
        prerequisites: vec![],
        mutations: vec![format!("Corrupt {}", missing.expected_state_var)],
        evidence_refs: vec![format!("transition:{}", missing.function)],
        confidence: 0.5,
        explanation: missing.reason.to_string(),
    }];

    let chain_id = compute_chain_id("state", &missing.expected_state_var, &steps);

    Some(ExploitChain {
        chain_id,
        goal: "CorruptAccounting".into(),
        steps,
        required_capabilities: vec![ExploitCapability::WriteState],
        assumptions: vec!["Attacker can trigger missing state transition".into()],
        violated_invariants: vec![missing.reason.to_string()],
        evidence_provenance: vec![EvidenceReference {
            kind: EvidenceRefKind::GraphAnalysis,
            ref_id: missing.function.clone(),
            source: "digger-state-transitions".into(),
            derivation: "Missing state transition detected".into(),
        }],
        confidence: 0.5,
        severity: digger_ir::Severity::Medium,
        historical_similarity: vec![],
        rank: None,
        explanation: format!(
            "State corruption: {} ({})",
            missing.expected_state_var, missing.reason
        ),
    })
}

/// Build a chain from a temporal anomaly.
fn chain_from_temporal_anomaly(
    anomaly: &digger_temporal::TemporalAnomaly,
    _capability_graph: &SynthesisCapabilityGraph,
    _inputs: &crate::engine::SynthesisInputs,
) -> Option<ExploitChain> {
    let steps = vec![
        ExploitStep {
            index: 0,
            state_transition: ExploitState::Preparation,
            function: anomaly.predecessor.clone(),
            action: format!("Call {} first", anomaly.predecessor),
            required_capability: ExploitCapability::MultiTransaction,
            affected_state: vec![anomaly.state_var.clone()],
            affected_assets: vec![],
            prerequisites: vec![],
            mutations: vec![format!("Set up {}", anomaly.state_var)],
            evidence_refs: vec![format!("temporal:{}", anomaly.state_var)],
            confidence: 0.6,
            explanation: format!("Temporal predecessor: {}", anomaly.predecessor),
        },
        ExploitStep {
            index: 1,
            state_transition: ExploitState::Execution,
            function: anomaly.successor.clone(),
            action: format!("Call {} to exploit ordering", anomaly.successor),
            required_capability: ExploitCapability::MultiTransaction,
            affected_state: vec![anomaly.state_var.clone()],
            affected_assets: vec![],
            prerequisites: vec![format!("{} must be called first", anomaly.predecessor)],
            mutations: vec![format!("Exploit {} ordering", anomaly.state_var)],
            evidence_refs: vec![format!("temporal:{}", anomaly.state_var)],
            confidence: 0.6,
            explanation: format!("Temporal successor: {}", anomaly.successor),
        },
    ];

    let chain_id = compute_chain_id("temporal", &anomaly.state_var, &steps);

    Some(ExploitChain {
        chain_id,
        goal: "PreventSettlement".into(),
        steps,
        required_capabilities: vec![ExploitCapability::MultiTransaction],
        assumptions: vec!["Attacker can control transaction ordering".into()],
        violated_invariants: vec![format!("Temporal ordering for {}", anomaly.state_var)],
        evidence_provenance: vec![EvidenceReference {
            kind: EvidenceRefKind::GraphAnalysis,
            ref_id: anomaly.state_var.clone(),
            source: "digger-temporal".into(),
            derivation: "Temporal ordering anomaly".into(),
        }],
        confidence: 0.6,
        severity: digger_ir::Severity::Medium,
        historical_similarity: vec![],
        rank: None,
        explanation: format!(
            "Temporal exploit: {} -> {} on {}",
            anomaly.predecessor, anomaly.successor, anomaly.state_var
        ),
    })
}

/// Build a chain from a lifecycle anomaly.
fn chain_from_lifecycle_anomaly(
    anomaly: &digger_resource_lifecycle::LifecycleAnomaly,
    lifecycle: &digger_resource_lifecycle::ResourceLifecycle,
    _capability_graph: &SynthesisCapabilityGraph,
    _inputs: &crate::engine::SynthesisInputs,
) -> Option<ExploitChain> {
    let steps = vec![ExploitStep {
        index: 0,
        state_transition: ExploitState::ValueExtraction,
        function: lifecycle.function.clone(),
        action: format!("Exploit lifecycle anomaly: {:?}", anomaly.kind),
        required_capability: ExploitCapability::TransferAssets,
        affected_state: lifecycle.tracking_vars.clone(),
        affected_assets: vec![],
        prerequisites: vec![],
        mutations: vec![anomaly.description.clone()],
        evidence_refs: vec![format!("lifecycle:{}", lifecycle.function)],
        confidence: 0.6,
        explanation: anomaly.description.clone(),
    }];

    let chain_id = compute_chain_id("lifecycle", &lifecycle.function, &steps);

    Some(ExploitChain {
        chain_id,
        goal: "DrainAssets".into(),
        steps,
        required_capabilities: vec![ExploitCapability::TransferAssets],
        assumptions: vec!["Attacker can trigger lifecycle anomaly".into()],
        violated_invariants: vec![anomaly.description.clone()],
        evidence_provenance: vec![EvidenceReference {
            kind: EvidenceRefKind::GraphAnalysis,
            ref_id: lifecycle.function.clone(),
            source: "digger-resource-lifecycle".into(),
            derivation: "Resource lifecycle anomaly detected".into(),
        }],
        confidence: 0.6,
        severity: digger_ir::Severity::High,
        historical_similarity: vec![],
        rank: None,
        explanation: format!(
            "Lifecycle exploit: {} ({})",
            lifecycle.function, anomaly.description
        ),
    })
}

// ─── Helpers ───────────────────────────────────────────────────────

fn capability_from_function(function: &str, _state_var: &str) -> ExploitCapability {
    let lower = function.to_lowercase();
    if lower.contains("flash") || lower.contains("borrow") {
        ExploitCapability::FlashLoan
    } else if lower.contains("oracle") || lower.contains("price") {
        ExploitCapability::OracleInfluence
    } else if lower.contains("governance") || lower.contains("vote") {
        ExploitCapability::GovernanceInfluence
    } else if lower.contains("upgrade") {
        ExploitCapability::UpgradeProxy
    } else if lower.contains("delegate") {
        ExploitCapability::DelegatecallExploit
    } else if lower.contains("mint") {
        ExploitCapability::MintTokens
    } else if lower.contains("transfer") || lower.contains("withdraw") {
        ExploitCapability::TransferAssets
    } else {
        ExploitCapability::WriteState
    }
}

fn step_index_to_state(index: usize) -> ExploitState {
    match index {
        0 => ExploitState::Preparation,
        1 => ExploitState::CapabilityAcquisition,
        2 => ExploitState::Execution,
        _ => ExploitState::StateCorruption,
    }
}

fn compute_chain_id(prefix: &str, seed: &str, steps: &[ExploitStep]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(seed.as_bytes());
    for step in steps {
        hasher.update(step.function.as_bytes());
        hasher.update(step.action.as_bytes());
    }
    let hash = format!("{:x}", hasher.finalize());
    format!("chain-{}-{}", prefix, &hash[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_graph_empty() {
        let graph = SynthesisCapabilityGraph::empty();
        assert!(!graph.has(&ExploitCapability::FlashLoan));
    }

    #[test]
    fn test_capability_prerequisites() {
        let mut graph = SynthesisCapabilityGraph::empty();
        graph.capabilities.push(ExploitCapability::BorrowLiquidity);
        graph.capabilities.push(ExploitCapability::FlashLoan);
        graph.links.push(CapabilityLink {
            from: ExploitCapability::BorrowLiquidity,
            to: ExploitCapability::FlashLoan,
            kind: CapabilityLinkKind::Prerequisite,
        });
        assert!(graph.prerequisites_satisfied(&ExploitCapability::FlashLoan));
    }

    #[test]
    fn test_exploit_state_transitions() {
        assert!(ExploitState::Preconditions
            .valid_transitions()
            .contains(&ExploitState::Preparation));
        assert!(ExploitState::Cleanup.valid_transitions().is_empty());
    }

    #[test]
    fn test_chain_id_deterministic() {
        let steps = vec![];
        let id1 = compute_chain_id("test", "seed", &steps);
        let id2 = compute_chain_id("test", "seed", &steps);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_capability_from_function() {
        assert_eq!(
            capability_from_function("flashLoan", ""),
            ExploitCapability::FlashLoan
        );
        assert_eq!(
            capability_from_function("getPrice", ""),
            ExploitCapability::OracleInfluence
        );
        assert_eq!(
            capability_from_function("transfer", ""),
            ExploitCapability::TransferAssets
        );
    }

    #[test]
    fn test_build_capability_graph() {
        let ir = digger_ir::SystemIR {
            program_id: "test_prog".into(),
            language: digger_ir::Language::Solidity,
            functions: vec![digger_ir::Function {
                id: "f1".into(),
                name: "withdraw".into(),
                contract: String::new(),
                visibility: digger_ir::Visibility::Public,
                inputs: vec![],
                outputs: vec![],
                modifiers: vec![],
                effects: digger_ir::Effects {
                    state_mutation: true,
                    external_call: true,
                    authority_required: false,
                    value_transfer: true,
                    has_arithmetic: false,
                    has_temporal_guard: false,
                    value_flow: None,
                    has_unchecked_arithmetic: false,
                    writes_caller_scoped_state: false,
                    has_precision_loss_ordering: false,
                },
            }],
            state: vec![],
            edges: vec![],
        };
        let inputs = crate::engine::SynthesisInputs {
            ir: Some(&ir),
            expansion: None,
            transitions: None,
            lifecycles: None,
            temporal: None,
            actors: None,
            economics: None,
            verification: None,
            adversarial: None,
            protocol: None,
            surface: None,
        };
        let graph = build_capability_graph(&inputs);
        assert!(!graph.capabilities.is_empty());
        assert!(graph.has(&ExploitCapability::WriteState));
        assert!(graph.has(&ExploitCapability::CrossContractCall));
        assert!(graph.has(&ExploitCapability::TransferAssets));

        let graph2 = build_capability_graph(&inputs);
        assert_eq!(
            serde_json::to_string(&graph).unwrap(),
            serde_json::to_string(&graph2).unwrap()
        );
    }

    #[test]
    fn test_synthesize_chains() {
        let ir = digger_ir::SystemIR {
            program_id: "test_prog".into(),
            language: digger_ir::Language::Solidity,
            functions: vec![],
            state: vec![],
            edges: vec![digger_ir::Edge::Authority(digger_ir::AuthorityEdge {
                function: "withdraw".into(),
                authority_source: "msg_sender".into(),
                check_type: "missing".into(),
            })],
        };
        let inputs = crate::engine::SynthesisInputs {
            ir: Some(&ir),
            expansion: None,
            transitions: None,
            lifecycles: None,
            temporal: None,
            actors: None,
            economics: None,
            verification: None,
            adversarial: None,
            protocol: None,
            surface: None,
        };
        let graph = SynthesisCapabilityGraph::empty();
        let config = crate::engine::SynthesisConfig::default();
        let chains = synthesize_chains(&inputs, &graph, &config);
        assert!(!chains.is_empty());
        assert!(chains[0].chain_id.starts_with("chain-auth-"));
    }
}
