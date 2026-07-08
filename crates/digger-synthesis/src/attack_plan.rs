/// Generation 3.1e — Attack Plan Generation (Enhanced)
///
/// Produces deterministic multi-step attack plans with ordered actions,
/// required actors, affected contracts/accounts, expected state changes,
/// broken invariants, expected outcomes, and step dependency graphs.
use crate::models::*;
use crate::preconditions::PreconditionResult;
use std::collections::BTreeMap;

/// Dependency between two attack steps.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StepDependency {
    /// Step that must complete first.
    pub from_step: usize,
    /// Step that depends on the first.
    pub to_step: usize,
    /// What the dependency is about.
    pub reason: String,
}

/// Extended attack plan with deeper detail.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DetailedAttackPlan {
    /// Base plan.
    pub base: AttackPlan,
    /// Step dependency graph.
    pub dependencies: Vec<StepDependency>,
    /// Multi-contract interactions.
    pub cross_contract_flows: Vec<CrossContractFlow>,
    /// Transaction ordering requirements.
    pub ordering: TransactionOrdering,
    /// Estimated gas/compute for each step.
    pub resource_estimates: Vec<ResourceEstimate>,
}

/// A flow between two contracts/programs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossContractFlow {
    /// Source contract/program.
    pub from: String,
    /// Target contract/program.
    pub to: String,
    /// What flows between them.
    pub flows: Vec<String>,
    /// Whether this crosses a trust boundary.
    pub crosses_trust_boundary: bool,
}

/// Transaction ordering constraints.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionOrdering {
    /// Whether ordering matters.
    pub ordering_matters: bool,
    /// Steps that must be in the same transaction.
    pub same_transaction: Vec<Vec<usize>>,
    /// Steps that must be in different transactions.
    pub different_transactions: Vec<(usize, usize)>,
    /// Maximum transactions required.
    pub max_transactions: usize,
}

/// Resource estimate for a step.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResourceEstimate {
    /// Step index.
    pub step_index: usize,
    /// Estimated gas units (EVM) or compute units (Solana).
    pub compute_units: u64,
    /// Estimated storage cost.
    pub storage_cost: u64,
    /// Whether external calls are needed.
    pub needs_external_calls: bool,
}

/// Generate a basic attack plan from a validated exploit chain.
pub fn generate_attack_plan(
    chain: &ExploitChain,
    preconditions: &PreconditionResult,
    feasibility: &FeasibilityScore,
) -> AttackPlan {
    let plan_id = format!("plan-{}", chain.chain_id);
    let title = format!("Attack Plan: {}", chain.goal);

    let steps: Vec<AttackPlanStep> = chain
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| generate_plan_step(i, step))
        .collect();

    let required_actors = identify_actors(chain);
    let affected_targets = identify_targets(chain);

    let broken_invariants = chain
        .violated_invariants
        .iter()
        .map(|inv| BrokenInvariant {
            description: inv.clone(),
            broken_by: identify_breaking_step(chain, inv),
            impact: estimate_impact(inv),
        })
        .collect();

    let expected_outcomes = generate_outcomes(chain, feasibility);

    AttackPlan {
        plan_id,
        title,
        goal: chain.goal.clone(),
        steps,
        required_actors,
        affected_targets,
        broken_invariants,
        expected_outcomes,
        preconditions: PreconditionSummary {
            total: preconditions.preconditions.len(),
            satisfied: preconditions.satisfied,
            missing: preconditions.missing,
            unknown: preconditions.unknown,
        },
        feasibility: feasibility.overall,
        evidence: chain.evidence_provenance.clone(),
    }
}

/// Generate a detailed attack plan with dependencies and cross-contract flows.
pub fn generate_detailed_attack_plan(
    chain: &ExploitChain,
    preconditions: &PreconditionResult,
    feasibility: &FeasibilityScore,
) -> DetailedAttackPlan {
    let base = generate_attack_plan(chain, preconditions, feasibility);
    let dependencies = build_step_dependencies(chain);
    let cross_contract_flows = build_cross_contract_flows(chain);
    let ordering = analyze_ordering(chain);
    let resource_estimates = estimate_resources(chain);

    DetailedAttackPlan {
        base,
        dependencies,
        cross_contract_flows,
        ordering,
        resource_estimates,
    }
}

fn generate_plan_step(index: usize, step: &ExploitStep) -> AttackPlanStep {
    let mut parameters = Vec::new();
    for var in &step.affected_state {
        parameters.push(format!("state:{}", var));
    }
    for asset in &step.affected_assets {
        parameters.push(format!("asset:{}", asset));
    }

    AttackPlanStep {
        step_number: index + 1,
        target_function: step.function.clone(),
        actor: "attacker".into(),
        action: step.action.clone(),
        parameters,
        expected_state_changes: step.mutations.clone(),
        expected_balance_changes: step
            .affected_assets
            .iter()
            .map(|a| format!("{}: attacker gains", a))
            .collect(),
        preconditions: step.prerequisites.clone(),
        evidence: step.evidence_refs.clone(),
        success_reason: step.explanation.clone(),
    }
}

fn identify_actors(chain: &ExploitChain) -> Vec<AttackActor> {
    let mut actors = vec![AttackActor {
        actor_id: "attacker".into(),
        role: "primary exploit executor".into(),
        responsibilities: vec!["Initiate and execute all exploit steps".into()],
        required_permissions: chain
            .required_capabilities
            .iter()
            .map(|c| c.to_string())
            .collect(),
    }];

    if chain
        .required_capabilities
        .contains(&ExploitCapability::MultiTransaction)
    {
        actors.push(AttackActor {
            actor_id: "sequencer".into(),
            role: "transaction ordering controller".into(),
            responsibilities: vec![
                "Control transaction ordering across blocks".into(),
                "Ensure exploit transactions land in correct order".into(),
            ],
            required_permissions: vec!["TransactionOrdering".into()],
        });
    }

    if chain
        .required_capabilities
        .contains(&ExploitCapability::FlashLoan)
    {
        actors.push(AttackActor {
            actor_id: "liquidity_provider".into(),
            role: "flash loan provider".into(),
            responsibilities: vec!["Provide uncollateralized liquidity for one transaction".into()],
            required_permissions: vec!["FlashLoan".into()],
        });
    }

    if chain
        .required_capabilities
        .contains(&ExploitCapability::GovernanceInfluence)
    {
        actors.push(AttackActor {
            actor_id: "governance_actor".into(),
            role: "governance participant".into(),
            responsibilities: vec![
                "Submit or vote on governance proposals".into(),
                "May require token delegation or quorum".into(),
            ],
            required_permissions: vec!["GovernanceInfluence".into()],
        });
    }

    if chain
        .required_capabilities
        .contains(&ExploitCapability::OracleInfluence)
    {
        actors.push(AttackActor {
            actor_id: "oracle_manipulator".into(),
            role: "price oracle manipulator".into(),
            responsibilities: vec![
                "Manipulate oracle price feeds through DEX trades".into(),
                "May require large capital or flash loan".into(),
            ],
            required_permissions: vec!["OracleInfluence".into()],
        });
    }

    if chain
        .required_capabilities
        .contains(&ExploitCapability::TriggerLiquidation)
    {
        actors.push(AttackActor {
            actor_id: "liquidator".into(),
            role: "liquidation trigger".into(),
            responsibilities: vec!["Trigger liquidation of undercollateralized positions".into()],
            required_permissions: vec!["TriggerLiquidation".into()],
        });
    }

    actors
}

fn identify_targets(chain: &ExploitChain) -> Vec<AffectedTarget> {
    let mut targets = BTreeMap::new();

    for step in &chain.steps {
        let target = targets
            .entry(step.function.clone())
            .or_insert_with(|| AffectedTarget {
                target_id: step.function.clone(),
                target_type: classify_target_type(&step.function),
                changes: vec![],
                broken_invariants: vec![],
            });

        for mutation in &step.mutations {
            if !target.changes.contains(mutation) {
                target.changes.push(mutation.clone());
            }
        }
    }

    for inv in &chain.violated_invariants {
        for target in targets.values_mut() {
            if !target.broken_invariants.contains(inv) {
                target.broken_invariants.push(inv.clone());
            }
        }
    }

    targets.into_values().collect()
}

fn classify_target_type(function: &str) -> String {
    let lower = function.to_lowercase();
    if lower.contains("flash") || lower.contains("borrow") {
        "flash_loan_provider".into()
    } else if lower.contains("oracle") || lower.contains("price") {
        "oracle".into()
    } else if lower.contains("governance")
        || lower.contains("vote")
        || lower.contains("proposal")
        || lower.contains("propose")
    {
        "governance".into()
    } else if lower.contains("upgrade") || lower.contains("proxy") {
        "proxy".into()
    } else if lower.contains("token") || lower.contains("erc20") || lower.contains("transfer") {
        "token_contract".into()
    } else {
        "protocol_contract".into()
    }
}

fn identify_breaking_step(chain: &ExploitChain, invariant: &str) -> String {
    chain
        .steps
        .iter()
        .filter(|s| {
            s.mutations
                .iter()
                .any(|m| m.to_lowercase().contains(&invariant.to_lowercase()))
        })
        .map(|s| s.function.clone())
        .collect::<Vec<_>>()
        .join(", ")
        .or_if_empty(|| {
            chain
                .steps
                .iter()
                .map(|s| s.function.clone())
                .collect::<Vec<_>>()
                .join(", ")
        })
}

fn estimate_impact(invariant: &str) -> String {
    let lower = invariant.to_lowercase();
    if lower.contains("balance") || lower.contains("conservation") {
        "Direct fund loss — assets may be drained from protocol".into()
    } else if lower.contains("authority") || lower.contains("access") {
        "Privilege escalation — attacker gains unauthorized control".into()
    } else if lower.contains("state") || lower.contains("corruption") {
        "State corruption — protocol state becomes inconsistent".into()
    } else if lower.contains("order") || lower.contains("temporal") {
        "Ordering violation — temporal assumptions broken".into()
    } else {
        "Protocol invariant broken — unknown impact severity".into()
    }
}

fn generate_outcomes(chain: &ExploitChain, feasibility: &FeasibilityScore) -> Vec<String> {
    let mut outcomes = Vec::new();

    outcomes.push(format!(
        "Goal '{}' {}",
        chain.goal,
        if feasibility.overall >= 0.7 {
            "is highly achievable"
        } else if feasibility.overall >= 0.5 {
            "is achievable with effort"
        } else if feasibility.overall >= 0.3 {
            "has significant barriers"
        } else {
            "is unlikely to succeed"
        }
    ));

    if !chain.violated_invariants.is_empty() {
        outcomes.push(format!(
            "Breaks {} invariant(s): {}",
            chain.violated_invariants.len(),
            chain.violated_invariants.join(", ")
        ));
    }

    let caps: Vec<String> = chain
        .required_capabilities
        .iter()
        .map(|c| c.to_string())
        .collect();
    outcomes.push(format!(
        "Requires {} capability(ies): {}",
        caps.len(),
        caps.join(", ")
    ));

    outcomes.push(format!(
        "Confidence: {:.0}%, Feasibility: {:.0}% (range: {:.0}%-{:.0}%)",
        chain.confidence * 100.0,
        feasibility.overall * 100.0,
        feasibility.overall * 80.0,
        (feasibility.overall * 120.0).min(100.0),
    ));

    outcomes
}

/// Build step dependency graph.
fn build_step_dependencies(chain: &ExploitChain) -> Vec<StepDependency> {
    let mut deps = Vec::new();

    for (i, step) in chain.steps.iter().enumerate() {
        for prereq in &step.prerequisites {
            if prereq.contains("Step") {
                if let Some(num_str) = prereq.split_whitespace().nth(1) {
                    if let Ok(num) = num_str.parse::<usize>() {
                        if num < i {
                            deps.push(StepDependency {
                                from_step: num,
                                to_step: i,
                                reason: prereq.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Implicit dependency: state writes after reads on same variable
        for var in &step.affected_state {
            for (j, earlier_step) in chain.steps.iter().enumerate() {
                if j < i && earlier_step.affected_state.contains(var) {
                    deps.push(StepDependency {
                        from_step: j,
                        to_step: i,
                        reason: format!("Sequential access to state variable '{}'", var),
                    });
                }
            }
        }
    }

    deps
}

/// Build cross-contract flow analysis.
fn build_cross_contract_flows(chain: &ExploitChain) -> Vec<CrossContractFlow> {
    let mut flows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for step in &chain.steps {
        if step.required_capability == ExploitCapability::CrossContractCall
            || step.required_capability == ExploitCapability::CrossProgramInvocation
            || step.required_capability == ExploitCapability::FlashLoan
        {
            let key = (step.function.clone(), "external".to_string());
            if seen.insert(key.clone()) {
                flows.push(CrossContractFlow {
                    from: "attacker".into(),
                    to: step.function.clone(),
                    flows: step.affected_assets.clone(),
                    crosses_trust_boundary: true,
                });
            }
        }
    }

    flows
}

/// Analyze transaction ordering requirements.
fn analyze_ordering(chain: &ExploitChain) -> TransactionOrdering {
    let ordering_matters = chain
        .required_capabilities
        .contains(&ExploitCapability::MultiTransaction)
        || chain
            .required_capabilities
            .contains(&ExploitCapability::TransactionOrdering);

    let mut same_transaction = Vec::new();
    let mut different_transactions = Vec::new();

    // Steps that modify the same variable must be ordered
    for i in 0..chain.steps.len() {
        for j in (i + 1)..chain.steps.len() {
            let shared: Vec<String> = chain.steps[i]
                .affected_state
                .iter()
                .filter(|v| chain.steps[j].affected_state.contains(v))
                .cloned()
                .collect();
            if !shared.is_empty() {
                different_transactions.push((i, j));
            }
        }
    }

    // Steps in the same function are in the same transaction
    let mut func_groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, step) in chain.steps.iter().enumerate() {
        func_groups
            .entry(step.function.clone())
            .or_default()
            .push(i);
    }
    for indices in func_groups.values() {
        if indices.len() > 1 {
            same_transaction.push(indices.clone());
        }
    }

    let max_transactions = if different_transactions.is_empty() {
        1
    } else {
        different_transactions.len() + 1
    };

    TransactionOrdering {
        ordering_matters,
        same_transaction,
        different_transactions,
        max_transactions,
    }
}

/// Estimate resource requirements per step.
fn estimate_resources(chain: &ExploitChain) -> Vec<ResourceEstimate> {
    chain
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let compute = estimate_compute(step);
            let storage = estimate_storage(step);
            let has_external = step.required_capability == ExploitCapability::CrossContractCall
                || step.required_capability == ExploitCapability::CrossProgramInvocation
                || step.required_capability == ExploitCapability::FlashLoan;

            ResourceEstimate {
                step_index: i,
                compute_units: compute,
                storage_cost: storage,
                needs_external_calls: has_external,
            }
        })
        .collect()
}

fn estimate_compute(step: &ExploitStep) -> u64 {
    let base = match step.state_transition {
        ExploitState::Preparation => 21000,
        ExploitState::CapabilityAcquisition => 50000,
        ExploitState::Execution => 100000,
        ExploitState::StateCorruption => 80000,
        ExploitState::ValueExtraction => 150000,
        ExploitState::Exit => 30000,
        ExploitState::Cleanup => 25000,
        ExploitState::Preconditions => 10000,
    };

    let multiplier = match step.required_capability {
        ExploitCapability::FlashLoan => 3,
        ExploitCapability::CrossContractCall | ExploitCapability::CrossProgramInvocation => 2,
        ExploitCapability::GovernanceInfluence => 2,
        _ => 1,
    };

    base * multiplier
}

fn estimate_storage(step: &ExploitStep) -> u64 {
    let state_writes = step.affected_state.len() as u64;
    state_writes * 20000 // ~20k gas per SSTORE
}

trait OrIfEmpty {
    fn or_if_empty<F: FnOnce() -> String>(self, f: F) -> String;
}

impl OrIfEmpty for String {
    fn or_if_empty<F: FnOnce() -> String>(self, f: F) -> String {
        if self.is_empty() {
            f()
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain() -> ExploitChain {
        ExploitChain {
            chain_id: "test".into(),
            goal: "DrainAssets".into(),
            steps: vec![
                ExploitStep {
                    index: 0,
                    state_transition: ExploitState::Preparation,
                    function: "deposit".into(),
                    action: "deposit funds".into(),
                    required_capability: ExploitCapability::TransferAssets,
                    affected_state: vec!["pool".into()],
                    affected_assets: vec!["USDC".into()],
                    prerequisites: vec![],
                    mutations: vec!["add to pool".into()],
                    evidence_refs: vec![],
                    confidence: 0.7,
                    explanation: "deposit".into(),
                },
                ExploitStep {
                    index: 1,
                    state_transition: ExploitState::Execution,
                    function: "withdraw".into(),
                    action: "withdraw excessive".into(),
                    required_capability: ExploitCapability::AuthorityEscalation,
                    affected_state: vec!["pool".into(), "balance".into()],
                    affected_assets: vec!["USDC".into()],
                    prerequisites: vec!["Step 0 must succeed".into()],
                    mutations: vec!["drain pool".into()],
                    evidence_refs: vec![],
                    confidence: 0.7,
                    explanation: "no auth check on withdraw".into(),
                },
            ],
            required_capabilities: vec![
                ExploitCapability::AuthorityEscalation,
                ExploitCapability::TransferAssets,
            ],
            assumptions: vec!["pool has funds".into()],
            violated_invariants: vec!["conservation".into(), "authority".into()],
            evidence_provenance: vec![EvidenceReference {
                kind: EvidenceRefKind::GraphAnalysis,
                ref_id: "g1".into(),
                source: "graph".into(),
                derivation: "missing auth".into(),
            }],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        }
    }

    #[test]
    fn test_detailed_plan_generation() {
        let chain = test_chain();
        let preconditions = crate::preconditions::PreconditionResult {
            chain_id: "test".into(),
            preconditions: vec![],
            satisfied: 0,
            missing: 0,
            unknown: 0,
            all_satisfied: true,
        };
        let feasibility = FeasibilityScore {
            chain_id: "test".into(),
            overall: 0.7,
            components: FeasibilityComponents {
                precondition_score: 0.8,
                state_reachability: 0.9,
                invariant_violations: 0.6,
                trust_boundary_score: 0.3,
                economic_viability: 0.8,
                assumption_violations: 0.85,
                evidence_quality: 0.6,
                step_efficiency: 0.84,
            },
            explanation: "test".into(),
            verdict: FeasibilityVerdict::Feasible,
        };

        let plan = generate_detailed_attack_plan(&chain, &preconditions, &feasibility);
        assert_eq!(plan.base.steps.len(), 2);
        assert!(!plan.dependencies.is_empty()); // Step 1 depends on Step 0
        assert!(plan.ordering.ordering_matters || !plan.ordering.different_transactions.is_empty());
        assert_eq!(plan.resource_estimates.len(), 2);
        assert!(!plan.base.required_actors.is_empty());
    }

    #[test]
    fn test_multi_actor_plan() {
        let mut chain = test_chain();
        chain
            .required_capabilities
            .push(ExploitCapability::FlashLoan);
        chain
            .required_capabilities
            .push(ExploitCapability::GovernanceInfluence);

        let plan = generate_attack_plan(
            &chain,
            &crate::preconditions::PreconditionResult {
                chain_id: "test".into(),
                preconditions: vec![],
                satisfied: 0,
                missing: 0,
                unknown: 0,
                all_satisfied: true,
            },
            &FeasibilityScore {
                chain_id: "test".into(),
                overall: 0.7,
                components: FeasibilityComponents {
                    precondition_score: 0.8,
                    state_reachability: 0.9,
                    invariant_violations: 0.6,
                    trust_boundary_score: 0.3,
                    economic_viability: 0.8,
                    assumption_violations: 0.85,
                    evidence_quality: 0.6,
                    step_efficiency: 0.84,
                },
                explanation: "test".into(),
                verdict: FeasibilityVerdict::Feasible,
            },
        );

        assert!(plan.required_actors.len() >= 3); // attacker + sequencer + flash_loan + governance
    }

    #[test]
    fn test_target_classification() {
        assert_eq!(classify_target_type("flashLoan"), "flash_loan_provider");
        assert_eq!(classify_target_type("getPrice"), "oracle");
        assert_eq!(classify_target_type("propose"), "governance");
        assert_eq!(classify_target_type("transfer"), "token_contract");
    }
}
