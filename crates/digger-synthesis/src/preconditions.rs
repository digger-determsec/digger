/// Generation 3.1a — Deterministic Precondition Solver
///
/// Enumerates every condition required for an exploit chain and validates
/// each one against the IR, graph analyses, and protocol state.
/// Reports which preconditions are satisfied, missing, or unknown.
use crate::models::*;

/// Result of precondition solving for a single chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreconditionResult {
    /// Chain being validated.
    pub chain_id: String,
    /// All preconditions enumerated.
    pub preconditions: Vec<Precondition>,
    /// Count of satisfied preconditions.
    pub satisfied: usize,
    /// Count of missing preconditions.
    pub missing: usize,
    /// Count of unknown preconditions.
    pub unknown: usize,
    /// Overall feasibility: all satisfied = true.
    pub all_satisfied: bool,
}

/// A single precondition that must hold for an exploit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Precondition {
    /// What this precondition checks.
    pub kind: PreconditionKind,
    /// Human-readable description.
    pub description: String,
    /// Current status.
    pub status: PreconditionStatus,
    /// Evidence supporting or contradicting this precondition.
    pub evidence: Vec<String>,
    /// The step index this precondition applies to (None = overall).
    pub step_index: Option<usize>,
}

/// Kind of precondition.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PreconditionKind {
    /// Caller has required permission/role.
    Permission,
    /// Caller owns or controls a required account.
    Ownership,
    /// Account has sufficient balance/lamports.
    Balance,
    /// Protocol has sufficient liquidity.
    Liquidity,
    /// Oracle can provide required price.
    OracleState,
    /// Governance quorum/voting state allows action.
    GovernanceState,
    /// Protocol configuration parameter allows the operation.
    ProtocolConfig,
    /// Timing/window constraint is met.
    Timing,
    /// External dependency (another contract/program) is available.
    ExternalDependency,
    /// Required account exists and is initialized.
    AccountExists,
    /// Account has required data layout.
    AccountLayout,
    /// PDA derivation will succeed with given seeds.
    PdaDerivation,
    /// Transaction size is within limits.
    TransactionSize,
    /// Compute budget is sufficient.
    ComputeBudget,
}

/// Status of a precondition.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PreconditionStatus {
    /// Verified to hold.
    Satisfied,
    /// Verified to NOT hold.
    Missing,
    /// Cannot determine from available evidence.
    Unknown,
}

/// Solve all preconditions for an exploit chain.
pub fn solve_preconditions(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> PreconditionResult {
    let mut preconditions = Vec::new();

    // Global preconditions (apply to entire chain)
    preconditions.extend(check_global_preconditions(chain, inputs));

    // Per-step preconditions
    for step in &chain.steps {
        preconditions.extend(check_step_preconditions(step, inputs));
    }

    let satisfied = preconditions
        .iter()
        .filter(|p| p.status == PreconditionStatus::Satisfied)
        .count();
    let missing = preconditions
        .iter()
        .filter(|p| p.status == PreconditionStatus::Missing)
        .count();
    let unknown = preconditions
        .iter()
        .filter(|p| p.status == PreconditionStatus::Unknown)
        .count();

    PreconditionResult {
        chain_id: chain.chain_id.clone(),
        preconditions,
        satisfied,
        missing,
        unknown,
        all_satisfied: missing == 0,
    }
}

/// Check global preconditions for the entire chain.
fn check_global_preconditions(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> Vec<Precondition> {
    let mut preconditions = Vec::new();

    // Check: required capabilities are achievable
    for cap in &chain.required_capabilities {
        preconditions.push(Precondition {
            kind: PreconditionKind::Permission,
            description: format!("Attacker must have capability: {}", cap),
            status: check_capability_available(cap, inputs),
            evidence: vec![format!("capability:{}", cap)],
            step_index: None,
        });
    }

    // Check: protocol functions exist and are callable
    if let Some(ir) = inputs.ir {
        for step in &chain.steps {
            let func_exists = ir.functions.iter().any(|f| f.name == step.function);
            preconditions.push(Precondition {
                kind: PreconditionKind::ExternalDependency,
                description: format!("Function '{}' must exist", step.function),
                status: if func_exists {
                    PreconditionStatus::Satisfied
                } else {
                    PreconditionStatus::Missing
                },
                evidence: vec![format!("ir:function:{}", step.function)],
                step_index: None,
            });
        }
    }

    // Check: no contradictory authority constraints
    if let Some(ir) = inputs.ir {
        let all_enforced: bool = !chain.steps.iter().any(|step| {
            ir.edges.iter().any(|e| {
                matches!(e, digger_ir::Edge::Authority(a) if a.function == step.function && a.check_type == "missing")
            })
        });

        if all_enforced
            && chain
                .required_capabilities
                .contains(&ExploitCapability::AuthorityEscalation)
        {
            preconditions.push(Precondition {
                kind: PreconditionKind::Permission,
                description: "Authority escalation requires missing authority check".into(),
                status: PreconditionStatus::Missing,
                evidence: vec!["authority:all_enforced".into()],
                step_index: None,
            });
        }
    }

    preconditions
}

/// Check preconditions for a single exploit step.
fn check_step_preconditions(
    step: &ExploitStep,
    inputs: &crate::engine::SynthesisInputs,
) -> Vec<Precondition> {
    let mut preconditions = Vec::new();

    // Check: function exists and is accessible
    if let Some(ir) = inputs.ir {
        let func_exists = ir.functions.iter().any(|f| f.name == step.function);
        preconditions.push(Precondition {
            kind: PreconditionKind::ExternalDependency,
            description: format!(
                "Step {}: Function '{}' must exist",
                step.index, step.function
            ),
            status: if func_exists {
                PreconditionStatus::Satisfied
            } else {
                PreconditionStatus::Missing
            },
            evidence: vec![format!("ir:function:{}", step.function)],
            step_index: Some(step.index),
        });

        // Check: function has required effects
        if let Some(func) = ir.functions.iter().find(|f| f.name == step.function) {
            match step.required_capability {
                ExploitCapability::WriteState => {
                    preconditions.push(Precondition {
                        kind: PreconditionKind::Permission,
                        description: format!(
                            "Step {}: Function '{}' must write state",
                            step.index, step.function
                        ),
                        status: if func.effects.state_mutation {
                            PreconditionStatus::Satisfied
                        } else {
                            PreconditionStatus::Missing
                        },
                        evidence: vec![format!(
                            "ir:effects:state_mutation:{}",
                            func.effects.state_mutation
                        )],
                        step_index: Some(step.index),
                    });
                }
                ExploitCapability::CrossContractCall
                | ExploitCapability::CrossProgramInvocation => {
                    preconditions.push(Precondition {
                        kind: PreconditionKind::ExternalDependency,
                        description: format!(
                            "Step {}: Function '{}' must make external calls",
                            step.index, step.function
                        ),
                        status: if func.effects.external_call {
                            PreconditionStatus::Satisfied
                        } else {
                            PreconditionStatus::Missing
                        },
                        evidence: vec![format!(
                            "ir:effects:external_call:{}",
                            func.effects.external_call
                        )],
                        step_index: Some(step.index),
                    });
                }
                ExploitCapability::TransferAssets => {
                    preconditions.push(Precondition {
                        kind: PreconditionKind::Balance,
                        description: format!(
                            "Step {}: Function '{}' must transfer value",
                            step.index, step.function
                        ),
                        status: if func.effects.value_transfer {
                            PreconditionStatus::Satisfied
                        } else {
                            PreconditionStatus::Missing
                        },
                        evidence: vec![format!(
                            "ir:effects:value_transfer:{}",
                            func.effects.value_transfer
                        )],
                        step_index: Some(step.index),
                    });
                }
                _ => {}
            }
        }
    }

    // Check: authority requirement
    if step.required_capability == ExploitCapability::AuthorityEscalation {
        if let Some(ir) = inputs.ir {
            let has_auth_check = ir.edges.iter().any(|e| {
                matches!(e, digger_ir::Edge::Authority(a) if a.function == step.function && a.check_type != "missing")
            });
            preconditions.push(Precondition {
                kind: PreconditionKind::Permission,
                description: format!(
                    "Step {}: Function '{}' must NOT have authority check (for escalation)",
                    step.index, step.function
                ),
                status: if has_auth_check {
                    PreconditionStatus::Missing
                } else {
                    PreconditionStatus::Satisfied
                },
                evidence: vec![format!("authority:{}", step.function)],
                step_index: Some(step.index),
            });
        }
    }

    // Check: state variable exists
    for var in &step.affected_state {
        if let Some(ir) = inputs.ir {
            let exists = ir.state.iter().any(|s| s.name == *var);
            preconditions.push(Precondition {
                kind: PreconditionKind::AccountExists,
                description: format!("Step {}: State variable '{}' must exist", step.index, var),
                status: if exists {
                    PreconditionStatus::Satisfied
                } else {
                    PreconditionStatus::Unknown
                },
                evidence: vec![format!("ir:state:{}", var)],
                step_index: Some(step.index),
            });
        }
    }

    // Check: prerequisites from previous steps
    for prereq in &step.prerequisites {
        if prereq.contains("Step") {
            // Parse step reference to check if prerequisite step was already executed
            if let Some(num_str) = prereq.split_whitespace().nth(1) {
                if let Ok(num) = num_str.parse::<usize>() {
                    preconditions.push(Precondition {
                        kind: PreconditionKind::Timing,
                        description: prereq.clone(),
                        status: if num < step.index {
                            PreconditionStatus::Satisfied
                        } else {
                            PreconditionStatus::Missing
                        },
                        evidence: vec![format!("ordering:{}<{}", num, step.index)],
                        step_index: Some(step.index),
                    });
                }
            }
        }
    }

    preconditions
}

/// Check if a capability is available given the IR evidence.
fn check_capability_available(
    cap: &ExploitCapability,
    inputs: &crate::engine::SynthesisInputs,
) -> PreconditionStatus {
    match cap {
        ExploitCapability::ReadState | ExploitCapability::WriteState => {
            PreconditionStatus::Satisfied
        }
        ExploitCapability::AuthorityEscalation => {
            // Checked per-step in check_step_preconditions
            PreconditionStatus::Satisfied
        }
        ExploitCapability::CrossContractCall | ExploitCapability::CrossProgramInvocation => {
            if let Some(ir) = inputs.ir {
                let has_external = ir
                    .edges
                    .iter()
                    .any(|e| matches!(e, digger_ir::Edge::External(_)));
                if has_external {
                    PreconditionStatus::Satisfied
                } else {
                    PreconditionStatus::Missing
                }
            } else {
                PreconditionStatus::Unknown
            }
        }
        ExploitCapability::TransferAssets => {
            if let Some(ir) = inputs.ir {
                let has_transfer = ir.functions.iter().any(|f| f.effects.value_transfer);
                if has_transfer {
                    PreconditionStatus::Satisfied
                } else {
                    PreconditionStatus::Missing
                }
            } else {
                PreconditionStatus::Unknown
            }
        }
        ExploitCapability::FlashLoan => PreconditionStatus::Unknown,
        ExploitCapability::OracleInfluence => PreconditionStatus::Unknown,
        ExploitCapability::GovernanceInfluence => PreconditionStatus::Unknown,
        _ => PreconditionStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain_preconditions() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.5,
            severity: digger_ir::Severity::Medium,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };

        let inputs = crate::engine::SynthesisInputs {
            ir: None,
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

        let result = solve_preconditions(&chain, &inputs);
        assert!(result.all_satisfied);
        assert_eq!(result.preconditions.len(), 0);
    }

    #[test]
    fn test_permission_precondition() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "transfer".into(),
                action: "call transfer".into(),
                required_capability: ExploitCapability::TransferAssets,
                affected_state: vec![],
                affected_assets: vec!["token".into()],
                prerequisites: vec![],
                mutations: vec![],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "test".into(),
            }],
            required_capabilities: vec![ExploitCapability::TransferAssets],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };

        let inputs = crate::engine::SynthesisInputs {
            ir: Some(&digger_ir::SystemIR {
                program_id: "test".into(),
                language: digger_ir::Language::Solidity,
                functions: vec![digger_ir::Function {
                    id: "f1".into(),
                    name: "transfer".into(),
                    contract: String::new(),
                    visibility: digger_ir::Visibility::Public,
                    inputs: vec![],
                    outputs: vec![],
                    modifiers: vec![],
                    effects: digger_ir::Effects {
                        state_mutation: false,
                        external_call: false,
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
            }),
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

        let result = solve_preconditions(&chain, &inputs);
        assert!(result.satisfied > 0);
    }
}
