/// Assumption elimination — validates exploit chain feasibility.
use crate::models::*;

/// Eliminate infeasible exploit chains.
///
/// Returns (viable_chains, eliminated_count).
pub fn eliminate_infeasible(
    chains: &mut Vec<ExploitChain>,
    inputs: &crate::engine::SynthesisInputs,
) -> (Vec<ExploitChain>, usize) {
    let mut viable = Vec::new();
    let mut eliminated = 0;

    for chain in chains.drain(..) {
        let (pass, _reasons) = check_feasibility(&chain, inputs);
        if pass {
            viable.push(chain);
        } else {
            eliminated += 1;
        }
    }

    // Sort viable by confidence descending
    viable.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    (viable, eliminated)
}

/// Check if an exploit chain is feasible.
///
/// Returns (is_feasible, elimination_reasons).
fn check_feasibility(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> (bool, Vec<String>) {
    let mut reasons = Vec::new();

    // 1. Check capability prerequisites
    if !check_capability_prerequisites(chain, inputs) {
        reasons.push("Missing required capabilities".into());
    }

    // 2. Check state preconditions
    if !check_state_preconditions(chain, inputs) {
        reasons.push("State preconditions not satisfiable".into());
    }

    // 3. Check authority constraints
    if !check_authority_constraints(chain, inputs) {
        reasons.push("Authority constraints block execution".into());
    }

    // 4. Check protocol rules
    if !check_protocol_rules(chain, inputs) {
        reasons.push("Protocol rules prevent exploitation".into());
    }

    // 5. Check ordering constraints
    if !check_ordering_constraints(chain) {
        reasons.push("Impossible execution ordering".into());
    }

    // 6. Check confidence threshold
    if chain.confidence < 0.1 {
        reasons.push("Confidence too low".into());
    }

    // 7. Check step count
    if chain.steps.is_empty() {
        reasons.push("Empty exploit chain".into());
    }

    (reasons.is_empty(), reasons)
}

/// Check if all required capabilities are available.
fn check_capability_prerequisites(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> bool {
    // Check if the program has functions that could provide these capabilities
    if let Some(ir) = inputs.ir {
        let has_external_call = ir
            .edges
            .iter()
            .any(|e| matches!(e, digger_ir::Edge::External(_)));
        let has_state_write = ir
            .edges
            .iter()
            .any(|e| matches!(e, digger_ir::Edge::State(s) if s.access == "write"));
        let has_authority = ir
            .edges
            .iter()
            .any(|e| matches!(e, digger_ir::Edge::Authority(a) if a.check_type != "missing"));

        for cap in &chain.required_capabilities {
            match cap {
                ExploitCapability::CrossContractCall
                | ExploitCapability::CrossProgramInvocation => {
                    if !has_external_call {
                        return false;
                    }
                }
                ExploitCapability::WriteState
                | ExploitCapability::MintTokens
                | ExploitCapability::BurnTokens => {
                    if !has_state_write {
                        return false;
                    }
                }
                ExploitCapability::AuthorityEscalation if has_authority => {
                    // Authority is enforced on all functions — escalation harder
                    // Not impossible but lower confidence
                }
                _ => {}
            }
        }
    }

    true
}

/// Check if state preconditions can be satisfied.
fn check_state_preconditions(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> bool {
    if let Some(ir) = inputs.ir {
        let state_writes: Vec<String> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let digger_ir::Edge::State(s) = e {
                    if s.access == "write" {
                        return Some(s.state.clone());
                    }
                }
                None
            })
            .collect();
        for step in &chain.steps {
            if !step.affected_state.is_empty() {
                let has_write = step.affected_state.iter().any(|s| state_writes.contains(s));
                if !has_write {
                    return false;
                }
            }
        }
    }
    true
}

/// Check if authority constraints block the exploit.
fn check_authority_constraints(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> bool {
    if let Some(ir) = inputs.ir {
        let enforced_functions: std::collections::HashSet<String> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let digger_ir::Edge::Authority(a) = e {
                    if a.check_type == "enforced" {
                        return Some(a.function.clone());
                    }
                }
                None
            })
            .collect();
        for cap in &chain.required_capabilities {
            if matches!(cap, ExploitCapability::AuthorityEscalation) {
                let all_enforced = chain
                    .steps
                    .iter()
                    .all(|s| enforced_functions.contains(&s.function));
                if all_enforced && !enforced_functions.is_empty() {
                    return false;
                }
            }
        }
    }
    true
}

/// Check if protocol rules prevent the exploit.
fn check_protocol_rules(chain: &ExploitChain, inputs: &crate::engine::SynthesisInputs) -> bool {
    if let Some(ir) = inputs.ir {
        let required_functions: std::collections::HashSet<String> =
            chain.steps.iter().map(|s| s.function.clone()).collect();
        let ir_functions: std::collections::HashSet<String> =
            ir.functions.iter().map(|f| f.name.clone()).collect();
        for req_fn in &required_functions {
            if !ir_functions.contains(req_fn) {
                return false;
            }
        }
    }
    true
}

/// Check if the execution ordering is possible.
fn check_ordering_constraints(chain: &ExploitChain) -> bool {
    // Check for cycles in step prerequisites
    let mut visited = HashSet::new();
    for step in &chain.steps {
        if !visited.insert(step.index) {
            return false; // Cycle detected
        }
    }

    // Check that prerequisites reference earlier steps
    for step in &chain.steps {
        for prereq in &step.prerequisites {
            if prereq.contains("Step") {
                // Parse step reference
                if let Some(num_str) = prereq.split_whitespace().nth(1) {
                    if let Ok(num) = num_str.parse::<usize>() {
                        if num >= step.index {
                            return false; // References future step
                        }
                    }
                }
            }
        }
    }

    true
}

use std::collections::HashSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain_eliminated() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 1.0,
            severity: digger_ir::Severity::Medium,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };

        let inputs = crate::engine::SynthesisInputs {
            ir: Some(&digger_ir::SystemIR {
                program_id: "test".into(),
                language: digger_ir::Language::Unknown,
                functions: vec![],
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

        let (viable, eliminated) = eliminate_infeasible(&mut vec![chain], &inputs);
        assert_eq!(viable.len(), 0);
        assert_eq!(eliminated, 1);
    }

    #[test]
    fn test_valid_chain_passes() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "vulnerable".into(),
                action: "call".into(),
                required_capability: ExploitCapability::WriteState,
                affected_state: vec!["balance".into()],
                affected_assets: vec![],
                prerequisites: vec![],
                mutations: vec!["modify balance".into()],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "test".into(),
            }],
            required_capabilities: vec![ExploitCapability::WriteState],
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
                language: digger_ir::Language::Unknown,
                functions: vec![digger_ir::Function {
                    id: "vulnerable".into(),
                    name: "vulnerable".into(),
                    contract: String::new(),
                    visibility: digger_ir::Visibility::Public,
                    inputs: vec![],
                    outputs: vec![],
                    modifiers: vec![],
                    effects: digger_ir::Effects {
                        state_mutation: true,
                        ..Default::default()
                    },
                }],
                state: vec![],
                edges: vec![digger_ir::Edge::State(digger_ir::StateEdge {
                    function: "vulnerable".into(),
                    state: "balance".into(),
                    access: "write".into(),
                })],
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

        let (viable, eliminated) = eliminate_infeasible(&mut vec![chain], &inputs);
        assert_eq!(viable.len(), 1);
        assert_eq!(eliminated, 0);
    }

    #[test]
    fn test_ordering_constraint() {
        // Step 1 depends on step 2 (impossible)
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![ExploitStep {
                index: 1,
                state_transition: ExploitState::Execution,
                function: "fn".into(),
                action: "call".into(),
                required_capability: ExploitCapability::WriteState,
                affected_state: vec![],
                affected_assets: vec![],
                prerequisites: vec!["Step 2 must succeed".into()],
                mutations: vec![],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "test".into(),
            }],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.7,
            severity: digger_ir::Severity::Medium,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };

        assert!(!check_ordering_constraints(&chain));
    }
}
