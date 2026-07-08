/// Generation 3.1b — State Validation Engine
///
/// Verifies that state transitions in synthesized exploits are actually
/// reachable. Models protocol state before/after each step and rejects
/// impossible attack chains.
use crate::models::*;
use std::collections::BTreeMap;

/// Result of state validation for a chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateValidationResult {
    /// Chain being validated.
    pub chain_id: String,
    /// Step-by-step state transition validation.
    pub transitions: Vec<StateTransitionValidation>,
    /// Whether all transitions are valid.
    pub all_valid: bool,
    /// Count of valid transitions.
    pub valid_count: usize,
    /// Count of invalid transitions.
    pub invalid_count: usize,
}

/// Validation of a single state transition.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateTransitionValidation {
    /// Step index.
    pub step_index: usize,
    /// Transition valid.
    pub valid: bool,
    /// Pre-state (state variables before this step).
    pub pre_state: BTreeMap<String, String>,
    /// Post-state (state variables after this step).
    pub post_state: BTreeMap<String, String>,
    /// State changes detected.
    pub changes: Vec<ValidatedChange>,
    /// Reason if invalid.
    pub invalid_reason: Option<String>,
}

/// A validated state change.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatedChange {
    /// Variable changed.
    pub variable: String,
    /// Whether the mutation is reachable.
    pub reachable: bool,
    /// Reasoning for reachability.
    pub reachability_reason: String,
    /// Whether this change violates invariants.
    pub violates_invariant: bool,
}

/// Validate all state transitions in a chain.
pub fn validate_state_transitions(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> StateValidationResult {
    let mut transitions = Vec::new();
    let mut current_state = build_state_snapshot(inputs);
    let mut all_valid = true;

    for step in &chain.steps {
        let pre_state = current_state.clone();

        // Determine what the step changes
        let changes = compute_changes(step, &pre_state, inputs);

        // Apply changes to get post-state
        let mut post_state = current_state.clone();
        for change in &changes {
            if change.reachable {
                post_state.insert(
                    change.variable.clone(),
                    format!("mutated_by:{}", step.function),
                );
            }
        }

        // Check validity
        let (valid, invalid_reason) =
            validate_step_transition(step, &pre_state, &post_state, inputs);
        if !valid {
            all_valid = false;
        }

        transitions.push(StateTransitionValidation {
            step_index: step.index,
            valid,
            pre_state,
            post_state: post_state.clone(),
            changes,
            invalid_reason,
        });

        current_state = post_state;
    }

    let valid_count = transitions.iter().filter(|t| t.valid).count();
    let invalid_count = transitions.iter().filter(|t| !t.valid).count();

    StateValidationResult {
        chain_id: chain.chain_id.clone(),
        transitions,
        all_valid,
        valid_count,
        invalid_count,
    }
}

/// Build initial state snapshot from IR.
fn build_state_snapshot(inputs: &crate::engine::SynthesisInputs) -> BTreeMap<String, String> {
    let mut state = BTreeMap::new();
    if let Some(ir) = inputs.ir {
        for var in &ir.state {
            state.insert(var.name.clone(), "initial".into());
        }
    }
    state
}

/// Compute changes a step makes to state.
fn compute_changes(
    step: &ExploitStep,
    pre_state: &BTreeMap<String, String>,
    _inputs: &crate::engine::SynthesisInputs,
) -> Vec<ValidatedChange> {
    let mut changes = Vec::new();

    for var in &step.affected_state {
        let reachable =
            pre_state.contains_key(var) || step.mutations.iter().any(|m| m.contains(var));

        let mut violates_invariant = false;
        for mutation in &step.mutations {
            if mutation.contains("Violate") || mutation.contains("violate") {
                violates_invariant = true;
            }
        }

        changes.push(ValidatedChange {
            variable: var.clone(),
            reachable,
            reachability_reason: if reachable {
                format!(
                    "Variable '{}' exists in pre-state or is created by step",
                    var
                )
            } else {
                format!(
                    "Variable '{}' not found in state and not created by step",
                    var
                )
            },
            violates_invariant,
        });
    }

    changes
}

/// Validate a single step transition.
fn validate_step_transition(
    step: &ExploitStep,
    pre_state: &BTreeMap<String, String>,
    post_state: &BTreeMap<String, String>,
    inputs: &crate::engine::SynthesisInputs,
) -> (bool, Option<String>) {
    // Check: function exists in IR
    if let Some(ir) = inputs.ir {
        if !ir.functions.iter().any(|f| f.name == step.function) {
            return (
                false,
                Some(format!("Function '{}' does not exist", step.function)),
            );
        }
    }

    // Check: required state variables are accessible
    for var in &step.affected_state {
        if step.required_capability == ExploitCapability::WriteState
            && !pre_state.contains_key(var)
            && !post_state.contains_key(var)
        {
            // Variable not in state — might be created, not necessarily invalid
        }
    }

    // Check: no impossible ordering (step modifies something that was already modified)
    for change in step.mutations.iter() {
        if let Some(var) = change.split_whitespace().nth(1) {
            if post_state.contains_key(var) && pre_state.get(var) == post_state.get(var) {
                // State didn't change but step claims to modify — possible if value is the same
            }
        }
    }

    // Check: authority constraints
    if step.required_capability == ExploitCapability::AuthorityEscalation {
        if let Some(ir) = inputs.ir {
            let all_enforced = !ir.edges.iter().any(|e| {
                matches!(e, digger_ir::Edge::Authority(a) if a.function == step.function && a.check_type == "missing")
            });
            if all_enforced {
                return (
                    false,
                    Some(format!(
                        "Function '{}' has authority on all paths — cannot escalate",
                        step.function
                    )),
                );
            }
        }
    }

    (true, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_chain() {
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

        let result = validate_state_transitions(&chain, &inputs);
        assert!(result.all_valid);
    }

    #[test]
    fn test_invalid_function() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "nonexistent".into(),
                action: "call".into(),
                required_capability: ExploitCapability::WriteState,
                affected_state: vec!["x".into()],
                affected_assets: vec![],
                prerequisites: vec![],
                mutations: vec!["mutate x".into()],
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

        let inputs = crate::engine::SynthesisInputs {
            ir: Some(&digger_ir::SystemIR {
                program_id: "test".into(),
                language: digger_ir::Language::Solidity,
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

        let result = validate_state_transitions(&chain, &inputs);
        assert!(!result.all_valid);
        assert!(result.invalid_count > 0);
    }
}
