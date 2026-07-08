/// Logical exploit simulation — models state evolution without executing code.
use crate::models::*;
use std::collections::BTreeMap;

/// Simulate an exploit chain — produce step-by-step state evolution.
pub fn simulate_chain(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> ExploitSimulation {
    let initial_state = build_initial_state(inputs);
    let mut current_state = initial_state.clone();
    let mut step_states = Vec::new();
    let mut success = true;
    let mut failure_reason = None;

    for step in &chain.steps {
        let before = current_state.clone();

        // Check preconditions
        let precondition_met = check_preconditions(step, &current_state, inputs);
        if !precondition_met {
            success = false;
            failure_reason = Some(format!(
                "Step {} ({}) preconditions not met",
                step.index, step.function
            ));
            break;
        }

        // Apply state changes
        let changes = apply_step(step, &mut current_state);

        let after = current_state.clone();

        step_states.push(StepState {
            step: step.index,
            before,
            changes,
            after,
            success_reason: explain_step_success(step, inputs),
        });
    }

    // Check invariant violations in final state
    let violated_invariants = current_state.violated_invariants.clone();

    // Compute economic impact
    let economic_impact = compute_impact(&initial_state, &current_state, chain);

    let explanation = if success {
        format!(
            "Exploit chain '{}' succeeds in {} steps. Final state has {} invariant violations.",
            chain.chain_id,
            chain.steps.len(),
            violated_invariants.len()
        )
    } else {
        format!(
            "Exploit chain '{}' fails: {}",
            chain.chain_id,
            failure_reason.as_deref().unwrap_or("unknown")
        )
    };

    ExploitSimulation {
        chain_id: chain.chain_id.clone(),
        initial_state,
        step_states,
        final_state: current_state,
        success,
        failure_reason,
        economic_impact,
        explanation,
    }
}

/// Build the initial protocol state from Gen 1/2 analysis.
fn build_initial_state(inputs: &crate::engine::SynthesisInputs) -> ProtocolState {
    let mut state_vars = BTreeMap::new();
    let balances = BTreeMap::new();
    let ownership = BTreeMap::new();
    let mut authority = BTreeMap::new();
    let mut violated_invariants = Vec::new();

    // Extract state variable info from IR
    if let Some(ir) = inputs.ir {
        for var in &ir.state {
            state_vars.insert(var.name.clone(), format!("{} (initial)", var.ty));
        }

        // Extract authority status from edges
        for edge in &ir.edges {
            if let digger_ir::Edge::Authority(a) = edge {
                authority.insert(a.function.clone(), a.check_type != "missing");
            }
        }
    }

    // Extract economic invariants
    if let Some(econ) = inputs.economics {
        for invariant in &econ.invariants {
            if !invariant.is_satisfied {
                violated_invariants
                    .push(format!("{}: {:?}", invariant.invariant_id, invariant.kind));
            }
        }
    }

    ProtocolState {
        step_index: -1,
        state_vars,
        balances,
        ownership,
        authority,
        violated_invariants,
    }
}

/// Check if step preconditions are met in current state.
fn check_preconditions(
    step: &ExploitStep,
    state: &ProtocolState,
    _inputs: &crate::engine::SynthesisInputs,
) -> bool {
    // Check authority preconditions
    if step.required_capability == ExploitCapability::AuthorityEscalation {
        // Must have a function without authority enforcement
        if let Some(auth_enforced) = state.authority.get(&step.function) {
            if *auth_enforced {
                return false; // Authority is enforced, can't escalate
            }
        }
    }

    // Check state prerequisites
    for prereq in &step.prerequisites {
        // Simple text-based prerequisite check
        if prereq.contains("must be called first") {
            // Check if the predecessor was executed
            let predecessor = prereq.replace(" must be called first", "");
            if !step_states_contains_function(&[], &predecessor) {
                // Predecessor not yet executed — but this is the current step
                // This check is for multi-step ordering
            }
        }
    }

    true
}

/// Apply a step to the state, producing mutations.
fn apply_step(step: &ExploitStep, state: &mut ProtocolState) -> Vec<StateChange> {
    let mut changes = Vec::new();

    for _mutation in &step.mutations {
        for var in &step.affected_state {
            let old_value = state.state_vars.get(var).cloned().unwrap_or_default();
            let new_value = format!("{} (mutated by {})", old_value, step.function);

            state.state_vars.insert(var.clone(), new_value.clone());
            changes.push(StateChange {
                kind: StateChangeKind::StateVariable,
                target: var.clone(),
                old_value,
                new_value,
            });
        }
    }

    // Track authority bypass
    if step.required_capability == ExploitCapability::AuthorityEscalation {
        if let Some(auth) = state.authority.get_mut(&step.function) {
            *auth = false;
            changes.push(StateChange {
                kind: StateChangeKind::Authority,
                target: step.function.clone(),
                old_value: "enforced".into(),
                new_value: "bypassed".into(),
            });
        }
    }

    // Track invariant violations
    for invariant in &step.mutations {
        if (invariant.contains("Violate") || invariant.contains("violate"))
            && !state.violated_invariants.contains(invariant)
        {
            state.violated_invariants.push(invariant.clone());
            changes.push(StateChange {
                kind: StateChangeKind::InvariantViolation,
                target: invariant.clone(),
                old_value: "satisfied".into(),
                new_value: "violated".into(),
            });
        }
    }

    changes
}

/// Explain why a step succeeds.
fn explain_step_success(step: &ExploitStep, inputs: &crate::engine::SynthesisInputs) -> String {
    // Check if authority is missing for this function
    if let Some(ir) = inputs.ir {
        for edge in &ir.edges {
            if let digger_ir::Edge::Authority(a) = edge {
                if a.function == step.function && a.check_type == "missing" {
                    return format!(
                        "Function {} lacks authority enforcement (source: {})",
                        step.function, a.authority_source
                    );
                }
            }
        }
    }

    step.explanation.clone()
}

/// Compute economic impact from state diff.
fn compute_impact(
    initial: &ProtocolState,
    final_state: &ProtocolState,
    chain: &ExploitChain,
) -> EconomicImpact {
    let mut assets_lost = BTreeMap::new();
    let mut assets_gained = BTreeMap::new();

    for step in &chain.steps {
        for var in &step.affected_state {
            if initial.state_vars.contains_key(var) && !assets_lost.contains_key(var) {
                assets_lost.insert(var.clone(), 1);
                assets_gained.insert(var.clone(), 1);
            }
        }
    }

    let invariant_violations: Vec<String> = final_state
        .violated_invariants
        .iter()
        .filter(|v| !initial.violated_invariants.contains(v))
        .cloned()
        .collect();

    EconomicImpact {
        assets_lost,
        assets_gained,
        total_usd_lost: 0.0, // Would need oracle data for actual USD
        invariant_violations,
        cascade_effects: vec![],
    }
}

fn step_states_contains_function(_steps: &[StepState], _function: &str) -> bool {
    // Placeholder — in a full simulation, we'd check step history
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulate_empty_chain() {
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

        let sim = simulate_chain(&chain, &inputs);
        assert!(sim.success);
        assert!(sim.step_states.is_empty());
    }

    #[test]
    fn test_build_initial_state() {
        let inputs = crate::engine::SynthesisInputs {
            ir: Some(&digger_ir::SystemIR {
                program_id: "test".into(),
                language: digger_ir::Language::Solidity,
                functions: vec![],
                state: vec![digger_ir::StateVariable {
                    id: "s1".into(),
                    name: "balance".into(),
                    ty: "uint256".into(),
                    mutable: true,
                }],
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

        let state = build_initial_state(&inputs);
        assert!(state.state_vars.contains_key("balance"));
    }
}
