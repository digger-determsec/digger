//! State mapping — maps Gen 5 StateMachines to SystemIR StateVariables.
//!
//! B5 scope: CONFIRMED EMPTY.
//!
//! # Decision (ADR-0024)
//!
//! SystemIR.state is ALWAYS empty. Rationale:
//!
//! 1. **No concrete storage units recovered.** ProtocolModel's `state_machines`
//!    are ABSTRACT lifecycles (Pausable/Upgradeable/Initializable) with
//!    label-only states ("Active", "Paused", etc.) — NOT concrete storage units.
//!
//! 2. **Fabrication hazard.** `StateVariable.ty` feeds the graph builder's
//!    pattern matcher. Fabricating name/ty would inject phantom storage and
//!    could trigger or suppress type-based rules.
//!
//! 3. **StateVariable is only actionable via Edge::State.** The hypothesis
//!    engines consume state access through `Edge::State { function, state,
//!    access }` edges, not the bare StateVariable list. Without recovered
//!    bodies, we cannot faithfully produce StateEdges — so synthesized
//!    variables would be inert or misleading.
//!
//! 4. **Redundancy.** The security signal of state machines (e.g. Pausable)
//!    is already represented by the corresponding capability function + its
//!    authority edge. Re-encoding as StateVariables is redundant.
//!
//! This is a model-layer limitation: concrete storage recovery is a future
//! enhancement requiring its own ADR.

use digger_ir::StateVariable;

/// Map resolved state machines to SystemIR StateVariables.
///
/// Returns an EMPTY vector — no concrete storage units are recovered.
/// This is a deliberate non-fabrication decision documented in ADR-0024.
pub fn map_state_machines_to_state(
    _state_machines: &[::digger_protocol_model::state_machine::StateMachine],
) -> Vec<StateVariable> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_protocol_model::state_machine::{
        ProtocolState, StateMachine, StateMachineKind, StateTransition,
    };

    fn make_state_machine(kind: StateMachineKind, labels: Vec<&str>) -> StateMachine {
        let states: Vec<ProtocolState> = labels
            .into_iter()
            .map(|l| ProtocolState { label: l.into() })
            .collect();
        let transitions = if states.len() >= 2 {
            vec![StateTransition {
                from: states[0].label.clone(),
                to: states[1].label.clone(),
                trigger: "test".into(),
            }]
        } else {
            vec![]
        };
        StateMachine {
            id: format!("sm:{:?}", kind),
            machine_kind: kind,
            states,
            transitions,
            basis_fact_ids: vec![],
            provenance: digger_reconstruct::provenance::Provenance::new(
                digger_reconstruct::provenance::EvidenceSource::Inferred,
                digger_reconstruct::provenance::ReconstructionStage::Enrich,
                digger_reconstruct::confidence::ConfidenceTier::Inferred,
                "test",
            ),
        }
    }

    #[test]
    fn state_always_empty_pausable() {
        let sm = make_state_machine(StateMachineKind::Pausable, vec!["Active", "Paused"]);
        assert!(map_state_machines_to_state(&[sm]).is_empty());
    }

    #[test]
    fn state_always_empty_upgradeable() {
        let sm = make_state_machine(
            StateMachineKind::Upgradeable,
            vec!["Implementation", "Upgraded"],
        );
        assert!(map_state_machines_to_state(&[sm]).is_empty());
    }

    #[test]
    fn state_always_empty_initializable() {
        let sm = make_state_machine(
            StateMachineKind::Initializable,
            vec!["Uninitialized", "Initialized"],
        );
        assert!(map_state_machines_to_state(&[sm]).is_empty());
    }

    #[test]
    fn state_empty_no_state_machines() {
        assert!(map_state_machines_to_state(&[]).is_empty());
    }

    #[test]
    fn determinism_state_always_empty() {
        let sm = make_state_machine(StateMachineKind::Pausable, vec!["Active", "Paused"]);
        let r1 = map_state_machines_to_state(std::slice::from_ref(&sm));
        let r2 = map_state_machines_to_state(&[sm]);
        assert_eq!(r1.len(), r2.len());
        assert!(r1.is_empty());
    }
}
