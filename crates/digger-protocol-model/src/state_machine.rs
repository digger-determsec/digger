//! State Machines -- deterministic protocol lifecycle models derived directly
//! from recovered structure (capabilities + standardized interface selectors).
//! Each capability maps to a FIXED, well-known lifecycle: there is no inference
//! about runtime behavior, only the structural states a capability implies.

use serde::{Deserialize, Serialize};

use crate::capability_graph::{CapabilityGraph, CapabilityKind};
use crate::ids::node_id;
use crate::selectors as sel;
use crate::{derive_provenance, InterfaceDetail, Provenance, RecoveredInterface};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StateMachineKind {
    Pausable,
    Upgradeable,
    Initializable,
}

impl StateMachineKind {
    pub fn label(&self) -> &'static str {
        match self {
            StateMachineKind::Pausable => "pausable",
            StateMachineKind::Upgradeable => "upgradeable",
            StateMachineKind::Initializable => "initializable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolState {
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: String,
    pub to: String,
    /// Deterministic trigger tag (the structural action that moves states).
    pub trigger: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachine {
    /// Deterministic content-addressed id (`statemachine:<digest>`).
    pub id: String,
    pub machine_kind: StateMachineKind,
    pub states: Vec<ProtocolState>,
    pub transitions: Vec<StateTransition>,
    pub basis_fact_ids: Vec<String>,
    pub provenance: Provenance,
}

impl StateMachine {
    fn new(
        machine_kind: StateMachineKind,
        states: Vec<ProtocolState>,
        transitions: Vec<StateTransition>,
        basis_fact_ids: Vec<String>,
    ) -> Self {
        let mut basis = basis_fact_ids;
        basis.sort();
        basis.dedup();
        let canon = format!(
            "statemachine|{}|{}|{}",
            machine_kind.label(),
            states
                .iter()
                .map(|s| s.label.clone())
                .collect::<Vec<_>>()
                .join(">"),
            basis.join(","),
        );
        let provenance = derive_provenance(&canon, &basis.join(","));
        StateMachine {
            id: node_id("statemachine", &canon),
            machine_kind,
            states,
            transitions,
            basis_fact_ids: basis,
            provenance,
        }
    }
}

impl_protocol_fact!(StateMachine);

fn state(label: &str) -> ProtocolState {
    ProtocolState {
        label: label.to_string(),
    }
}

/// Deterministically derive lifecycle state machines from recovered structure.
pub fn derive_state_machines(
    capabilities: &CapabilityGraph,
    interface: Option<&RecoveredInterface>,
) -> Vec<StateMachine> {
    let mut machines: Vec<StateMachine> = Vec::new();

    if let Some(pause_id) = capabilities.fact_id_for(CapabilityKind::Pause) {
        machines.push(StateMachine::new(
            StateMachineKind::Pausable,
            vec![state("Active"), state("Paused")],
            vec![
                StateTransition {
                    from: "Active".into(),
                    to: "Paused".into(),
                    trigger: "pause".into(),
                },
                StateTransition {
                    from: "Paused".into(),
                    to: "Active".into(),
                    trigger: "unpause".into(),
                },
            ],
            vec![pause_id.to_string()],
        ));
    }

    if let Some(up_id) = capabilities.fact_id_for(CapabilityKind::Upgrade) {
        machines.push(StateMachine::new(
            StateMachineKind::Upgradeable,
            vec![state("Implementation"), state("Upgraded")],
            vec![StateTransition {
                from: "Implementation".into(),
                to: "Upgraded".into(),
                trigger: "upgrade".into(),
            }],
            vec![up_id.to_string()],
        ));
    }

    // Initialization lifecycle from standardized initializer selectors.
    if let Some(iface) = interface {
        if let InterfaceDetail::Evm(abi) = &iface.detail {
            if let Some(initializer) = abi
                .functions
                .iter()
                .find(|f| sel::is_initializer(f.selector.selector.as_str()))
            {
                machines.push(StateMachine::new(
                    StateMachineKind::Initializable,
                    vec![state("Uninitialized"), state("Initialized")],
                    vec![StateTransition {
                        from: "Uninitialized".into(),
                        to: "Initialized".into(),
                        trigger: "initialize".into(),
                    }],
                    vec![initializer.id.clone()],
                ));
            }
        }
    }

    machines.sort_by(|a, b| a.id.cmp(&b.id));
    machines.dedup_by(|a, b| a.id == b.id);
    machines
}
