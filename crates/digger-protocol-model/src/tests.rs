use serde::{Deserialize, Serialize};

use crate::actors::{derive_actors, Actor, ActorKind};
use crate::assets::{derive_assets, Asset, AssetKind};
use crate::attack_surface::{AttackSurface, SurfaceKind};
use crate::capability_graph::{
    derive_capability_graph, Capability, CapabilityEdge, CapabilityEdgeKind, CapabilityGraph,
    CapabilityKind,
};
use crate::dependencies::normalize_dependencies;
use crate::economics::EconomicFlowKind;
use crate::ids::node_id;
use crate::invariants::{InvariantCandidate, InvariantKind};
use crate::model::{ProtocolModel, ProtocolModelInput};
use crate::permissions::{derive_permissions, Permission, PermissionAction};
use crate::selectors;
use crate::state_machine::{ProtocolState, StateMachine, StateMachineKind, StateTransition};
use crate::trust::{
    TrustBoundary, TrustBoundaryKind, TrustEdge, TrustEdgeKind, TrustGraph, TrustNode,
    TrustNodeKind,
};
use crate::upgrade::{UpgradePath, UpgradePathStep};
use crate::{
    AuthorityKind, ConfidenceTier, DependencyKind, DeploymentDetail, EvidenceSource, Provenance,
    ReconstructionStage, RecoveredAbi, RecoveredAddress, RecoveredDependency, RecoveredFact,
    RecoveredFunction, RecoveredInterface,
};
use digger_reconstruct::dependency::{DependencyDetail, EvmDependency};
use digger_reconstruct::deployment::{
    DeploymentKind, DeploymentMetadata, EvmDeployment, RecoveredDeployment,
};
use digger_reconstruct::interface::{
    InterfaceDetail, InterfaceKind, ParameterLayout, ReturnLayout,
};
use digger_reconstruct::lifter::RecoveredSelector;

fn tp() -> Provenance {
    Provenance::new(
        EvidenceSource::Inferred,
        ReconstructionStage::Enrich,
        ConfidenceTier::Inferred,
        "test-seed",
    )
}

fn addr(hex: &str) -> RecoveredAddress {
    RecoveredAddress::Resolved(hex.to_string())
}

fn dep(id: &str, kind: DependencyKind) -> RecoveredDependency {
    RecoveredDependency {
        id: id.to_string(),
        kind,
        address: addr("0x1234"),
        detail: DependencyDetail::Evm(EvmDependency::default()),
        provenance: tp(),
    }
}

fn authority(
    id: &str,
    kind: AuthorityKind,
    address: RecoveredAddress,
) -> crate::RecoveredAuthority {
    crate::RecoveredAuthority {
        id: id.to_string(),
        kind,
        address,
        provenance: tp(),
    }
}

fn evm_deploy_with_auth() -> RecoveredDeployment {
    RecoveredDeployment {
        id: "deploy:test-evm".to_string(),
        kind: DeploymentKind::Evm,
        detail: DeploymentDetail::Evm(EvmDeployment {
            id: "evmdeploy:test".to_string(),
            proxies: vec![],
            implementation_chain: vec![],
            upgrade_authority: Some(authority(
                "auth:test",
                AuthorityKind::UpgradeAuthority,
                addr("0xaaaa"),
            )),
            upgrade_path: vec![],
            relationships: vec![],
            metadata: DeploymentMetadata {
                runtime_code_len: 100,
                runtime_code_digest: "abc123".to_string(),
            },
            truncated_at_max_depth: false,
            provenance: tp(),
        }),
        provenance: tp(),
    }
}

fn evm_interface(selectors: &[&str]) -> RecoveredInterface {
    let functions: Vec<RecoveredFunction> = selectors
        .iter()
        .map(|sel_hex| RecoveredFunction {
            id: node_id("fn", sel_hex),
            selector: RecoveredSelector {
                id: node_id("sel", sel_hex),
                selector: sel_hex.to_string(),
                bytes: vec![0, 0, 0, 0],
                provenance: tp(),
            },
            parameters: ParameterLayout {
                observed_word_slots: vec![],
                provenance: tp(),
            },
            returns: ReturnLayout {
                observed_return_words: None,
                provenance: tp(),
            },
            provenance: tp(),
        })
        .collect();
    RecoveredInterface {
        id: "iface:test".to_string(),
        kind: InterfaceKind::Evm,
        detail: InterfaceDetail::Evm(RecoveredAbi {
            id: "abi:test".to_string(),
            functions,
            provenance: tp(),
        }),
        provenance: tp(),
    }
}

fn roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(val: T) {
    let json = serde_json::to_string(&val).expect("serialize");
    let back: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(val, back);
}

// =====================================================================
// Round-trip serialization tests
// =====================================================================

#[test]
fn rt_asset_kind() {
    roundtrip(AssetKind::FungibleToken);
    roundtrip(AssetKind::NonFungibleToken);
    roundtrip(AssetKind::Vault);
    roundtrip(AssetKind::TreasuryAsset);
    roundtrip(AssetKind::NativeToken);
    roundtrip(AssetKind::Unknown);
}

#[test]
fn rt_actor_kind() {
    roundtrip(ActorKind::Owner);
    roundtrip(ActorKind::Admin);
    roundtrip(ActorKind::UpgradeAuthority);
    roundtrip(ActorKind::Governance);
    roundtrip(ActorKind::ExternalProtocol);
    roundtrip(ActorKind::Unknown);
}

#[test]
fn rt_permission_action() {
    roundtrip(PermissionAction::Upgrade);
    roundtrip(PermissionAction::Mint);
    roundtrip(PermissionAction::Burn);
    roundtrip(PermissionAction::Pause);
    roundtrip(PermissionAction::Withdraw);
    roundtrip(PermissionAction::Govern);
}

#[test]
fn rt_economic_flow_kind() {
    roundtrip(EconomicFlowKind::Mint);
    roundtrip(EconomicFlowKind::Burn);
    roundtrip(EconomicFlowKind::Deposit);
    roundtrip(EconomicFlowKind::Withdraw);
    roundtrip(EconomicFlowKind::Bridge);
    roundtrip(EconomicFlowKind::OraclePriced);
}

#[test]
fn rt_invariant_kind() {
    roundtrip(InvariantKind::SupplyConservation);
    roundtrip(InvariantKind::OwnershipPreservation);
    roundtrip(InvariantKind::VaultAccountingConsistency);
    roundtrip(InvariantKind::AuthorizationConsistency);
    roundtrip(InvariantKind::UpgradeSafety);
}

#[test]
fn rt_surface_kind() {
    roundtrip(SurfaceKind::Upgrade);
    roundtrip(SurfaceKind::ExternalCall);
    roundtrip(SurfaceKind::PrivilegedExecution);
    roundtrip(SurfaceKind::AssetMovement);
    roundtrip(SurfaceKind::Initialization);
    roundtrip(SurfaceKind::Proxy);
    roundtrip(SurfaceKind::Governance);
}

#[test]
fn rt_capability_kind() {
    roundtrip(CapabilityKind::Upgrade);
    roundtrip(CapabilityKind::Mint);
    roundtrip(CapabilityKind::Burn);
    roundtrip(CapabilityKind::Pause);
    roundtrip(CapabilityKind::OracleDependency);
    roundtrip(CapabilityKind::BridgeDependency);
    roundtrip(CapabilityKind::FlashLoan);
    roundtrip(CapabilityKind::Delegatecall);
    roundtrip(CapabilityKind::Treasury);
    roundtrip(CapabilityKind::Governance);
}

#[test]
fn rt_capability_edge_kind() {
    roundtrip(CapabilityEdgeKind::Controls);
    roundtrip(CapabilityEdgeKind::UsesMechanism);
}

#[test]
fn rt_state_machine_kind() {
    roundtrip(StateMachineKind::Pausable);
    roundtrip(StateMachineKind::Upgradeable);
    roundtrip(StateMachineKind::Initializable);
}

#[test]
fn rt_trust_node_kind() {
    roundtrip(TrustNodeKind::ProtocolCore);
    roundtrip(TrustNodeKind::PrivilegedActor);
    roundtrip(TrustNodeKind::ExternalSystem);
    roundtrip(TrustNodeKind::UpgradeAuthority);
    roundtrip(TrustNodeKind::EmergencyControl);
    roundtrip(TrustNodeKind::SharedDependency);
}

#[test]
fn rt_trust_edge_kind() {
    roundtrip(TrustEdgeKind::Controls);
    roundtrip(TrustEdgeKind::TrustsExternally);
    roundtrip(TrustEdgeKind::DependsOn);
    roundtrip(TrustEdgeKind::CanUpgrade);
    roundtrip(TrustEdgeKind::CanHalt);
}

#[test]
fn rt_trust_boundary_kind() {
    roundtrip(TrustBoundaryKind::PrivilegedControl);
    roundtrip(TrustBoundaryKind::ExternalDependency);
    roundtrip(TrustBoundaryKind::UpgradeAuthority);
    roundtrip(TrustBoundaryKind::EmergencyControl);
    roundtrip(TrustBoundaryKind::SharedDependency);
}

#[test]
fn rt_asset() {
    let asset = Asset::new(
        AssetKind::FungibleToken,
        addr("0xdeadbeef"),
        vec!["dep:1".into()],
    );
    roundtrip(asset);
}

#[test]
fn rt_actor() {
    let actor = Actor::new(ActorKind::Owner, addr("0xaaaa"), vec!["auth:1".into()]);
    roundtrip(actor);
}

#[test]
fn rt_permission() {
    let perm = Permission::new(
        PermissionAction::Upgrade,
        Some(addr("0xaaaa")),
        "cap:1".into(),
    );
    roundtrip(perm);
}

#[test]
fn rt_permission_no_holder() {
    let perm = Permission::new(PermissionAction::Mint, None, "cap:2".into());
    roundtrip(perm);
}

#[test]
fn rt_economic_flow() {
    use crate::economics::EconomicFlow;
    let flow = EconomicFlow::new(
        EconomicFlowKind::Deposit,
        Some(addr("0xbbbb")),
        vec!["asset:1".into()],
    );
    roundtrip(flow);
}

#[test]
fn rt_economic_flow_no_ref() {
    use crate::economics::EconomicFlow;
    let flow = EconomicFlow::new(EconomicFlowKind::Mint, None, vec!["cap:1".into()]);
    roundtrip(flow);
}

#[test]
fn rt_invariant_candidate() {
    let ic = InvariantCandidate {
        id: "invariant:test".into(),
        kind: InvariantKind::SupplyConservation,
        candidate: true,
        rationale: "test rationale".into(),
        basis_fact_ids: vec!["cap:1".into()],
        provenance: tp(),
    };
    roundtrip(ic);
}

#[test]
fn rt_attack_surface() {
    let asurf = AttackSurface {
        id: "surface:test".into(),
        kind: SurfaceKind::Upgrade,
        exposed_by_fact_ids: vec!["cap:1".into()],
        provenance: tp(),
    };
    roundtrip(asurf);
}

#[test]
fn rt_capability() {
    let cap = Capability::new(CapabilityKind::Mint, vec!["dep:1".into()]);
    roundtrip(cap);
}

#[test]
fn rt_capability_edge() {
    let edge = CapabilityEdge {
        from_id: "cap:1".into(),
        to_id: "cap:2".into(),
        kind: CapabilityEdgeKind::Controls,
    };
    roundtrip(edge);
}

#[test]
fn rt_capability_graph() {
    let cap = Capability::new(CapabilityKind::Mint, vec!["dep:1".into()]);
    let cap2 = Capability::new(CapabilityKind::Burn, vec!["dep:2".into()]);
    let edge = CapabilityEdge {
        from_id: cap.id.clone(),
        to_id: cap2.id.clone(),
        kind: CapabilityEdgeKind::UsesMechanism,
    };
    let graph = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![cap, cap2],
        edges: vec![edge],
        provenance: tp(),
    };
    roundtrip(graph);
}

#[test]
fn rt_protocol_state() {
    let ps = ProtocolState {
        label: "Active".into(),
    };
    roundtrip(ps);
}

#[test]
fn rt_state_transition() {
    let st = StateTransition {
        from: "Active".into(),
        to: "Paused".into(),
        trigger: "pause".into(),
    };
    roundtrip(st);
}

#[test]
fn rt_state_machine() {
    let sm = StateMachine {
        id: "statemachine:test".into(),
        machine_kind: StateMachineKind::Pausable,
        states: vec![
            ProtocolState {
                label: "Active".into(),
            },
            ProtocolState {
                label: "Paused".into(),
            },
        ],
        transitions: vec![StateTransition {
            from: "Active".into(),
            to: "Paused".into(),
            trigger: "pause".into(),
        }],
        basis_fact_ids: vec!["cap:1".into()],
        provenance: tp(),
    };
    roundtrip(sm);
}

#[test]
fn rt_trust_node() {
    let tn = TrustNode::new(TrustNodeKind::ProtocolCore, "protocol-core");
    roundtrip(tn);
}

#[test]
fn rt_trust_edge() {
    let te = TrustEdge {
        from_id: "trustnode:1".into(),
        to_id: "trustnode:2".into(),
        kind: TrustEdgeKind::Controls,
    };
    roundtrip(te);
}

#[test]
fn rt_trust_graph() {
    let core = TrustNode::new(TrustNodeKind::ProtocolCore, "protocol-core");
    let actor = TrustNode::new(TrustNodeKind::PrivilegedActor, "actor:1");
    let graph = TrustGraph {
        id: "trustgraph:test".into(),
        nodes: vec![core.clone(), actor.clone()],
        edges: vec![TrustEdge {
            from_id: core.id.clone(),
            to_id: actor.id.clone(),
            kind: TrustEdgeKind::Controls,
        }],
        provenance: tp(),
    };
    roundtrip(graph);
}

#[test]
fn rt_trust_boundary() {
    let tb = TrustBoundary::new(
        TrustBoundaryKind::PrivilegedControl,
        "trustnode:1".into(),
        "trustnode:2".into(),
    );
    roundtrip(tb);
}

#[test]
fn rt_upgrade_path_step() {
    let step = UpgradePathStep {
        mechanism: "uups.upgradeTo".into(),
    };
    roundtrip(step);
}

#[test]
fn rt_upgrade_path() {
    let up = UpgradePath {
        id: "upgrade:test".into(),
        steps: vec![UpgradePathStep {
            mechanism: "uups.upgradeTo".into(),
        }],
        authority: Some(addr("0xaaaa")),
        basis_fact_ids: vec!["deploy:1".into()],
        provenance: tp(),
    };
    roundtrip(up);
}

#[test]
fn rt_upgrade_path_no_authority() {
    let up = UpgradePath {
        id: "upgrade:test2".into(),
        steps: vec![UpgradePathStep {
            mechanism: "solana.bpf_upgradeable_loader".into(),
        }],
        authority: None,
        basis_fact_ids: vec!["deploy:1".into()],
        provenance: tp(),
    };
    roundtrip(up);
}

#[test]
fn rt_protocol_model() {
    let dep = dep("dep:1", DependencyKind::Token);
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[dep],
        interface: None,
    };
    let model = ProtocolModel::build(&input);
    roundtrip(model);
}

// =====================================================================
// Exhaustive enum pin tests (compile-time lock)
// =====================================================================

#[test]
fn pin_asset_kind() {
    fn _exhaustive(k: AssetKind) -> usize {
        match k {
            AssetKind::FungibleToken => 1,
            AssetKind::NonFungibleToken => 2,
            AssetKind::Vault => 3,
            AssetKind::TreasuryAsset => 4,
            AssetKind::NativeToken => 5,
            AssetKind::Unknown => 6,
        }
    }
    assert_eq!(_exhaustive(AssetKind::FungibleToken), 1);
    assert_eq!(_exhaustive(AssetKind::Unknown), 6);
}

#[test]
fn pin_actor_kind() {
    fn _exhaustive(k: ActorKind) -> usize {
        match k {
            ActorKind::Owner => 1,
            ActorKind::Admin => 2,
            ActorKind::UpgradeAuthority => 3,
            ActorKind::Governance => 4,
            ActorKind::ExternalProtocol => 5,
            ActorKind::Unknown => 6,
        }
    }
    assert_eq!(_exhaustive(ActorKind::Owner), 1);
    assert_eq!(_exhaustive(ActorKind::Unknown), 6);
}

#[test]
fn pin_permission_action() {
    fn _exhaustive(a: PermissionAction) -> usize {
        match a {
            PermissionAction::Upgrade => 1,
            PermissionAction::Mint => 2,
            PermissionAction::Burn => 3,
            PermissionAction::Pause => 4,
            PermissionAction::Withdraw => 5,
            PermissionAction::Govern => 6,
        }
    }
    assert_eq!(_exhaustive(PermissionAction::Upgrade), 1);
    assert_eq!(_exhaustive(PermissionAction::Govern), 6);
}

#[test]
fn pin_economic_flow_kind() {
    fn _exhaustive(k: EconomicFlowKind) -> usize {
        match k {
            EconomicFlowKind::Mint => 1,
            EconomicFlowKind::Burn => 2,
            EconomicFlowKind::Deposit => 3,
            EconomicFlowKind::Withdraw => 4,
            EconomicFlowKind::Bridge => 5,
            EconomicFlowKind::OraclePriced => 6,
        }
    }
    assert_eq!(_exhaustive(EconomicFlowKind::Mint), 1);
    assert_eq!(_exhaustive(EconomicFlowKind::OraclePriced), 6);
}

#[test]
fn pin_invariant_kind() {
    fn _exhaustive(k: InvariantKind) -> usize {
        match k {
            InvariantKind::SupplyConservation => 1,
            InvariantKind::OwnershipPreservation => 2,
            InvariantKind::VaultAccountingConsistency => 3,
            InvariantKind::AuthorizationConsistency => 4,
            InvariantKind::UpgradeSafety => 5,
        }
    }
    assert_eq!(_exhaustive(InvariantKind::SupplyConservation), 1);
    assert_eq!(_exhaustive(InvariantKind::UpgradeSafety), 5);
}

#[test]
fn pin_surface_kind() {
    fn _exhaustive(k: SurfaceKind) -> usize {
        match k {
            SurfaceKind::Upgrade => 1,
            SurfaceKind::ExternalCall => 2,
            SurfaceKind::PrivilegedExecution => 3,
            SurfaceKind::AssetMovement => 4,
            SurfaceKind::Initialization => 5,
            SurfaceKind::Proxy => 6,
            SurfaceKind::Governance => 7,
        }
    }
    assert_eq!(_exhaustive(SurfaceKind::Upgrade), 1);
    assert_eq!(_exhaustive(SurfaceKind::Governance), 7);
}

#[test]
fn pin_capability_kind() {
    fn _exhaustive(k: CapabilityKind) -> usize {
        match k {
            CapabilityKind::Upgrade => 1,
            CapabilityKind::Mint => 2,
            CapabilityKind::Burn => 3,
            CapabilityKind::Pause => 4,
            CapabilityKind::OracleDependency => 5,
            CapabilityKind::BridgeDependency => 6,
            CapabilityKind::FlashLoan => 7,
            CapabilityKind::Delegatecall => 8,
            CapabilityKind::Treasury => 9,
            CapabilityKind::Governance => 10,
        }
    }
    assert_eq!(_exhaustive(CapabilityKind::Upgrade), 1);
    assert_eq!(_exhaustive(CapabilityKind::Governance), 10);
}

#[test]
fn pin_capability_edge_kind() {
    fn _exhaustive(k: CapabilityEdgeKind) -> usize {
        match k {
            CapabilityEdgeKind::Controls => 1,
            CapabilityEdgeKind::UsesMechanism => 2,
        }
    }
    assert_eq!(_exhaustive(CapabilityEdgeKind::Controls), 1);
    assert_eq!(_exhaustive(CapabilityEdgeKind::UsesMechanism), 2);
}

#[test]
fn pin_state_machine_kind() {
    fn _exhaustive(k: StateMachineKind) -> usize {
        match k {
            StateMachineKind::Pausable => 1,
            StateMachineKind::Upgradeable => 2,
            StateMachineKind::Initializable => 3,
        }
    }
    assert_eq!(_exhaustive(StateMachineKind::Pausable), 1);
    assert_eq!(_exhaustive(StateMachineKind::Initializable), 3);
}

#[test]
fn pin_trust_node_kind() {
    fn _exhaustive(k: TrustNodeKind) -> usize {
        match k {
            TrustNodeKind::ProtocolCore => 1,
            TrustNodeKind::PrivilegedActor => 2,
            TrustNodeKind::ExternalSystem => 3,
            TrustNodeKind::UpgradeAuthority => 4,
            TrustNodeKind::EmergencyControl => 5,
            TrustNodeKind::SharedDependency => 6,
        }
    }
    assert_eq!(_exhaustive(TrustNodeKind::ProtocolCore), 1);
    assert_eq!(_exhaustive(TrustNodeKind::SharedDependency), 6);
}

#[test]
fn pin_trust_edge_kind() {
    fn _exhaustive(k: TrustEdgeKind) -> usize {
        match k {
            TrustEdgeKind::Controls => 1,
            TrustEdgeKind::TrustsExternally => 2,
            TrustEdgeKind::DependsOn => 3,
            TrustEdgeKind::CanUpgrade => 4,
            TrustEdgeKind::CanHalt => 5,
        }
    }
    assert_eq!(_exhaustive(TrustEdgeKind::Controls), 1);
    assert_eq!(_exhaustive(TrustEdgeKind::CanHalt), 5);
}

#[test]
fn pin_trust_boundary_kind() {
    fn _exhaustive(k: TrustBoundaryKind) -> usize {
        match k {
            TrustBoundaryKind::PrivilegedControl => 1,
            TrustBoundaryKind::ExternalDependency => 2,
            TrustBoundaryKind::UpgradeAuthority => 3,
            TrustBoundaryKind::EmergencyControl => 4,
            TrustBoundaryKind::SharedDependency => 5,
        }
    }
    assert_eq!(_exhaustive(TrustBoundaryKind::PrivilegedControl), 1);
    assert_eq!(_exhaustive(TrustBoundaryKind::SharedDependency), 5);
}

// =====================================================================
// Constructor / invariant tests
// =====================================================================

#[test]
fn asset_new_deduplicates_basis() {
    let asset = Asset::new(
        AssetKind::FungibleToken,
        addr("0x1234"),
        vec!["dep:1".into(), "dep:1".into(), "dep:2".into()],
    );
    assert_eq!(asset.basis_fact_ids, vec!["dep:1", "dep:2"]);
    assert!(asset.id.starts_with("asset:"));
}

#[test]
fn actor_new_deduplicates_basis() {
    let actor = Actor::new(
        ActorKind::Owner,
        addr("0xaaaa"),
        vec!["auth:1".into(), "auth:1".into(), "deploy:1".into()],
    );
    assert_eq!(actor.basis_fact_ids, vec!["auth:1", "deploy:1"]);
    assert!(actor.id.starts_with("actor:"));
}

#[test]
fn actor_new_sorts_basis() {
    let actor = Actor::new(
        ActorKind::Admin,
        addr("0xbbbb"),
        vec!["dep:3".into(), "dep:1".into(), "dep:2".into()],
    );
    assert_eq!(actor.basis_fact_ids, vec!["dep:1", "dep:2", "dep:3"]);
}

#[test]
fn economic_flow_new_deduplicates_basis() {
    use crate::economics::EconomicFlow;
    let flow = EconomicFlow::new(
        EconomicFlowKind::Deposit,
        Some(addr("0xaaaa")),
        vec!["asset:1".into(), "asset:1".into()],
    );
    assert_eq!(flow.basis_fact_ids, vec!["asset:1"]);
    assert!(flow.id.starts_with("flow:"));
}

#[test]
fn capability_new_deduplicates_basis() {
    let cap = Capability::new(
        CapabilityKind::Mint,
        vec!["fn:1".into(), "fn:1".into(), "fn:2".into()],
    );
    assert_eq!(cap.basis_fact_ids, vec!["fn:1", "fn:2"]);
    assert!(cap.id.starts_with("cap:"));
}

#[test]
fn permission_new_deterministic_id() {
    let p1 = Permission::new(
        PermissionAction::Upgrade,
        Some(addr("0xaaaa")),
        "cap:1".into(),
    );
    let p2 = Permission::new(
        PermissionAction::Upgrade,
        Some(addr("0xaaaa")),
        "cap:1".into(),
    );
    assert_eq!(p1.id, p2.id);
    assert!(p1.id.starts_with("perm:"));
}

#[test]
fn trust_node_new_deterministic_id() {
    let n1 = TrustNode::new(TrustNodeKind::ProtocolCore, "ref:1");
    let n2 = TrustNode::new(TrustNodeKind::ProtocolCore, "ref:1");
    assert_eq!(n1.id, n2.id);
    assert!(n1.id.starts_with("trustnode:"));
}

#[test]
fn trust_boundary_new_deterministic_id() {
    let b1 = TrustBoundary::new(TrustBoundaryKind::PrivilegedControl, "a".into(), "b".into());
    let b2 = TrustBoundary::new(TrustBoundaryKind::PrivilegedControl, "a".into(), "b".into());
    assert_eq!(b1.id, b2.id);
    assert!(b1.id.starts_with("trustbound:"));
}

#[test]
fn capability_graph_has_and_fact_id_for() {
    let cap1 = Capability::new(CapabilityKind::Mint, vec!["fn:1".into()]);
    let cap2 = Capability::new(CapabilityKind::Burn, vec!["fn:2".into()]);
    let graph = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![cap1.clone(), cap2.clone()],
        edges: vec![],
        provenance: tp(),
    };
    assert!(graph.has(CapabilityKind::Mint));
    assert!(graph.has(CapabilityKind::Burn));
    assert!(!graph.has(CapabilityKind::Pause));
    assert_eq!(
        graph.fact_id_for(CapabilityKind::Mint),
        Some(cap1.id.as_str())
    );
    assert_eq!(
        graph.fact_id_for(CapabilityKind::Burn),
        Some(cap2.id.as_str())
    );
    assert_eq!(graph.fact_id_for(CapabilityKind::Pause), None);
}

#[test]
fn selectors_is_initializer() {
    assert!(selectors::is_initializer(selectors::INITIALIZE));
    assert!(selectors::is_initializer(selectors::INITIALIZE_ADDR));
    assert!(!selectors::is_initializer("0xdeadbeef"));
    assert!(!selectors::is_initializer(selectors::MINT_ADDR_UINT));
}

#[test]
fn recovered_fact_trait_for_asset() {
    let asset = Asset::new(
        AssetKind::FungibleToken,
        addr("0x1234"),
        vec!["dep:1".into()],
    );
    assert!(asset.fact_id().starts_with("asset:"));
    assert_eq!(asset.confidence(), ConfidenceTier::Inferred);
    assert!(!asset.reproducibility().input_digest.is_empty());
}

#[test]
fn recovered_fact_trait_for_capability_graph() {
    let cap = Capability::new(CapabilityKind::Mint, vec!["fn:1".into()]);
    let graph = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![cap],
        edges: vec![],
        provenance: tp(),
    };
    assert_eq!(graph.fact_id(), "capgraph:test");
    assert_eq!(graph.confidence(), ConfidenceTier::Inferred);
}

#[test]
fn recovered_fact_trait_for_protocol_model() {
    let model = ProtocolModel::build(&ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    });
    assert!(model.fact_id().starts_with("protocol:"));
    assert_eq!(model.confidence(), ConfidenceTier::Inferred);
}

// =====================================================================
// Ordering / determinism tests
// =====================================================================

#[test]
fn derive_assets_sorted_by_id() {
    let deps = vec![
        dep("dep:z", DependencyKind::Token),
        dep("dep:a", DependencyKind::Token),
        dep("dep:m", DependencyKind::Vault),
    ];
    let assets = derive_assets(&deps);
    assert_eq!(assets.len(), 3);
    for w in assets.windows(2) {
        assert!(
            w[0].id <= w[1].id,
            "assets not sorted: {} > {}",
            w[0].id,
            w[1].id
        );
    }
}

#[test]
fn derive_assets_only_token_and_vault() {
    let deps = vec![
        dep("dep:1", DependencyKind::Token),
        dep("dep:2", DependencyKind::Vault),
        dep("dep:3", DependencyKind::Bridge),
        dep("dep:4", DependencyKind::PriceOracle),
    ];
    let assets = derive_assets(&deps);
    assert_eq!(assets.len(), 2);
    let kinds: Vec<AssetKind> = assets.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&AssetKind::FungibleToken));
    assert!(kinds.contains(&AssetKind::Vault));
}

#[test]
fn derive_actors_sorted_by_id() {
    let deps = vec![
        dep("dep:z", DependencyKind::Governance),
        dep("dep:a", DependencyKind::ExternalProtocol),
        dep("dep:m", DependencyKind::Governance),
    ];
    let actors = derive_actors(None, &deps);
    assert_eq!(actors.len(), 3);
    for w in actors.windows(2) {
        assert!(
            w[0].id <= w[1].id,
            "actors not sorted: {} > {}",
            w[0].id,
            w[1].id
        );
    }
}

#[test]
fn derive_actors_from_deployment_and_deps() {
    let deployment = evm_deploy_with_auth();
    let deps = vec![
        dep("dep:governance", DependencyKind::Governance),
        dep("dep:external", DependencyKind::ExternalProtocol),
    ];
    let actors = derive_actors(Some(&deployment), &deps);
    assert_eq!(actors.len(), 3);
    let kinds: Vec<ActorKind> = actors.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&ActorKind::UpgradeAuthority));
    assert!(kinds.contains(&ActorKind::Governance));
    assert!(kinds.contains(&ActorKind::ExternalProtocol));
}

#[test]
fn normalize_dependencies_sorted() {
    let deps = vec![
        dep("dep:c", DependencyKind::Token),
        dep("dep:a", DependencyKind::Token),
        dep("dep:b", DependencyKind::Token),
    ];
    let normalized = normalize_dependencies(&deps);
    assert_eq!(normalized.len(), 3);
    assert_eq!(normalized[0].id, "dep:a");
    assert_eq!(normalized[1].id, "dep:b");
    assert_eq!(normalized[2].id, "dep:c");
}

#[test]
fn normalize_dependencies_dedupes() {
    let d = dep("dep:1", DependencyKind::Token);
    let deps = vec![d.clone(), d.clone(), dep("dep:2", DependencyKind::Token)];
    let normalized = normalize_dependencies(&deps);
    assert_eq!(normalized.len(), 2);
}

#[test]
fn build_protocol_model_deterministic() {
    let dep = dep("dep:1", DependencyKind::Token);
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[dep],
        interface: None,
    };
    let m1 = ProtocolModel::build(&input);
    let m2 = ProtocolModel::build(&input);
    assert_eq!(m1.id, m2.id);
    assert_eq!(m1.actors, m2.actors);
    assert_eq!(m1.assets, m2.assets);
    assert_eq!(m1.permissions, m2.permissions);
    assert_eq!(m1.capability_graph, m2.capability_graph);
    assert_eq!(m1.trust_graph, m2.trust_graph);
    assert_eq!(m1.attack_surfaces, m2.attack_surfaces);
    assert_eq!(m1.invariant_candidates, m2.invariant_candidates);
    assert_eq!(m1.economic_flows, m2.economic_flows);
    assert_eq!(m1.state_machines, m2.state_machines);
    assert_eq!(m1.upgrade_paths, m2.upgrade_paths);
}

#[test]
fn build_protocol_model_empty_inputs() {
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let model = ProtocolModel::build(&input);
    assert!(model.id.starts_with("protocol:"));
    assert!(model.actors.is_empty());
    assert!(model.assets.is_empty());
    assert!(model.permissions.is_empty());
    assert!(model.capability_graph.capabilities.is_empty());
    assert!(model.state_machines.is_empty());
    assert!(model.economic_flows.is_empty());
    assert!(model.attack_surfaces.is_empty());
}

#[test]
fn build_protocol_model_with_deployment() {
    let deployment = evm_deploy_with_auth();
    let input = ProtocolModelInput {
        deployment: Some(&deployment),
        dependencies: &[],
        interface: None,
    };
    let model = ProtocolModel::build(&input);
    assert!(!model.actors.is_empty());
    assert!(model
        .actors
        .iter()
        .any(|a| a.kind == ActorKind::UpgradeAuthority));
    assert!(model.capability_graph.has(CapabilityKind::Upgrade));
    assert!(!model.upgrade_paths.is_empty());
}

#[test]
fn build_protocol_model_with_selectors() {
    let iface = evm_interface(&[
        selectors::MINT_ADDR_UINT,
        selectors::BURN_UINT,
        selectors::PAUSE,
        selectors::UNPAUSE,
    ]);
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: Some(&iface),
    };
    let model = ProtocolModel::build(&input);
    assert!(model.capability_graph.has(CapabilityKind::Mint));
    assert!(model.capability_graph.has(CapabilityKind::Burn));
    assert!(model.capability_graph.has(CapabilityKind::Pause));
    assert_eq!(model.state_machines.len(), 1);
    assert_eq!(
        model.state_machines[0].machine_kind,
        StateMachineKind::Pausable
    );
}

#[test]
fn build_protocol_model_with_deps() {
    let deps = vec![
        dep("dep:oracle", DependencyKind::PriceOracle),
        dep("dep:bridge", DependencyKind::Bridge),
        dep("dep:governance", DependencyKind::Governance),
        dep("dep:vault", DependencyKind::Vault),
        dep("dep:token", DependencyKind::Token),
    ];
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &deps,
        interface: None,
    };
    let model = ProtocolModel::build(&input);
    assert!(model.capability_graph.has(CapabilityKind::OracleDependency));
    assert!(model.capability_graph.has(CapabilityKind::BridgeDependency));
    assert!(model.capability_graph.has(CapabilityKind::Governance));
    assert!(model.capability_graph.has(CapabilityKind::Treasury));
    assert_eq!(model.assets.len(), 2);
    assert!(model.trust_boundaries.len() >= 3);
}

#[test]
fn derive_capability_graph_deterministic() {
    let deps = vec![
        dep("dep:1", DependencyKind::PriceOracle),
        dep("dep:2", DependencyKind::Bridge),
    ];
    let g1 = derive_capability_graph(None, &deps, None);
    let g2 = derive_capability_graph(None, &deps, None);
    assert_eq!(g1.id, g2.id);
    assert_eq!(g1.capabilities, g2.capabilities);
    assert_eq!(g1.edges, g2.edges);
}

#[test]
fn derive_capability_graph_sorted() {
    let iface = evm_interface(&[
        selectors::MINT_ADDR_UINT,
        selectors::BURN_UINT,
        selectors::PAUSE,
        selectors::UPGRADE_TO,
        selectors::FLASH_LOAN_3156,
        selectors::PROPOSE,
        selectors::WITHDRAW_UINT,
    ]);
    let graph = derive_capability_graph(None, &[], Some(&iface));
    assert_eq!(graph.capabilities.len(), 7);
    for w in graph.capabilities.windows(2) {
        assert!(
            w[0].id <= w[1].id,
            "capabilities not sorted: {} > {}",
            w[0].id,
            w[1].id
        );
    }
}

#[test]
fn derive_permissions_sorted() {
    let mut caps = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![
            Capability::new(CapabilityKind::Mint, vec!["fn:1".into()]),
            Capability::new(CapabilityKind::Burn, vec!["fn:2".into()]),
            Capability::new(CapabilityKind::Pause, vec!["fn:3".into()]),
            Capability::new(CapabilityKind::Governance, vec!["fn:4".into()]),
        ],
        edges: vec![],
        provenance: tp(),
    };
    caps.capabilities.sort_by(|a, b| a.id.cmp(&b.id));
    let perms = derive_permissions(&caps, Some(&addr("0xaaaa")));
    assert_eq!(perms.len(), 4);
    for w in perms.windows(2) {
        assert!(
            w[0].id <= w[1].id,
            "permissions not sorted: {} > {}",
            w[0].id,
            w[1].id
        );
    }
}

#[test]
fn permissions_upgrade_gets_holder() {
    let mut caps = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![Capability::new(
            CapabilityKind::Upgrade,
            vec!["fn:1".into()],
        )],
        edges: vec![],
        provenance: tp(),
    };
    caps.capabilities.sort_by(|a, b| a.id.cmp(&b.id));
    let perms = derive_permissions(&caps, Some(&addr("0xaaaa")));
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].action, PermissionAction::Upgrade);
    assert_eq!(perms[0].holder, Some(addr("0xaaaa")));
}

#[test]
fn permissions_non_upgrade_no_holder() {
    let mut caps = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![Capability::new(CapabilityKind::Mint, vec!["fn:1".into()])],
        edges: vec![],
        provenance: tp(),
    };
    caps.capabilities.sort_by(|a, b| a.id.cmp(&b.id));
    let perms = derive_permissions(&caps, Some(&addr("0xaaaa")));
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].action, PermissionAction::Mint);
    assert_eq!(perms[0].holder, None);
}

#[test]
fn derive_invariants_empty_inputs() {
    let graph = CapabilityGraph {
        id: "capgraph:empty".into(),
        capabilities: vec![],
        edges: vec![],
        provenance: tp(),
    };
    let invariants = crate::invariants::derive_invariant_candidates(&graph, &[], &[], &[]);
    assert!(invariants.is_empty());
}

#[test]
fn derive_invariants_supply_conservation() {
    let graph = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![
            Capability::new(CapabilityKind::Mint, vec!["fn:1".into()]),
            Capability::new(CapabilityKind::Burn, vec!["fn:2".into()]),
        ],
        edges: vec![],
        provenance: tp(),
    };
    let invariants = crate::invariants::derive_invariant_candidates(&graph, &[], &[], &[]);
    assert!(invariants
        .iter()
        .any(|i| i.kind == InvariantKind::SupplyConservation));
    assert!(invariants.iter().all(|i| i.candidate));
}

#[test]
fn derive_invariants_ownership_preservation() {
    let actors = vec![Actor::new(
        ActorKind::Owner,
        addr("0xaaaa"),
        vec!["auth:1".into()],
    )];
    let graph = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![],
        edges: vec![],
        provenance: tp(),
    };
    let invariants = crate::invariants::derive_invariant_candidates(&graph, &actors, &[], &[]);
    assert!(invariants
        .iter()
        .any(|i| i.kind == InvariantKind::OwnershipPreservation));
}

#[test]
fn derive_invariants_vault_accounting() {
    let assets = vec![Asset::new(
        AssetKind::Vault,
        addr("0xaaaa"),
        vec!["dep:1".into()],
    )];
    let graph = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![],
        edges: vec![],
        provenance: tp(),
    };
    let invariants = crate::invariants::derive_invariant_candidates(&graph, &[], &assets, &[]);
    assert!(invariants
        .iter()
        .any(|i| i.kind == InvariantKind::VaultAccountingConsistency));
}

#[test]
fn derive_invariants_upgrade_safety() {
    let graph = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![Capability::new(
            CapabilityKind::Upgrade,
            vec!["dep:1".into()],
        )],
        edges: vec![],
        provenance: tp(),
    };
    let invariants = crate::invariants::derive_invariant_candidates(&graph, &[], &[], &[]);
    assert!(invariants
        .iter()
        .any(|i| i.kind == InvariantKind::UpgradeSafety));
}

#[test]
fn derive_economic_flows_sorted() {
    let mut caps = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![
            Capability::new(CapabilityKind::Mint, vec!["fn:1".into()]),
            Capability::new(CapabilityKind::Burn, vec!["fn:2".into()]),
        ],
        edges: vec![],
        provenance: tp(),
    };
    caps.capabilities.sort_by(|a, b| a.id.cmp(&b.id));
    let flows = crate::economics::derive_economic_flows(&caps, &[], &[]);
    assert!(flows.len() >= 2);
    for w in flows.windows(2) {
        assert!(
            w[0].id <= w[1].id,
            "flows not sorted: {} > {}",
            w[0].id,
            w[1].id
        );
    }
}

#[test]
fn derive_state_machines_sorted() {
    let mut caps = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![
            Capability::new(CapabilityKind::Pause, vec!["fn:1".into()]),
            Capability::new(CapabilityKind::Upgrade, vec!["fn:2".into()]),
        ],
        edges: vec![],
        provenance: tp(),
    };
    caps.capabilities.sort_by(|a, b| a.id.cmp(&b.id));
    let machines = crate::state_machine::derive_state_machines(&caps, None);
    assert_eq!(machines.len(), 2);
    for w in machines.windows(2) {
        assert!(
            w[0].id <= w[1].id,
            "machines not sorted: {} > {}",
            w[0].id,
            w[1].id
        );
    }
}

#[test]
fn derive_trust_deterministic() {
    let actors = vec![Actor::new(
        ActorKind::Owner,
        addr("0xaaaa"),
        vec!["auth:1".into()],
    )];
    let deps = vec![dep("dep:1", DependencyKind::PriceOracle)];
    let graph = CapabilityGraph {
        id: "capgraph:test".into(),
        capabilities: vec![Capability::new(CapabilityKind::Pause, vec!["fn:1".into()])],
        edges: vec![],
        provenance: tp(),
    };
    let t1 = crate::trust::derive_trust(None, &deps, &actors, &graph);
    let t2 = crate::trust::derive_trust(None, &deps, &actors, &graph);
    assert_eq!(t1.graph.id, t2.graph.id);
    assert_eq!(t1.boundaries.len(), t2.boundaries.len());
    for (b1, b2) in t1.boundaries.iter().zip(t2.boundaries.iter()) {
        assert_eq!(b1.id, b2.id);
    }
}

#[test]
fn derive_upgrade_paths_deterministic() {
    let deployment = evm_deploy_with_auth();
    let p1 = crate::upgrade::derive_upgrade_paths(Some(&deployment));
    let p2 = crate::upgrade::derive_upgrade_paths(Some(&deployment));
    assert_eq!(p1.len(), p2.len());
    for (u1, u2) in p1.iter().zip(p2.iter()) {
        assert_eq!(u1.id, u2.id);
    }
}

#[test]
fn derive_upgrade_paths_empty_when_no_deployment() {
    let paths = crate::upgrade::derive_upgrade_paths(None);
    assert!(paths.is_empty());
}

#[test]
fn protocol_model_provenance_is_inferred() {
    let model = ProtocolModel::build(&ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    });
    assert_eq!(
        model.provenance.originating_evidence,
        EvidenceSource::Inferred
    );
    assert_eq!(model.provenance.stage, ReconstructionStage::Enrich);
    assert_eq!(model.provenance.confidence, ConfidenceTier::Inferred);
}

#[test]
fn asset_label_coverage() {
    assert_eq!(AssetKind::FungibleToken.label(), "fungible_token");
    assert_eq!(AssetKind::NonFungibleToken.label(), "non_fungible_token");
    assert_eq!(AssetKind::Vault.label(), "vault");
    assert_eq!(AssetKind::TreasuryAsset.label(), "treasury_asset");
    assert_eq!(AssetKind::NativeToken.label(), "native_token");
    assert_eq!(AssetKind::Unknown.label(), "unknown");
}

#[test]
fn actor_kind_label_coverage() {
    assert_eq!(ActorKind::Owner.label(), "owner");
    assert_eq!(ActorKind::Admin.label(), "admin");
    assert_eq!(ActorKind::UpgradeAuthority.label(), "upgrade_authority");
    assert_eq!(ActorKind::Governance.label(), "governance");
    assert_eq!(ActorKind::ExternalProtocol.label(), "external_protocol");
    assert_eq!(ActorKind::Unknown.label(), "unknown");
}

#[test]
fn permission_action_label_coverage() {
    assert_eq!(PermissionAction::Upgrade.label(), "upgrade");
    assert_eq!(PermissionAction::Mint.label(), "mint");
    assert_eq!(PermissionAction::Burn.label(), "burn");
    assert_eq!(PermissionAction::Pause.label(), "pause");
    assert_eq!(PermissionAction::Withdraw.label(), "withdraw");
    assert_eq!(PermissionAction::Govern.label(), "govern");
}

#[test]
fn capability_kind_label_coverage() {
    assert_eq!(CapabilityKind::Upgrade.label(), "upgrade");
    assert_eq!(CapabilityKind::Mint.label(), "mint");
    assert_eq!(CapabilityKind::Burn.label(), "burn");
    assert_eq!(CapabilityKind::Pause.label(), "pause");
    assert_eq!(
        CapabilityKind::OracleDependency.label(),
        "oracle_dependency"
    );
    assert_eq!(
        CapabilityKind::BridgeDependency.label(),
        "bridge_dependency"
    );
    assert_eq!(CapabilityKind::FlashLoan.label(), "flash_loan");
    assert_eq!(CapabilityKind::Delegatecall.label(), "delegatecall");
    assert_eq!(CapabilityKind::Treasury.label(), "treasury");
    assert_eq!(CapabilityKind::Governance.label(), "governance");
}

#[test]
fn surface_kind_label_coverage() {
    assert_eq!(SurfaceKind::Upgrade.label(), "upgrade");
    assert_eq!(SurfaceKind::ExternalCall.label(), "external_call");
    assert_eq!(
        SurfaceKind::PrivilegedExecution.label(),
        "privileged_execution"
    );
    assert_eq!(SurfaceKind::AssetMovement.label(), "asset_movement");
    assert_eq!(SurfaceKind::Initialization.label(), "initialization");
    assert_eq!(SurfaceKind::Proxy.label(), "proxy");
    assert_eq!(SurfaceKind::Governance.label(), "governance");
}

#[test]
fn state_machine_kind_label_coverage() {
    assert_eq!(StateMachineKind::Pausable.label(), "pausable");
    assert_eq!(StateMachineKind::Upgradeable.label(), "upgradeable");
    assert_eq!(StateMachineKind::Initializable.label(), "initializable");
}

#[test]
fn economic_flow_kind_label_coverage() {
    assert_eq!(EconomicFlowKind::Mint.label(), "mint");
    assert_eq!(EconomicFlowKind::Burn.label(), "burn");
    assert_eq!(EconomicFlowKind::Deposit.label(), "deposit");
    assert_eq!(EconomicFlowKind::Withdraw.label(), "withdraw");
    assert_eq!(EconomicFlowKind::Bridge.label(), "bridge");
    assert_eq!(EconomicFlowKind::OraclePriced.label(), "oracle_priced");
}

#[test]
fn invariant_kind_label_coverage() {
    assert_eq!(
        InvariantKind::SupplyConservation.label(),
        "supply_conservation"
    );
    assert_eq!(
        InvariantKind::OwnershipPreservation.label(),
        "ownership_preservation"
    );
    assert_eq!(
        InvariantKind::VaultAccountingConsistency.label(),
        "vault_accounting_consistency"
    );
    assert_eq!(
        InvariantKind::AuthorizationConsistency.label(),
        "authorization_consistency"
    );
    assert_eq!(InvariantKind::UpgradeSafety.label(), "upgrade_safety");
}
