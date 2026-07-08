//! Actors -- the deterministic principals a protocol recognizes, derived from
//! recovered deployment authorities and dependency facts. An actor is always
//! tied to a recovered address (resolved or honestly unresolved); we never
//! invent principals that have no recovered evidence.

use serde::{Deserialize, Serialize};

use crate::ids::node_id;
use crate::{
    derive_provenance, AuthorityKind, DependencyKind, DeploymentDetail, Provenance,
    RecoveredAddress, RecoveredDependency, RecoveredDeployment,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActorKind {
    Owner,
    Admin,
    UpgradeAuthority,
    Governance,
    ExternalProtocol,
    Unknown,
}

impl ActorKind {
    pub fn label(&self) -> &'static str {
        match self {
            ActorKind::Owner => "owner",
            ActorKind::Admin => "admin",
            ActorKind::UpgradeAuthority => "upgrade_authority",
            ActorKind::Governance => "governance",
            ActorKind::ExternalProtocol => "external_protocol",
            ActorKind::Unknown => "unknown",
        }
    }

    fn from_authority(kind: AuthorityKind) -> ActorKind {
        match kind {
            AuthorityKind::ProxyAdmin => ActorKind::Admin,
            AuthorityKind::UpgradeAuthority => ActorKind::UpgradeAuthority,
            AuthorityKind::BeaconOwner => ActorKind::Owner,
            AuthorityKind::DiamondOwner => ActorKind::Owner,
        }
    }
}

/// A recovered protocol actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// Deterministic content-addressed id (`actor:<digest>`).
    pub id: String,
    pub kind: ActorKind,
    pub address: RecoveredAddress,
    pub basis_fact_ids: Vec<String>,
    pub provenance: Provenance,
}

impl Actor {
    pub fn new(kind: ActorKind, address: RecoveredAddress, basis_fact_ids: Vec<String>) -> Self {
        let mut basis = basis_fact_ids;
        basis.sort();
        basis.dedup();
        let canon = format!("actor|{}|{:?}|{}", kind.label(), address, basis.join(","));
        let provenance = derive_provenance(&canon, &basis.join(","));
        Actor {
            id: node_id("actor", &canon),
            kind,
            address,
            basis_fact_ids: basis,
            provenance,
        }
    }
}

impl_protocol_fact!(Actor);

/// Deterministically derive actors from recovered deployment + dependencies.
pub fn derive_actors(
    deployment: Option<&RecoveredDeployment>,
    dependencies: &[RecoveredDependency],
) -> Vec<Actor> {
    let mut actors: Vec<Actor> = Vec::new();

    if let Some(dep) = deployment {
        match &dep.detail {
            DeploymentDetail::Evm(e) => {
                if let Some(auth) = &e.upgrade_authority {
                    actors.push(Actor::new(
                        ActorKind::from_authority(auth.kind),
                        auth.address.clone(),
                        vec![auth.id.clone(), dep.id.clone()],
                    ));
                }
            }
            DeploymentDetail::Solana(s) => {
                if let Some(auth) = &s.upgrade_authority {
                    actors.push(Actor::new(
                        ActorKind::from_authority(auth.kind),
                        auth.address.clone(),
                        vec![auth.id.clone(), dep.id.clone()],
                    ));
                }
            }
        }
    }

    for d in dependencies {
        let kind = match d.kind {
            DependencyKind::Governance => Some(ActorKind::Governance),
            DependencyKind::ExternalProtocol => Some(ActorKind::ExternalProtocol),
            _ => None,
        };
        if let Some(k) = kind {
            actors.push(Actor::new(k, d.address.clone(), vec![d.id.clone()]));
        }
    }

    actors.sort_by(|a, b| a.id.cmp(&b.id));
    actors.dedup_by(|a, b| a.id == b.id);
    actors
}
