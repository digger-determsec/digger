//! Edge mapping — maps Gen 5 capabilities to SystemIR Edge variants.
//!
//! B4 scope: Authority edges + External edges only.
//!
//! # Deliberate omissions (no fabrication)
//!
//! - **NO `Edge::Call`**: CapabilityEdge `Controls`/`UsesMechanism` are
//!   semantic relations, NOT recovered call-graph edges. Emitting CallEdges
//!   would create phantom call/reentrancy attack paths.
//! - **NO `Edge::State`**: Synthetic functions have no recovered bodies, so
//!   state access cannot be derived faithfully.
//! - **Cross-protocol edges** (SharesCapability/SharesDependency) excluded (D3).

use digger_ir::{AuthorityEdge, Edge, ExternalCallEdge};
use digger_protocol_model::capability_graph::{Capability, CapabilityKind};
use digger_protocol_model::permissions::Permission;
use digger_protocol_model::trust::TrustBoundary;
use digger_protocol_model::RecoveredDependency;

/// Kinds that are per-guard (have a corresponding PermissionAction).
fn is_guardable_kind(kind: CapabilityKind) -> bool {
    matches!(
        kind,
        CapabilityKind::Upgrade
            | CapabilityKind::Mint
            | CapabilityKind::Burn
            | CapabilityKind::Pause
            | CapabilityKind::Treasury
            | CapabilityKind::Governance
            | CapabilityKind::Delegatecall
            | CapabilityKind::BridgeDependency
    )
}

/// Kinds that produce external calls.
fn is_external_kind(kind: CapabilityKind) -> bool {
    matches!(
        kind,
        CapabilityKind::OracleDependency
            | CapabilityKind::BridgeDependency
            | CapabilityKind::FlashLoan
            | CapabilityKind::Delegatecall
    )
}

/// Map resolved capabilities + permissions to Authority and External edges.
pub fn map_to_edges(
    capabilities: &[Capability],
    permissions: &[Permission],
    trust_boundaries: &[TrustBoundary],
    dependencies: &[RecoveredDependency],
    function_names: &[String],
) -> Vec<Edge> {
    let mut edges: Vec<Edge> = Vec::new();

    // Build permission index: capability_fact_id -> Permission.
    let mut perm_index: std::collections::BTreeMap<String, &Permission> =
        std::collections::BTreeMap::new();
    for p in permissions {
        perm_index.insert(p.capability_fact_id.clone(), p);
    }

    // Build capability index: kind -> capability id.
    let mut kind_to_cap_id: std::collections::BTreeMap<CapabilityKind, String> =
        std::collections::BTreeMap::new();
    for c in capabilities {
        kind_to_cap_id.entry(c.kind).or_insert_with(|| c.id.clone());
    }

    // Authority edges: one per guardable function.
    for name in function_names {
        let cap_kind = parse_function_kind(name);
        let Some(kind) = cap_kind else { continue };
        if !is_guardable_kind(kind) {
            continue;
        }

        // Determine check_type from holder evidence.
        let check_type = if let Some(cap_id) = kind_to_cap_id.get(&kind) {
            let has_holder = perm_index
                .values()
                .any(|p| p.capability_fact_id == *cap_id && p.holder.is_some());
            if has_holder {
                "enforced"
            } else {
                "missing"
            }
        } else {
            "missing"
        };

        edges.push(Edge::Authority(AuthorityEdge {
            function: name.clone(),
            authority_source: "unknown".into(),
            check_type: check_type.into(),
        }));
    }

    // External edges: one per external-call function.
    for name in function_names {
        let cap_kind = parse_function_kind(name);
        let Some(kind) = cap_kind else { continue };
        if !is_external_kind(kind) {
            continue;
        }

        let target = find_dependency_target(kind, dependencies);

        edges.push(Edge::External(ExternalCallEdge {
            function: name.clone(),
            target,
            risk_flags: vec!["external_call".into()],
        }));
    }

    // Authority edges from TrustBoundary UpgradeAuthority entries.
    for tb in trust_boundaries {
        if tb.kind == ::digger_protocol_model::trust::TrustBoundaryKind::UpgradeAuthority {
            let upgrade_name = function_names
                .iter()
                .find(|n| n.starts_with("__gen5::upgrade"))
                .cloned();
            if let Some(name) = upgrade_name {
                let already_has = edges.iter().any(|e| {
                    matches!(e, Edge::Authority(a) if a.function == name && a.check_type == "enforced")
                });
                if !already_has {
                    edges.push(Edge::Authority(AuthorityEdge {
                        function: name,
                        authority_source: "trust_boundary".into(),
                        check_type: "enforced".into(),
                    }));
                }
            }
        }
    }

    // Deterministic sorting.
    crate::ordering::canonical_edge_order(&mut edges);
    edges
}

/// Extract the CapabilityKind from a function name.
fn parse_function_kind(name: &str) -> Option<CapabilityKind> {
    let rest = name.strip_prefix("__gen5::")?;
    let kind_str = rest.split("::").next()?;
    match kind_str {
        "upgrade" => Some(CapabilityKind::Upgrade),
        "mint" => Some(CapabilityKind::Mint),
        "burn" => Some(CapabilityKind::Burn),
        "pause" => Some(CapabilityKind::Pause),
        "oracle_dependency" => Some(CapabilityKind::OracleDependency),
        "bridge_dependency" => Some(CapabilityKind::BridgeDependency),
        "flash_loan" => Some(CapabilityKind::FlashLoan),
        "delegatecall" => Some(CapabilityKind::Delegatecall),
        "treasury" => Some(CapabilityKind::Treasury),
        "governance" => Some(CapabilityKind::Governance),
        _ => None,
    }
}

/// Find a dependency target for an external-call capability.
fn find_dependency_target(kind: CapabilityKind, dependencies: &[RecoveredDependency]) -> String {
    let dep_kind = match kind {
        CapabilityKind::OracleDependency => {
            Some(::digger_protocol_model::DependencyKind::PriceOracle)
        }
        CapabilityKind::BridgeDependency => Some(::digger_protocol_model::DependencyKind::Bridge),
        _ => None,
    };

    if let Some(dk) = dep_kind {
        if dependencies.iter().any(|d| d.kind == dk) {
            return kind.label().to_string();
        }
    }
    "external".into()
}
