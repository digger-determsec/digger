//! Deterministic selection logic for the Research Context.
//!
//! Selects the minimal relevant subset of protocols, investigations, and graph
//! nodes based on EXACT fingerprint equality matches. No scoring, no ranking,
//! no fuzzy match.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use ::digger_investigation::InvestigationPlan;
use ::digger_protocol_model::model::ProtocolModel;
use ::digger_research_graph::graph::ResearchGraph;
use ::digger_research_graph::node::NodeKind;

/// Why a particular reference was included in the context.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SelectionFilter {
    ExactCompositeFingerprint,
    ExactCapabilityFingerprint,
    ExactDependencyFingerprint,
    InvestigationTargetKindOverlap,
    SharedInvariantFamily,
    SharedTrustBoundary,
}

impl SelectionFilter {
    pub fn label(&self) -> &'static str {
        match self {
            SelectionFilter::ExactCompositeFingerprint => "exact_composite_fingerprint",
            SelectionFilter::ExactCapabilityFingerprint => "exact_capability_fingerprint",
            SelectionFilter::ExactDependencyFingerprint => "exact_dependency_fingerprint",
            SelectionFilter::InvestigationTargetKindOverlap => "investigation_target_kind_overlap",
            SelectionFilter::SharedInvariantFamily => "shared_invariant_family",
            SelectionFilter::SharedTrustBoundary => "shared_trust_boundary",
        }
    }
}

/// Structured selection reason: which filter matched and for which target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SelectionReason {
    pub filter: SelectionFilter,
    pub matched_protocol_id: String,
}

/// Collect the TargetKinds from an InvestigationPlan's targets.
fn plan_target_kinds(plan: &InvestigationPlan) -> BTreeSet<&'static str> {
    plan.targets.iter().map(|t| t.kind.label()).collect()
}

/// Collect the invariant fingerprint ids from a ProtocolModel's invariant
/// candidates (the invariant_fp on the ArchitectureFingerprint summarizes these).
fn protocol_invariant_fingerprint(pm: &ProtocolModel) -> String {
    use ::digger_research_graph::ids::{digest_str, sorted_unique};
    let labels: Vec<String> = pm
        .invariant_candidates
        .iter()
        .map(|i| format!("{:?}", i.kind))
        .collect();
    let sorted = sorted_unique(labels);
    digest_str(&format!("invariant|{}", sorted.join(",")))
}

/// Collect the trust boundary fingerprint ids from a ProtocolModel.
fn protocol_trust_fingerprint(pm: &ProtocolModel) -> String {
    use ::digger_research_graph::ids::{digest_str, sorted_unique};
    let labels: Vec<String> = pm
        .trust_boundaries
        .iter()
        .map(|b| format!("{:?}", b.kind))
        .collect();
    let sorted = sorted_unique(labels);
    digest_str(&format!("trust|{}", sorted.join(",")))
}

/// Deterministically select related protocol ids, investigation ids, and graph
/// node ids that match the current protocol's fingerprints/plan via exact
/// equality.
///
/// Returns (selected_protocol_ids, selected_investigation_ids, selected_node_ids, reasons).
pub fn select_related(
    model: &ProtocolModel,
    plan: &InvestigationPlan,
    graph: &ResearchGraph,
) -> (
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeSet<String>,
    Vec<SelectionReason>,
) {
    // Current protocol's fingerprints.
    let current_fp = graph
        .fingerprints
        .iter()
        .find(|f| f.protocol_id == model.id);
    let current_invariant_fp = protocol_invariant_fingerprint(model);
    let current_trust_fp = protocol_trust_fingerprint(model);
    let current_target_kinds = plan_target_kinds(plan);

    // Build index: protocol_id -> protocol node id
    let mut protocol_node_id: BTreeMap<String, String> = BTreeMap::new();
    let mut investigation_node_id: BTreeMap<String, String> = BTreeMap::new();
    let mut node_kind: BTreeMap<String, NodeKind> = BTreeMap::new();
    for n in &graph.nodes {
        node_kind.insert(n.id.clone(), n.kind);
        match n.kind {
            NodeKind::Protocol => {
                protocol_node_id.insert(n.ref_id.clone(), n.id.clone());
            }
            NodeKind::Investigation => {
                investigation_node_id.insert(n.ref_id.clone(), n.id.clone());
            }
            _ => {}
        }
    }

    // Index: protocol_node_id -> investigation_node_id (via References edges)
    let mut investigation_of: BTreeMap<String, String> = BTreeMap::new();
    for e in &graph.edges {
        if e.kind == ::digger_research_graph::edge::EdgeKind::References
            && node_kind.get(&e.from_id) == Some(&NodeKind::Protocol)
            && node_kind.get(&e.to_id) == Some(&NodeKind::Investigation)
        {
            investigation_of.insert(e.from_id.clone(), e.to_id.clone());
        }
    }

    let mut selected_protocols: BTreeSet<String> = BTreeSet::new();
    let mut selected_investigations: BTreeSet<String> = BTreeSet::new();
    let mut selected_nodes: BTreeSet<String> = BTreeSet::new();
    let mut reasons: Vec<SelectionReason> = Vec::new();

    // Always include the current protocol and its investigation.
    if let Some(pnid) = protocol_node_id.get(&model.id) {
        selected_nodes.insert(pnid.clone());
    }
    // Direct: find investigation node for current protocol.
    if let Some(pnid) = protocol_node_id.get(&model.id) {
        if let Some(inv_nid) = investigation_of.get(pnid) {
            selected_nodes.insert(inv_nid.clone());
        }
    }

    // Iterate over all fingerprints in the graph to find matches.
    for fp in &graph.fingerprints {
        if fp.protocol_id == model.id {
            // Current protocol's own fingerprint -- its nodes are already included.
            continue;
        }

        let mut matched = false;

        // Filter 1: exact composite fingerprint equality
        if let Some(current) = current_fp {
            if current.composite_fp == fp.composite_fp {
                matched = true;
                reasons.push(SelectionReason {
                    filter: SelectionFilter::ExactCompositeFingerprint,
                    matched_protocol_id: fp.protocol_id.clone(),
                });
            }
        }

        // Filter 2: exact capability fingerprint equality
        if let Some(current) = current_fp {
            if current.capability_fp == fp.capability_fp {
                matched = true;
                reasons.push(SelectionReason {
                    filter: SelectionFilter::ExactCapabilityFingerprint,
                    matched_protocol_id: fp.protocol_id.clone(),
                });
            }
        }

        // Filter 3: exact dependency fingerprint equality
        if let Some(current) = current_fp {
            if current.dependency_fp == fp.dependency_fp {
                matched = true;
                reasons.push(SelectionReason {
                    filter: SelectionFilter::ExactDependencyFingerprint,
                    matched_protocol_id: fp.protocol_id.clone(),
                });
            }
        }

        // Filter 5: shared invariant family
        if current_invariant_fp == fp.invariant_fp {
            matched = true;
            reasons.push(SelectionReason {
                filter: SelectionFilter::SharedInvariantFamily,
                matched_protocol_id: fp.protocol_id.clone(),
            });
        }

        // Filter 6: shared trust-boundary structure
        if current_trust_fp == fp.trust_fp {
            matched = true;
            reasons.push(SelectionReason {
                filter: SelectionFilter::SharedTrustBoundary,
                matched_protocol_id: fp.protocol_id.clone(),
            });
        }

        if matched {
            selected_protocols.insert(fp.protocol_id.clone());
            // Include the protocol's node.
            if let Some(pnid) = protocol_node_id.get(&fp.protocol_id) {
                selected_nodes.insert(pnid.clone());
            }
            // Include the protocol's investigation node if one exists.
            if let Some(pnid) = protocol_node_id.get(&fp.protocol_id) {
                if let Some(inv_nid) = investigation_of.get(pnid) {
                    selected_nodes.insert(inv_nid.clone());
                    // Collect the investigation's plan target kinds for filter 4.
                    // We need to find the investigation target kinds from the graph.
                    // Investigation nodes reference InvestigationTarget nodes.
                    for e in graph.edges_from(inv_nid) {
                        if e.kind == ::digger_research_graph::edge::EdgeKind::References
                            && node_kind.get(&e.to_id) == Some(&NodeKind::InvestigationTarget)
                        {
                            selected_nodes.insert(e.to_id.clone());
                        }
                    }
                }
            }
        }
    }

    // Filter 4: investigation target-kind overlap.
    // For each matched protocol, check if any of its investigation targets share
    // a target kind with the current plan.
    let matched_protocols: Vec<String> = selected_protocols.iter().cloned().collect();
    for mpid in &matched_protocols {
        if let Some(pnid) = protocol_node_id.get(mpid) {
            if let Some(inv_nid) = investigation_of.get(pnid) {
                for e in graph.edges_from(inv_nid) {
                    if e.kind == ::digger_research_graph::edge::EdgeKind::References {
                        if let Some(target_node) = graph.node(&e.to_id) {
                            if target_node.kind == NodeKind::InvestigationTarget {
                                // Check if the target's label matches any current target kind.
                                let target_kind_label = target_node.label.as_str();
                                if current_target_kinds
                                    .iter()
                                    .any(|tk| target_kind_label.contains(tk))
                                    && !reasons.iter().any(|r| {
                                        r.filter == SelectionFilter::InvestigationTargetKindOverlap
                                            && r.matched_protocol_id == *mpid
                                    })
                                {
                                    reasons.push(SelectionReason {
                                        filter: SelectionFilter::InvestigationTargetKindOverlap,
                                        matched_protocol_id: mpid.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Collect all investigation ids for selected protocols.
    for mpid in &selected_protocols {
        if let Some(pnid) = protocol_node_id.get(mpid) {
            if let Some(inv_nid) = investigation_of.get(pnid) {
                selected_investigations.insert(inv_nid.clone());
            }
        }
    }

    // Include all nodes that are connected to selected protocol/investigation nodes
    // via within-protocol edges (Controls, DependsOn, etc.).
    let all_selected: Vec<String> = selected_nodes.iter().cloned().collect();
    for nid in &all_selected {
        for e in graph.edges_from(nid) {
            if matches!(
                e.kind,
                ::digger_research_graph::edge::EdgeKind::Controls
                    | ::digger_research_graph::edge::EdgeKind::DependsOn
                    | ::digger_research_graph::edge::EdgeKind::Owns
                    | ::digger_research_graph::edge::EdgeKind::Protects
                    | ::digger_research_graph::edge::EdgeKind::Upgrades
                    | ::digger_research_graph::edge::EdgeKind::References
            ) {
                selected_nodes.insert(e.to_id.clone());
            }
        }
        // Also follow edges TO this node.
        for e in &graph.edges {
            if e.to_id == *nid
                && matches!(
                    e.kind,
                    ::digger_research_graph::edge::EdgeKind::Controls
                        | ::digger_research_graph::edge::EdgeKind::DependsOn
                        | ::digger_research_graph::edge::EdgeKind::Owns
                        | ::digger_research_graph::edge::EdgeKind::Protects
                        | ::digger_research_graph::edge::EdgeKind::Upgrades
                )
            {
                selected_nodes.insert(e.from_id.clone());
            }
        }
    }

    // Deterministic ordering for reasons.
    reasons.sort();
    reasons.dedup_by(|a, b| a.filter == b.filter && a.matched_protocol_id == b.matched_protocol_id);

    (
        selected_protocols,
        selected_investigations,
        selected_nodes,
        reasons,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_reason_is_deterministic() {
        let r1 = SelectionReason {
            filter: SelectionFilter::ExactCompositeFingerprint,
            matched_protocol_id: "protocol:abc".to_string(),
        };
        let r2 = SelectionReason {
            filter: SelectionFilter::ExactCompositeFingerprint,
            matched_protocol_id: "protocol:abc".to_string(),
        };
        assert_eq!(r1, r2);
        // Ordering is deterministic: sorted by filter discriminant, then protocol_id
        let mut reasons = [
            SelectionReason {
                filter: SelectionFilter::SharedTrustBoundary,
                matched_protocol_id: "protocol:aaa".to_string(),
            },
            SelectionReason {
                filter: SelectionFilter::ExactCompositeFingerprint,
                matched_protocol_id: "protocol:bbb".to_string(),
            },
        ];
        reasons.sort();
        // ExactCompositeFingerprint (discriminant 0) < SharedTrustBoundary (discriminant 5)
        assert_eq!(
            reasons[0].filter,
            SelectionFilter::ExactCompositeFingerprint
        );
        assert_eq!(reasons[0].matched_protocol_id, "protocol:bbb");
        assert_eq!(reasons[1].filter, SelectionFilter::SharedTrustBoundary);
        assert_eq!(reasons[1].matched_protocol_id, "protocol:aaa");
    }
}
