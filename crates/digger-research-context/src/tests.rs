//! Deterministic unit tests for the research context (run under `cargo test` in
//! CI; no toolchain in the build sandbox).

use super::*;
use crate::context::assemble_research_context;
use ::digger_investigation::build_investigation_plan;
use ::digger_protocol_model::model::{ProtocolModel, ProtocolModelInput};
use ::digger_reconstruct::fact::RecoveredFact;
use ::digger_research_graph::builder::build_research_graph;

/// Build an empty protocol model + plan + graph.
fn empty_setup() -> (
    ProtocolModel,
    ::digger_investigation::InvestigationPlan,
    ::digger_research_graph::graph::ResearchGraph,
) {
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let pm = ProtocolModel::build(&input);
    let plan = build_investigation_plan(&pm);
    let graph = build_research_graph(&pm, &plan);
    (pm, plan, graph)
}

/// Build a graph with two identical empty protocols merged together.
fn two_identical_protocols() -> (
    ProtocolModel,
    ::digger_investigation::InvestigationPlan,
    ::digger_research_graph::graph::ResearchGraph,
) {
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let pm1 = ProtocolModel::build(&input);
    let plan1 = build_investigation_plan(&pm1);
    let graph1 = build_research_graph(&pm1, &plan1);

    let pm2 = ProtocolModel::build(&input);
    let plan2 = build_investigation_plan(&pm2);
    let graph2 = build_research_graph(&pm2, &plan2);

    let merged = ::digger_research_graph::graph::ResearchGraph::merge(&[&graph1, &graph2]);
    (pm1, plan1, merged)
}

#[test]
fn references_only_no_copied_objects() {
    let (pm, plan, graph) = empty_setup();
    let ctx = assemble_research_context(&pm, &plan, &graph);

    assert_eq!(ctx.current_protocol_id, pm.id);
    assert_eq!(ctx.current_investigation_id, plan.id);

    for pid in &ctx.referenced_protocol_ids {
        assert!(!pid.is_empty());
    }
}

#[test]
fn context_is_deterministic() {
    let (pm, plan, graph) = empty_setup();
    let ctx1 = assemble_research_context(&pm, &plan, &graph);
    let ctx2 = assemble_research_context(&pm, &plan, &graph);
    assert_eq!(ctx1, ctx2);
    assert_eq!(ctx1.id, ctx2.id);
    assert_eq!(ctx1.provenance.id, ctx2.provenance.id);
}

#[test]
fn recovered_fact_impl_is_present() {
    let (pm, plan, graph) = empty_setup();
    let ctx = assemble_research_context(&pm, &plan, &graph);

    assert_eq!(ctx.fact_id(), ctx.id);
    assert!(ctx.id.starts_with("rctx:"));

    let prov = ctx.provenance();
    assert!(!prov.id.is_empty());
    assert_eq!(
        prov.originating_evidence,
        ::digger_reconstruct::provenance::EvidenceSource::Inferred
    );
    assert_eq!(
        prov.stage,
        ::digger_reconstruct::provenance::ReconstructionStage::Enrich
    );
    assert_eq!(
        ctx.confidence(),
        ::digger_reconstruct::confidence::ConfidenceTier::Inferred
    );
    assert!(!ctx.reproducibility().reconstructor_crate.is_empty());
}

#[test]
fn context_self_includes_current_protocol_node() {
    let (pm, plan, graph) = empty_setup();
    let ctx = assemble_research_context(&pm, &plan, &graph);

    let protocol_node = graph.node_by_ref(&pm.id);
    if let Some(pn) = protocol_node {
        assert!(
            ctx.referenced_node_ids.contains(&pn.id),
            "current protocol's graph node should be in the context"
        );
    }
}

#[test]
fn context_self_includes_investigation_node() {
    let (pm, plan, graph) = empty_setup();
    let ctx = assemble_research_context(&pm, &plan, &graph);

    let inv_node = graph.node_by_ref(&plan.id);
    if let Some(inv) = inv_node {
        assert!(
            ctx.referenced_node_ids.contains(&inv.id),
            "current investigation's graph node should be in the context"
        );
    }
}

#[test]
fn boundedness_context_not_exceeding_full_graph() {
    let (pm, plan, graph) = empty_setup();
    let ctx = assemble_research_context(&pm, &plan, &graph);

    assert!(
        ctx.node_count() <= graph.nodes.len(),
        "context ({} nodes) should not exceed full graph ({} nodes)",
        ctx.node_count(),
        graph.nodes.len()
    );
}

#[test]
fn idempotency_same_inputs_produce_same_output() {
    let (pm, plan, graph) = empty_setup();

    let ctx1 = assemble_research_context(&pm, &plan, &graph);
    let ctx2 = assemble_research_context(&pm, &plan, &graph);
    let ctx3 = assemble_research_context(&pm, &plan, &graph);

    assert_eq!(ctx1, ctx2);
    assert_eq!(ctx2, ctx3);
    assert_eq!(ctx1.id, ctx3.id);
}

#[test]
fn context_protocol_count_matches_set() {
    let (pm, plan, graph) = empty_setup();
    let ctx = assemble_research_context(&pm, &plan, &graph);
    assert_eq!(ctx.protocol_count(), ctx.referenced_protocol_ids.len());
}

#[test]
fn reasons_for_returns_matching_entries() {
    let (pm, plan, graph) = empty_setup();
    let ctx = assemble_research_context(&pm, &plan, &graph);

    if let Some(selected_pid) = ctx.referenced_protocol_ids.iter().next() {
        let reasons = ctx.reasons_for(selected_pid);
        for r in &reasons {
            assert_eq!(r.matched_protocol_id, *selected_pid);
        }
    }
}

#[test]
fn selection_reason_ordering_is_deterministic() {
    let r1 = SelectionReason {
        filter: SelectionFilter::ExactCompositeFingerprint,
        matched_protocol_id: "protocol:abc".to_string(),
    };
    let r2 = SelectionReason {
        filter: SelectionFilter::ExactCompositeFingerprint,
        matched_protocol_id: "protocol:abc".to_string(),
    };
    assert_eq!(r1, r2);

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

#[test]
fn context_boundedness_single_protocol() {
    let (pm, plan, graph) = empty_setup();
    let ctx = assemble_research_context(&pm, &plan, &graph);

    // For a single empty protocol, no other protocols should be referenced.
    assert_eq!(ctx.protocol_count(), 0);
    assert!(ctx.node_count() <= graph.nodes.len());
}

#[test]
fn merged_graph_still_self_contained() {
    let (pm, plan, graph) = two_identical_protocols();
    let ctx = assemble_research_context(&pm, &plan, &graph);

    // Identical empty protocols get deduplicated by merge, so the merged graph
    // has only one protocol. The context should still be valid and bounded.
    assert!(ctx.node_count() <= graph.nodes.len());
    assert!(ctx.node_count() > 0);
}
