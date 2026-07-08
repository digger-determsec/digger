#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

//! digger-systemir-bridge — Generation 5 Phase B: SystemIR Bridge.
//!
//! Connects the deterministic Gen 5 pre-IR pipeline to the Gen 1/2 analysis
//! pipeline by converting Gen 5 `ProtocolModel` + `ResearchContext` +
//! `InvestigationPlan` into per-protocol `SystemIR` collections.
//!
//! ```text
//! Gen 5: ProtocolModel + InvestigationPlan + ResearchContext
//!   → digger-systemir-bridge
//!   → BridgedOutput { systems: BTreeMap<ProtocolId, SystemIR> }
//!   → Gen 2/3/4 analysis
//! ```
//!
//! This is the ONLY crate allowed to depend on both `digger-ir` (for SystemIR)
//! and the Gen 5 chain. No Gen 5 crate gains a `digger-ir` dependency.
//!
//! # Determinism
//!
//! - BTreeMap/BTreeSet only (no HashMap/HashSet)
//! - No f32/f64, no rand/time
//! - Provenance is deterministic and preserved
//! - Same inputs → byte-identical BridgedOutput

use std::collections::BTreeMap;

use digger_ir::{Language, SystemIR};
use digger_reconstruct::provenance::Provenance;

pub use digger_investigation::InvestigationPlan;
pub use digger_protocol_model::model::ProtocolModel;
pub use digger_research_context::ResearchContext;

mod map_edges;
mod map_functions;
mod map_state;
mod ordering;
pub mod resolve;

pub use resolve::{resolve_context, ResolvedContext};

/// Re-export for testing — map_state_machines_to_state always returns empty.
pub use map_state::map_state_machines_to_state;

/// The bridge output: per-protocol SystemIR collection with Gen 5 sidecar.
///
/// `systems` maps `protocol_id → SystemIR` for each protocol referenced in the
/// ResearchContext. One SystemIR per protocol — never merged (D4).
#[derive(Debug, Clone)]
pub struct BridgedOutput {
    /// Per-protocol SystemIR, keyed by protocol id. BTreeMap = deterministic.
    pub systems: BTreeMap<String, SystemIR>,
    /// The ResearchContext id that produced this output.
    pub context_id: String,
    /// Deterministic provenance of the bridge operation.
    pub provenance: Provenance,
    /// Investigation priority sidecar (D2) — target id → priority rank.
    /// Never baked into IR ordering. Deterministic from InvestigationPlan targets.
    pub plan_priority: BTreeMap<String, u32>,
}

/// Deterministically bridge Gen 5 to SystemIR.
///
/// Returns one SystemIR per protocol referenced in the ResearchContext,
/// wrapped in a `BridgedOutput` with provenance and sidecar metadata.
pub fn bridge_to_systemir(
    model: &ProtocolModel,
    plan: &InvestigationPlan,
    context: &ResearchContext,
) -> BridgedOutput {
    // B2: Resolve context references against the protocol model.
    let resolved = resolve_context(model, context);

    // B3: Synthesize Functions from resolved capabilities.
    let functions =
        map_functions::synthesize_functions(&resolved.capabilities, &resolved.permissions);

    // Collect function names for edge mapping.
    let function_names: Vec<String> = functions.iter().map(|f| f.name.clone()).collect();

    // B4: Map to Authority + External edges.
    let edges = map_edges::map_to_edges(
        &resolved.capabilities,
        &resolved.permissions,
        &resolved.trust_boundaries,
        &resolved.dependencies,
        &function_names,
    );

    // Assemble per-protocol SystemIR.
    let system_ir = SystemIR {
        program_id: model.id.clone(),
        language: Language::Unknown,
        functions,
        state: Vec::new(), // B5: intentionally empty — no concrete storage recovered
        edges,
    };

    let mut systems = BTreeMap::new();
    systems.insert(model.id.clone(), system_ir);

    // Plan priority: project InvestigationTargets to their ranks, keyed by target id.
    let plan_priority = build_plan_priority(plan);

    let provenance = derive_bridge_provenance(&context.id, &model.id, &plan.id);

    BridgedOutput {
        systems,
        context_id: context.id.clone(),
        provenance,
        plan_priority,
    }
}

/// Deterministically build the plan_priority sidecar from InvestigationPlan targets.
///
/// Each target is projected to its PriorityRank.rank, keyed by the target's
/// deterministic content-addressed id. Only real targets from the plan; no
/// synthesized entries. Deterministic ordering (BTreeMap).
fn build_plan_priority(plan: &InvestigationPlan) -> BTreeMap<String, u32> {
    let mut priority = BTreeMap::new();
    for target in plan.ordered_targets() {
        if target.priority.rank > 0 {
            priority.insert(target.id.clone(), target.priority.rank);
        }
    }
    priority
}

/// Deterministic provenance for the bridge operation.
///
/// Basis records the source fact ids: model.id, plan.id, and context.id,
/// so lineage is fully traceable.
fn derive_bridge_provenance(context_id: &str, protocol_id: &str, plan_id: &str) -> Provenance {
    use digger_gen5_common::derive_provenance;
    let basis = format!("{}|{}|{}", protocol_id, plan_id, context_id);
    derive_provenance(&format!("bridge|{}", basis), &basis)
}

#[cfg(test)]
mod tests;
