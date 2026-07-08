//! ResearchContext -- the immutable, bounded, deterministic context assembled
//! from the current ProtocolModel + InvestigationPlan + ResearchGraph.
//!
//! It stores REFERENCES ONLY (ids, not full objects) and records WHY each
//! reference was included (structured selection reasons). It is a
//! [`RecoveredFact`] with deterministic content-addressed id.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use ::digger_reconstruct::fact::RecoveredFact;

use crate::fact_impl::derive_provenance;
use crate::ids::{canon, join_ids, node_id};
use crate::selection::SelectionReason;
use crate::Provenance;

/// An immutable, bounded, deterministic research context. Stores references only
/// (ids, not full objects). Never embeds the whole graph or copies protocol/investigation data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchContext {
    /// Deterministic content-addressed id (`rctx:<digest>`).
    pub id: String,
    /// The current protocol model id.
    pub current_protocol_id: String,
    /// The current investigation plan id.
    pub current_investigation_id: String,
    /// Referenced protocol model ids (from the graph).
    pub referenced_protocol_ids: BTreeSet<String>,
    /// Referenced investigation plan ids (from the graph).
    pub referenced_investigation_ids: BTreeSet<String>,
    /// Referenced graph node ids (the selected subset).
    pub referenced_node_ids: BTreeSet<String>,
    /// Structured reasons explaining why each reference was included.
    pub selection_reasons: Vec<SelectionReason>,
    pub provenance: Provenance,
}

impl ResearchContext {
    /// Build a ResearchContext from deterministic selection results.
    ///
    /// All inputs are borrowed; nothing is copied except ids.
    pub fn new(
        current_protocol_id: String,
        current_investigation_id: String,
        referenced_protocol_ids: BTreeSet<String>,
        referenced_investigation_ids: BTreeSet<String>,
        referenced_node_ids: BTreeSet<String>,
        selection_reasons: Vec<SelectionReason>,
    ) -> Self {
        let mut basis_parts: Vec<String> = Vec::new();
        basis_parts.push(current_protocol_id.clone());
        basis_parts.push(current_investigation_id.clone());
        basis_parts.extend(referenced_protocol_ids.iter().cloned());
        basis_parts.extend(referenced_investigation_ids.iter().cloned());
        basis_parts.extend(referenced_node_ids.iter().cloned());
        for r in &selection_reasons {
            basis_parts.push(format!("{}:{}", r.filter.label(), r.matched_protocol_id));
        }
        let basis = join_ids(&basis_parts);
        let id_canon = canon(&[&current_protocol_id, &basis]);
        let provenance = derive_provenance(&format!("rctx|{}", id_canon), &basis);

        ResearchContext {
            id: node_id("rctx", &id_canon),
            current_protocol_id,
            current_investigation_id,
            referenced_protocol_ids,
            referenced_investigation_ids,
            referenced_node_ids,
            selection_reasons,
            provenance,
        }
    }

    /// Number of referenced graph nodes (boundedness metric).
    pub fn node_count(&self) -> usize {
        self.referenced_node_ids.len()
    }

    /// Number of referenced protocols.
    pub fn protocol_count(&self) -> usize {
        self.referenced_protocol_ids.len()
    }

    /// Selection reasons for a specific matched protocol.
    pub fn reasons_for(&self, protocol_id: &str) -> Vec<&SelectionReason> {
        self.selection_reasons
            .iter()
            .filter(|r| r.matched_protocol_id == protocol_id)
            .collect()
    }
}

/// Deterministically assemble a [`ResearchContext`] from the current
/// ProtocolModel, InvestigationPlan, and ResearchGraph.
///
/// This is the main public entry point. Selection is equality-only, bounded,
/// and deterministic.
pub fn assemble_research_context(
    model: &::digger_protocol_model::model::ProtocolModel,
    plan: &::digger_investigation::InvestigationPlan,
    graph: &::digger_research_graph::graph::ResearchGraph,
) -> ResearchContext {
    let (selected_protocols, selected_investigations, selected_nodes, reasons) =
        crate::selection::select_related(model, plan, graph);

    ResearchContext::new(
        model.id.clone(),
        plan.id.clone(),
        selected_protocols,
        selected_investigations,
        selected_nodes,
        reasons,
    )
}

impl RecoveredFact for ResearchContext {
    fn fact_id(&self) -> &str {
        &self.id
    }
    fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}
