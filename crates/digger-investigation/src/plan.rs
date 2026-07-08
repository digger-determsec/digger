//! InvestigationPlan -- the canonical, deterministic output of Phase A5. It is
//! an ordered set of [`InvestigationTarget`]s (rank 1 first) plus provenance
//! linking it to the source [`ProtocolModel`]. It contains NO findings, NO
//! hypotheses, and NO exploitability judgments. Implements `RecoveredFact`.

use serde::{Deserialize, Serialize};

use crate::target::{InvestigationTarget, TargetKind};
use crate::Provenance;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationPlan {
    /// Deterministic content-addressed id (`plan:<digest>`).
    pub id: String,
    /// The ProtocolModel this plan was derived from (related node linkage).
    pub protocol_model_id: String,
    /// Targets in deterministic priority order (rank 1 first).
    pub targets: Vec<InvestigationTarget>,
    pub provenance: Provenance,
}

impl InvestigationPlan {
    /// The target for `kind`, if the plan recovered one.
    pub fn target(&self, kind: TargetKind) -> Option<&InvestigationTarget> {
        self.targets.iter().find(|t| t.kind == kind)
    }

    /// Targets in rank order (already sorted; provided for call-site clarity).
    pub fn ordered_targets(&self) -> &[InvestigationTarget] {
        &self.targets
    }

    /// The highest-priority (rank 1) target, if any.
    pub fn first_target(&self) -> Option<&InvestigationTarget> {
        self.targets.first()
    }
}

impl_investigation_fact!(InvestigationPlan);
