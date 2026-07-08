//! Architecture Fingerprints -- deterministic content digests over recovered
//! protocol structure. They enable architecture / dependency / capability /
//! upgrade / trust-model / state-machine SIMILARITY purely as EXACT EQUALITY of
//! deterministic digests. There is NO machine learning, NO embedding, and NO
//! probabilistic similarity anywhere: two protocols are "similar" on a facet iff
//! that facet's FNV-1a digest is identical.

use serde::{Deserialize, Serialize};

use crate::fact_impl::derive_provenance;
use crate::ids::{canon, digest_str, node_id, sorted_unique};
use crate::ProtocolModel;
use crate::Provenance;

/// A deterministic per-facet digest of a protocol's architecture. Each `*_fp`
/// field is an FNV-1a digest over the sorted, deduplicated set of recovered
/// structural labels for that facet, so equality of a facet means structural
/// similarity on that facet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchitectureFingerprint {
    /// Deterministic content-addressed id (`archfp:<digest>`).
    pub id: String,
    /// The ProtocolModel this fingerprint summarizes.
    pub protocol_id: String,
    /// Digest over the protocol's capability kinds.
    pub capability_fp: String,
    /// Digest over the protocol's dependency kinds.
    pub dependency_fp: String,
    /// Digest over the protocol's upgrade mechanisms + step count.
    pub upgrade_fp: String,
    /// Digest over the protocol's trust-boundary kinds.
    pub trust_fp: String,
    /// Digest over the protocol's state-machine kinds + transition counts.
    pub state_machine_fp: String,
    /// Digest over the protocol's invariant-candidate kinds (invariant family).
    pub invariant_fp: String,
    /// Digest over the five architecture facets (the overall architecture).
    pub composite_fp: String,
    /// Sorted, deduped capability kind labels (for deterministic `extends`).
    pub capability_labels: Vec<String>,
    /// Sorted, deduped dependency kind labels (deterministic, explainable).
    pub dependency_labels: Vec<String>,
    pub provenance: Provenance,
}

impl_graph_fact!(ArchitectureFingerprint);

/// FNV-1a digest over a facet's sorted, deduplicated label set.
fn facet(prefix: &str, items: Vec<String>) -> String {
    let v = sorted_unique(items);
    digest_str(&format!("{}|{}", prefix, v.join(",")))
}

/// Build the deterministic architecture fingerprint for a ProtocolModel.
pub fn derive_fingerprint(pm: &ProtocolModel) -> ArchitectureFingerprint {
    let capability_labels = sorted_unique(
        pm.capability_graph
            .capabilities
            .iter()
            .map(|c| format!("{:?}", c.kind))
            .collect(),
    );
    let dependency_labels = sorted_unique(
        pm.dependencies
            .iter()
            .map(|d| format!("{:?}", d.kind))
            .collect(),
    );

    let capability_fp = facet("capability", capability_labels.clone());
    let dependency_fp = facet("dependency", dependency_labels.clone());

    let total_steps: usize = pm.upgrade_paths.iter().map(|p| p.steps.len()).sum();
    let mut upgrade_items: Vec<String> = pm
        .upgrade_paths
        .iter()
        .flat_map(|p| p.steps.iter().map(|s| s.mechanism.clone()))
        .collect();
    upgrade_items.push(format!("steps={}", total_steps));
    let upgrade_fp = facet("upgrade", upgrade_items);

    let trust_fp = facet(
        "trust",
        pm.trust_boundaries
            .iter()
            .map(|b| format!("{:?}", b.kind))
            .collect(),
    );
    let state_machine_fp = facet(
        "state_machine",
        pm.state_machines
            .iter()
            .map(|m| format!("{:?}:{}", m.machine_kind, m.transitions.len()))
            .collect(),
    );
    let invariant_fp = facet(
        "invariant",
        pm.invariant_candidates
            .iter()
            .map(|i| format!("{:?}", i.kind))
            .collect(),
    );

    // The composite architecture is the five architecture facets (the invariant
    // family is tracked separately, for shares_invariant_family).
    let composite_fp = digest_str(&format!(
        "composite|{}|{}|{}|{}|{}",
        capability_fp, dependency_fp, upgrade_fp, trust_fp, state_machine_fp
    ));

    let id_canon = canon(&[&pm.id, &composite_fp]);
    let provenance = derive_provenance(&format!("archfp|{}", id_canon), &pm.id);

    ArchitectureFingerprint {
        id: node_id("archfp", &id_canon),
        protocol_id: pm.id.clone(),
        capability_fp,
        dependency_fp,
        upgrade_fp,
        trust_fp,
        state_machine_fp,
        invariant_fp,
        composite_fp,
        capability_labels,
        dependency_labels,
        provenance,
    }
}
