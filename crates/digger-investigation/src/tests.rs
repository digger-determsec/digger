//! Deterministic unit tests for the investigation planner. These run under
//! `cargo test` in CI (no toolchain in the build sandbox).

use super::*;
use crate::priority::PriorityKey;
use crate::scope::{ScopeBand, FOCUSED_MAX, MODERATE_MAX};
use crate::target::{FactorInputs, TargetKind};
use ::digger_protocol_model::model::{ProtocolModel, ProtocolModelInput};

#[allow(clippy::too_many_arguments)]
fn key(c: u32, p: u32, a: u32, t: u32, e: u32, u: u32, x: u32, s: u32) -> PriorityKey {
    PriorityKey {
        capability_concentration: c,
        permission_concentration: p,
        asset_concentration: a,
        trust_boundary_density: t,
        external_dependency_count: e,
        upgrade_complexity: u,
        cross_contract_interaction_density: x,
        state_machine_complexity: s,
    }
}

#[test]
fn priority_key_is_lexicographic_by_significance() {
    // capability concentration is the most significant field: a single extra
    // capability outranks any number of less-significant counts.
    let high_caps = key(2, 0, 0, 0, 0, 0, 0, 0);
    let many_low = key(1, 9, 9, 9, 9, 9, 9, 9);
    assert!(high_caps > many_low);
    // ties on capability fall through to permission concentration, etc.
    let a = key(1, 2, 0, 0, 0, 0, 0, 0);
    let b = key(1, 1, 9, 0, 0, 0, 0, 0);
    assert!(a > b);
}

#[test]
fn empty_key_is_empty() {
    assert!(key(0, 0, 0, 0, 0, 0, 0, 0).is_empty());
    assert!(!key(0, 0, 0, 0, 0, 0, 0, 1).is_empty());
}

#[test]
fn scope_band_thresholds_are_fixed() {
    assert_eq!(ScopeBand::from_related_count(0), ScopeBand::Focused);
    assert_eq!(
        ScopeBand::from_related_count(FOCUSED_MAX),
        ScopeBand::Focused
    );
    assert_eq!(
        ScopeBand::from_related_count(FOCUSED_MAX + 1),
        ScopeBand::Moderate
    );
    assert_eq!(
        ScopeBand::from_related_count(MODERATE_MAX),
        ScopeBand::Moderate
    );
    assert_eq!(
        ScopeBand::from_related_count(MODERATE_MAX + 1),
        ScopeBand::Broad
    );
}

#[test]
fn factor_inputs_only_emit_nonzero_factors() {
    let inputs = FactorInputs {
        capability: vec!["cap:1".into(), "cap:2".into()],
        permission: vec![],
        ..Default::default()
    };
    let factors = inputs.factors();
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].count, 2);
    // key still records the integer counts, including the zeros.
    let k = inputs.key();
    assert_eq!(k.capability_concentration, 2);
    assert_eq!(k.permission_concentration, 0);
}

#[test]
fn factor_inputs_support_is_sorted_and_deduped() {
    let inputs = FactorInputs {
        capability: vec!["cap:b".into(), "cap:a".into(), "cap:b".into()],
        related_extra: vec!["surf:z".into()],
        ..Default::default()
    };
    let support = inputs.support();
    assert_eq!(
        support.capability_fact_ids,
        vec!["cap:a".to_string(), "cap:b".to_string()]
    );
    // related includes capabilities + extras, sorted + deduped.
    assert_eq!(
        support.related_node_ids,
        vec![
            "cap:a".to_string(),
            "cap:b".to_string(),
            "surf:z".to_string()
        ]
    );
}

#[test]
fn empty_protocol_model_yields_no_targets() {
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let pm = ProtocolModel::build(&input);
    let plan = build_investigation_plan(&pm);
    assert!(plan.targets.is_empty());
    assert_eq!(plan.protocol_model_id, pm.id);
}

#[test]
fn plan_is_deterministic() {
    let input = ProtocolModelInput {
        deployment: None,
        dependencies: &[],
        interface: None,
    };
    let pm = ProtocolModel::build(&input);
    let a = build_investigation_plan(&pm);
    let b = build_investigation_plan(&pm);
    assert_eq!(a.id, b.id);
    assert_eq!(a, b);
}

#[test]
fn target_implements_recovered_fact() {
    // RecoveredFact is the reconstruction trait; confirm an investigation
    // target exposes id + provenance through it.
    use ::digger_reconstruct::fact::RecoveredFact;
    let inputs = FactorInputs {
        capability: vec!["cap:1".into()],
        ..Default::default()
    };
    let t = crate::target::InvestigationTarget::from_inputs(TargetKind::UpgradeSubsystem, &inputs);
    assert_eq!(t.fact_id(), t.id);
    assert!(!t.provenance().id.is_empty());
}
