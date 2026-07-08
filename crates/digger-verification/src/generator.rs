use crate::models::*;
use digger_execution::CEIViolation;
use digger_graph::analysis::*;
use digger_resource_lifecycle::*;
use digger_state_transitions::*;
/// Verification Property Generator — produces VerificationProperty from semantic models.
///
/// Reads from existing semantic models only. Never reads from source code or AST.
/// Deterministic: same inputs → same output.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Generate verification properties from semantic analysis results.
///
/// Consumes outputs from Generation 1 semantic models:
/// - AuthorityGraph (authority enforcement)
/// - StateTransitionReport (state evolution)
/// - ResourceLifecycleReport (resource movement)
/// - CEIViolation list (ordering violations)
pub fn generate_properties(
    authority: &AuthorityGraph,
    transitions: &StateTransitionReport,
    lifecycles: &ResourceLifecycleReport,
    cei_violations: &[CEIViolation],
    protocol_id: &str,
) -> VerificationReport {
    let mut properties = vec![];

    // 1. Authority invariants
    generate_authority_properties(authority, &mut properties);

    // 2. State transition ordering constraints
    generate_transition_properties(transitions, &mut properties);

    // 3. Resource lifecycle invariants
    generate_lifecycle_properties(lifecycles, &mut properties);

    // 4. CEI ordering constraints
    generate_cei_properties(cei_violations, &mut properties);

    // Sort for deterministic output
    properties.sort_by(|a, b| a.property_id.cmp(&b.property_id));

    let summary = build_summary(&properties);

    VerificationReport {
        protocol_id: protocol_id.into(),
        properties,
        summary,
    }
}

/// Generate authority invariant properties.
fn generate_authority_properties(
    authority: &AuthorityGraph,
    properties: &mut Vec<VerificationProperty>,
) {
    for relation in &authority.relations {
        if !relation.enforced && !relation.is_invariant {
            // Public function without authority
            properties.push(VerificationProperty {
                property_id: compute_property_id("authority", &relation.function, ""),
                kind: PropertyKind::AuthorityInvariant,
                origin: PropertyOrigin::AuthorityGraph,
                description: format!(
                    "Function '{}' must have enforced authority",
                    relation.function
                ),
                scope: vec![relation.function.clone()],
                state_vars: vec![],
                predicate: Predicate::Always(Box::new(Condition::HasAuthority {
                    function: relation.function.clone(),
                })),
                evidence: vec![EvidenceRef::Authority {
                    function: relation.function.clone(),
                    source: format!("{:?}", relation.source),
                }],
                severity: digger_ir::Severity::Critical,
            });
        }
    }
}

/// Generate state transition ordering properties.
fn generate_transition_properties(
    transitions: &StateTransitionReport,
    properties: &mut Vec<VerificationProperty>,
) {
    for transition in &transitions.transitions {
        if transition.external_between_read_write {
            // External call between read and write — ordering constraint
            properties.push(VerificationProperty {
                property_id: compute_property_id(
                    "transition",
                    &transition.function,
                    &transition.state_var,
                ),
                kind: PropertyKind::OrderingConstraint,
                origin: PropertyOrigin::StateTransition,
                description: format!(
                    "Function '{}': state write to '{}' must precede external call",
                    transition.function, transition.state_var
                ),
                scope: vec![transition.function.clone()],
                state_vars: vec![transition.state_var.clone()],
                predicate: Predicate::Before(
                    format!("StateWrite:{}", transition.state_var),
                    "ExternalCall".into(),
                ),
                evidence: vec![EvidenceRef::StateTransition {
                    function: transition.function.clone(),
                    state_var: transition.state_var.clone(),
                    kind: format!("{:?}", transition.kind),
                }],
                severity: digger_ir::Severity::High,
            });
        }

        if !transition.authority_before_transition {
            // State write without authority
            properties.push(VerificationProperty {
                property_id: compute_property_id(
                    "transition_auth",
                    &transition.function,
                    &transition.state_var,
                ),
                kind: PropertyKind::AccessControlRequirement,
                origin: PropertyOrigin::StateTransition,
                description: format!(
                    "Function '{}': state write to '{}' must have authority enforcement",
                    transition.function, transition.state_var
                ),
                scope: vec![transition.function.clone()],
                state_vars: vec![transition.state_var.clone()],
                predicate: Predicate::Always(Box::new(Condition::HasAuthority {
                    function: transition.function.clone(),
                })),
                evidence: vec![EvidenceRef::StateTransition {
                    function: transition.function.clone(),
                    state_var: transition.state_var.clone(),
                    kind: format!("{:?}", transition.kind),
                }],
                severity: digger_ir::Severity::High,
            });
        }
    }
}

/// Generate resource lifecycle properties.
fn generate_lifecycle_properties(
    lifecycles: &ResourceLifecycleReport,
    properties: &mut Vec<VerificationProperty>,
) {
    for lifecycle in &lifecycles.lifecycles {
        for anomaly in &lifecycle.anomalies {
            let (kind, predicate, severity) = match anomaly.kind {
                AnomalyKind::UnauthorizedEgress => (
                    PropertyKind::AccessControlRequirement,
                    Predicate::Always(Box::new(Condition::HasAuthority {
                        function: lifecycle.function.clone(),
                    })),
                    digger_ir::Severity::Critical,
                ),
                AnomalyKind::IngressWithoutAccounting => (
                    PropertyKind::AccountingInvariant,
                    Predicate::Always(Box::new(Condition::HasStateWrite {
                        function: lifecycle.function.clone(),
                        state_var: "*".into(),
                    })),
                    digger_ir::Severity::High,
                ),
                AnomalyKind::EgressWithoutAccountingDecrease => (
                    PropertyKind::AccountingInvariant,
                    Predicate::Always(Box::new(Condition::HasStateWrite {
                        function: lifecycle.function.clone(),
                        state_var: "*".into(),
                    })),
                    digger_ir::Severity::High,
                ),
                AnomalyKind::AccountingIntegrityRisk => (
                    PropertyKind::OrderingConstraint,
                    Predicate::Before("StateWrite".into(), "ExternalCall".into()),
                    digger_ir::Severity::High,
                ),
                AnomalyKind::UntrackedMovement => (
                    PropertyKind::AccountingInvariant,
                    Predicate::Always(Box::new(Condition::HasStateWrite {
                        function: lifecycle.function.clone(),
                        state_var: "*".into(),
                    })),
                    digger_ir::Severity::High,
                ),
            };

            properties.push(VerificationProperty {
                property_id: compute_property_id(
                    "lifecycle",
                    &lifecycle.function,
                    &anomaly.kind.to_string(),
                ),
                kind,
                origin: PropertyOrigin::ResourceLifecycle,
                description: anomaly.description.clone(),
                scope: vec![lifecycle.function.clone()],
                state_vars: lifecycle.tracking_vars.clone(),
                predicate,
                evidence: vec![EvidenceRef::LifecyclePhase {
                    function: lifecycle.function.clone(),
                    kind: format!("{:?}", anomaly.kind),
                    index: anomaly.operation_index,
                }],
                severity,
            });
        }
    }
}

/// Generate CEI ordering properties.
fn generate_cei_properties(
    cei_violations: &[CEIViolation],
    properties: &mut Vec<VerificationProperty>,
) {
    for violation in cei_violations {
        properties.push(VerificationProperty {
            property_id: compute_property_id(
                "cei",
                &violation.function_name,
                &violation.state_variable,
            ),
            kind: PropertyKind::OrderingConstraint,
            origin: PropertyOrigin::ExecutionOrdering,
            description: format!(
                "Function '{}': state write to '{}' must precede external call to '{}'",
                violation.function_name, violation.state_variable, violation.external_call_target
            ),
            scope: vec![violation.function_name.clone()],
            state_vars: vec![violation.state_variable.clone()],
            predicate: Predicate::Before(
                format!("StateWrite:{}", violation.state_variable),
                format!("ExternalCall:{}", violation.external_call_target),
            ),
            evidence: vec![EvidenceRef::Operation {
                function: violation.function_name.clone(),
                index: violation.external_call_index,
                kind: "ExternalCall".into(),
            }],
            severity: violation.severity.clone(),
        });
    }
}

/// Compute a deterministic property ID.
fn compute_property_id(prefix: &str, function: &str, extra: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(function.as_bytes());
    hasher.update(extra.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Build summary statistics.
fn build_summary(properties: &[VerificationProperty]) -> VerificationSummary {
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_origin: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();

    for prop in properties {
        *by_kind.entry(format!("{:?}", prop.kind)).or_default() += 1;
        *by_origin.entry(prop.origin.to_string()).or_default() += 1;
        *by_severity.entry(prop.severity.to_string()).or_default() += 1;
    }

    VerificationSummary {
        total_properties: properties.len(),
        by_kind,
        by_origin,
        by_severity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_execution::CEIViolation;

    fn empty_authority() -> AuthorityGraph {
        AuthorityGraph {
            relations: vec![],
            enforced_functions: vec![],
            missing_authority: vec![],
            invariant_only: vec![],
            propagation_chains: vec![],
            summary: AuthoritySummary {
                total_functions: 0,
                enforced_count: 0,
                missing_count: 0,
                invariant_count: 0,
                enforcement_rate: 0.0,
            },
        }
    }

    fn empty_transitions() -> StateTransitionReport {
        StateTransitionReport {
            protocol_id: "test".into(),
            transitions: vec![],
            missing_transitions: vec![],
            summary: StateTransitionSummary {
                total_transitions: 0,
                total_missing: 0,
                transitions_with_external_between: 0,
                transitions_without_authority: 0,
                functions_with_missing: 0,
            },
        }
    }

    fn empty_lifecycles() -> ResourceLifecycleReport {
        ResourceLifecycleReport {
            protocol_id: "test".into(),
            lifecycles: vec![],
            summary: LifecycleSummary {
                total_lifecycles: 0,
                total_anomalies: 0,
                functions_with_anomalies: 0,
                complete_lifecycles: 0,
                incomplete_lifecycles: 0,
            },
        }
    }

    #[test]
    fn generate_empty_inputs() {
        let report = generate_properties(
            &empty_authority(),
            &empty_transitions(),
            &empty_lifecycles(),
            &[],
            "test",
        );
        assert_eq!(report.properties.len(), 0);
        assert_eq!(report.summary.total_properties, 0);
    }

    #[test]
    fn generate_deterministic() {
        let r1 = generate_properties(
            &empty_authority(),
            &empty_transitions(),
            &empty_lifecycles(),
            &[],
            "test",
        );
        let r2 = generate_properties(
            &empty_authority(),
            &empty_transitions(),
            &empty_lifecycles(),
            &[],
            "test",
        );
        assert_eq!(r1, r2);
    }

    #[test]
    fn properties_sorted_by_id() {
        let cei = vec![CEIViolation {
            function_name: "withdraw".into(),
            external_call_index: 0,
            state_write_index: 1,
            external_call_target: "call".into(),
            state_variable: "balances".into(),
            severity: digger_ir::Severity::High,
        }];
        let report = generate_properties(
            &empty_authority(),
            &empty_transitions(),
            &empty_lifecycles(),
            &cei,
            "test",
        );
        for i in 1..report.properties.len() {
            assert!(report.properties[i - 1].property_id <= report.properties[i].property_id);
        }
    }

    #[test]
    fn cei_generates_ordering_property() {
        let cei = vec![CEIViolation {
            function_name: "withdraw".into(),
            external_call_index: 0,
            state_write_index: 1,
            external_call_target: "call".into(),
            state_variable: "balances".into(),
            severity: digger_ir::Severity::High,
        }];
        let report = generate_properties(
            &empty_authority(),
            &empty_transitions(),
            &empty_lifecycles(),
            &cei,
            "test",
        );
        assert_eq!(report.properties.len(), 1);
        assert_eq!(report.properties[0].kind, PropertyKind::OrderingConstraint);
        assert_eq!(
            report.properties[0].origin,
            PropertyOrigin::ExecutionOrdering
        );
    }

    #[test]
    fn summary_by_kind_origin_severity() {
        let cei = vec![CEIViolation {
            function_name: "withdraw".into(),
            external_call_index: 0,
            state_write_index: 1,
            external_call_target: "call".into(),
            state_variable: "balances".into(),
            severity: digger_ir::Severity::High,
        }];
        let report = generate_properties(
            &empty_authority(),
            &empty_transitions(),
            &empty_lifecycles(),
            &cei,
            "test",
        );
        assert_eq!(report.summary.total_properties, 1);
        assert!(!report.summary.by_kind.is_empty());
        assert!(!report.summary.by_origin.is_empty());
        assert!(!report.summary.by_severity.is_empty());
    }

    #[test]
    fn serialization_roundtrip() {
        let report = generate_properties(
            &empty_authority(),
            &empty_transitions(),
            &empty_lifecycles(),
            &[],
            "test",
        );
        let json = serde_json::to_string(&report).unwrap();
        let restored: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.protocol_id, "test");
        assert_eq!(restored.properties.len(), 0);
    }

    #[test]
    fn compute_property_id_deterministic() {
        let id1 = compute_property_id("prefix", "func", "extra");
        let id2 = compute_property_id("prefix", "func", "extra");
        assert_eq!(id1, id2);
    }

    #[test]
    fn compute_property_id_unique() {
        let id1 = compute_property_id("a", "b", "c");
        let id2 = compute_property_id("a", "b", "d");
        assert_ne!(id1, id2);
    }
}
