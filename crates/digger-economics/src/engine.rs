use crate::models::*;
/// Economic Semantics Engine — behavioral economic constraint inference.
///
/// Derives economic relationships from behavioral patterns in state transitions,
/// resource lifecycles, execution ordering, and temporal dependencies.
///
/// All inference is behavioral — no naming heuristics.
/// Deterministic: same inputs → same output.
use digger_parser::model::*;
use digger_resource_lifecycle::*;
use digger_state_transitions::*;
use digger_temporal::*;

/// Maximum relations per protocol.
const MAX_RELATIONS: usize = 100;

/// Analyze economic semantics for a program.
pub fn analyze_economics(
    program: &RawProgram,
    transitions: &StateTransitionReport,
    lifecycles: &ResourceLifecycleReport,
    temporal: &TemporalReport,
    protocol_id: &str,
) -> EconomicReport {
    let mut relations = Vec::new();

    // 1. Conservation relations
    let conservation = detect_conservation(program, transitions);
    relations.extend(conservation.into_iter().map(|c| {
        EconomicRelation {
            relation_id: format!("conservation:{}", c.conserved_var),
            kind: EconomicRelationKind::Conservation(c.clone()),
            state_vars: vec![c.conserved_var.clone()],
            functions: c
                .inflow_functions
                .iter()
                .chain(c.outflow_functions.iter())
                .cloned()
                .collect(),
            evidence: vec![format!(
                "Variable '{}' is incremented by inflows and decremented by outflows",
                c.conserved_var
            )],
            is_satisfied: true,
        }
    }));

    // 2. Collateral relations
    let collateral = detect_collateral(program, transitions, lifecycles);
    relations.extend(collateral.into_iter().map(|c| EconomicRelation {
        relation_id: format!("collateral:{}:{}", c.collateral_var, c.constrained_var),
        kind: EconomicRelationKind::Collateral(c.clone()),
        state_vars: vec![c.collateral_var.clone(), c.constrained_var.clone()],
        functions: c.enforcing_functions.clone(),
        evidence: vec![format!(
            "Variable '{}' constrains '{}'",
            c.collateral_var, c.constrained_var
        )],
        is_satisfied: true,
    }));

    // 3. Debt relations
    let debt = detect_debt(program, transitions, lifecycles);
    relations.extend(debt.into_iter().map(|d| {
        EconomicRelation {
            relation_id: format!("debt:{}", d.debt_var),
            kind: EconomicRelationKind::Debt(d.clone()),
            state_vars: vec![d.debt_var.clone()],
            functions: d
                .borrowing_functions
                .iter()
                .chain(d.repayment_functions.iter())
                .cloned()
                .collect(),
            evidence: vec![format!(
                "Variable '{}' is created by borrowing and reduced by repayment",
                d.debt_var
            )],
            is_satisfied: true,
        }
    }));

    // 4. Dependency relations
    let dependencies = detect_dependencies(program, transitions, temporal);
    relations.extend(dependencies.into_iter().map(|d| EconomicRelation {
        relation_id: format!("dependency:{}:{}", d.influencer, d.influenced),
        kind: EconomicRelationKind::Dependency(d.clone()),
        state_vars: vec![d.influencer.clone(), d.influenced.clone()],
        functions: d.functions.clone(),
        evidence: vec![format!(
            "Variable '{}' influences '{}'",
            d.influencer, d.influenced
        )],
        is_satisfied: true,
    }));

    // Sort for deterministic output
    relations.sort_by(|a, b| a.relation_id.cmp(&b.relation_id));

    // Bound
    relations.truncate(MAX_RELATIONS);

    // Generate invariants from relations
    let invariants = generate_invariants(&relations, program);

    // Build summary
    let summary = build_summary(&relations, &invariants);

    EconomicReport {
        protocol_id: protocol_id.into(),
        relations,
        invariants,
        summary,
    }
}

/// Detect conservation relations.
///
/// A conservation relation exists when a state variable is incremented by
/// some functions and decremented by others.
fn detect_conservation(
    _program: &RawProgram,
    transitions: &StateTransitionReport,
) -> Vec<ConservationRelation> {
    let mut rules = Vec::new();

    // Group transitions by state variable
    let mut var_transitions: std::collections::BTreeMap<String, Vec<&StateTransition>> =
        std::collections::BTreeMap::new();
    for t in &transitions.transitions {
        var_transitions
            .entry(t.state_var.clone())
            .or_default()
            .push(t);
    }

    for (var, trans) in &var_transitions {
        // Collect all functions that write this variable
        let writers: Vec<String> = trans
            .iter()
            .filter(|t| {
                matches!(
                    t.kind,
                    TransitionKind::Assignment
                        | TransitionKind::Increment
                        | TransitionKind::Decrement
                        | TransitionKind::Compound
                )
            })
            .map(|t| t.function.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        // If 2+ functions write the same variable, it's a conservation candidate
        // Behavioral: multiple writers to same variable = conserved quantity
        if writers.len() >= 2 {
            // Split: functions that also read before writing (inflow)
            // vs functions that only write (outflow)
            let inflow: Vec<String> = trans
                .iter()
                .filter(|t| t.read_before_write && writers.contains(&t.function))
                .map(|t| t.function.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();

            // If no function reads before writing, treat all as inflow
            // (conservation is inferred from multiple writers alone)
            let (inflow_fns, outflow_fns) = if inflow.is_empty() {
                (writers.clone(), writers)
            } else {
                let outflow: Vec<String> = writers
                    .iter()
                    .filter(|w| !inflow.contains(w))
                    .cloned()
                    .collect();
                (inflow, outflow)
            };

            rules.push(ConservationRelation {
                conserved_var: var.clone(),
                inflow_functions: inflow_fns,
                outflow_functions: outflow_fns,
            });
        }
    }

    rules.sort_by(|a, b| a.conserved_var.cmp(&b.conserved_var));
    rules
}

/// Detect collateral relations.
///
/// A collateral relation exists when a function reads two state variables
/// and enforces a relationship between them (e.g., collateral >= debt * factor).
///
/// Inferred from: function tracks multiple state variables via lifecycle,
/// writes to one, and has authority — behavioral pattern, not naming.
fn detect_collateral(
    _program: &RawProgram,
    transitions: &StateTransitionReport,
    lifecycles: &ResourceLifecycleReport,
) -> Vec<CollateralRelation> {
    let mut relations = Vec::new();

    // Group transitions by function
    let mut func_transitions: std::collections::BTreeMap<String, Vec<&StateTransition>> =
        std::collections::BTreeMap::new();
    for t in &transitions.transitions {
        func_transitions
            .entry(t.function.clone())
            .or_default()
            .push(t);
    }

    // Group lifecycle tracking vars by function
    let mut func_tracking: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for lc in &lifecycles.lifecycles {
        func_tracking.insert(lc.function.clone(), lc.tracking_vars.clone());
    }

    // For each function that writes state and has a lifecycle tracking multiple vars,
    // infer collateral relationship
    for (func, trans) in &func_transitions {
        let writes: Vec<String> = trans
            .iter()
            .filter(|t| {
                matches!(
                    t.kind,
                    TransitionKind::Assignment
                        | TransitionKind::Increment
                        | TransitionKind::Decrement
                        | TransitionKind::Compound
                )
            })
            .map(|t| t.state_var.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        if writes.is_empty() {
            continue;
        }

        // Get tracked vars from lifecycle
        if let Some(tracked) = func_tracking.get(func) {
            // If function tracks 2+ vars and writes to at least one,
            // the tracked-but-not-written vars are potential collateral
            let tracked_set: std::collections::BTreeSet<&String> = tracked.iter().collect();
            let writes_set: std::collections::BTreeSet<&String> = writes.iter().collect();

            let reads_not_written: Vec<String> = tracked_set
                .iter()
                .filter(|v| !writes_set.contains(**v))
                .map(|v| (*v).clone())
                .collect();

            if !reads_not_written.is_empty() && !writes.is_empty() {
                for read_var in &reads_not_written {
                    for write_var in &writes {
                        if read_var != write_var {
                            relations.push(CollateralRelation {
                                collateral_var: read_var.clone(),
                                constrained_var: write_var.clone(),
                                enforcing_functions: vec![func.clone()],
                            });
                        }
                    }
                }
            }
        }
    }

    relations.sort_by(|a, b| a.collateral_var.cmp(&b.collateral_var));
    relations.dedup_by(|a, b| {
        a.collateral_var == b.collateral_var && a.constrained_var == b.constrained_var
    });
    relations
}

/// Detect debt relations.
///
/// A debt relation exists when a state variable is increased by some functions
/// (borrowing) and decreased by others (repayment), with corresponding asset flows.
fn detect_debt(
    _program: &RawProgram,
    transitions: &StateTransitionReport,
    lifecycles: &ResourceLifecycleReport,
) -> Vec<DebtRelation> {
    let mut relations = Vec::new();

    // Group transitions by state variable
    let mut var_transitions: std::collections::BTreeMap<String, Vec<&StateTransition>> =
        std::collections::BTreeMap::new();
    for t in &transitions.transitions {
        var_transitions
            .entry(t.state_var.clone())
            .or_default()
            .push(t);
    }

    for (var, trans) in &var_transitions {
        // Collect all functions that write this variable
        let writers: Vec<String> = trans
            .iter()
            .filter(|t| {
                matches!(
                    t.kind,
                    TransitionKind::Assignment
                        | TransitionKind::Increment
                        | TransitionKind::Decrement
                        | TransitionKind::Compound
                )
            })
            .map(|t| t.function.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        if writers.len() >= 2 {
            // Check if any lifecycle has egress (asset leaving) — indicates debt pattern
            let has_egress = lifecycles
                .lifecycles
                .iter()
                .any(|l| l.phases.iter().any(|p| p.kind == PhaseKind::Egress));

            if has_egress {
                // Split: functions that read before write (borrowing)
                // vs functions that only write (repayment)
                let borrowers: Vec<String> = trans
                    .iter()
                    .filter(|t| t.read_before_write && writers.contains(&t.function))
                    .map(|t| t.function.clone())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();

                let repayments: Vec<String> = writers
                    .iter()
                    .filter(|w| !borrowers.contains(w))
                    .cloned()
                    .collect();

                if !borrowers.is_empty() && !repayments.is_empty() {
                    relations.push(DebtRelation {
                        debt_var: var.clone(),
                        borrowing_functions: borrowers,
                        repayment_functions: repayments,
                    });
                }
            }
        }
    }

    relations.sort_by(|a, b| a.debt_var.cmp(&b.debt_var));
    relations
}

/// Detect dependency relations.
///
/// A dependency relation exists when one state variable's value constrains
/// or influences another variable's valid range, without implying ownership or obligation.
fn detect_dependencies(
    _program: &RawProgram,
    transitions: &StateTransitionReport,
    temporal: &TemporalReport,
) -> Vec<DependencyRelation> {
    let mut relations = Vec::new();

    // Find functions that read multiple state variables
    let mut func_reads: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for t in &transitions.transitions {
        if t.read_before_write {
            func_reads
                .entry(t.function.clone())
                .or_default()
                .push(t.state_var.clone());
        }
    }

    // If a function reads V1 and V2, V1 may influence V2
    for (func, vars) in &func_reads {
        let unique_vars: std::collections::BTreeSet<&String> = vars.iter().collect();
        if unique_vars.len() >= 2 {
            let var_vec: Vec<&String> = unique_vars.into_iter().collect();
            for i in 0..var_vec.len() {
                for j in (i + 1)..var_vec.len() {
                    relations.push(DependencyRelation {
                        influencer: var_vec[i].clone(),
                        influenced: var_vec[j].clone(),
                        functions: vec![func.clone()],
                        is_directional: true,
                    });
                }
            }
        }
    }

    // Also check temporal dependencies for cross-function influence
    for dep in &temporal.dependencies {
        if !relations
            .iter()
            .any(|r| r.influencer == dep.predecessor && r.influenced == dep.successor)
        {
            relations.push(DependencyRelation {
                influencer: dep.predecessor.clone(),
                influenced: dep.successor.clone(),
                functions: vec![dep.predecessor.clone(), dep.successor.clone()],
                is_directional: true,
            });
        }
    }

    relations.sort_by(|a, b| {
        a.influencer
            .cmp(&b.influencer)
            .then(a.influenced.cmp(&b.influenced))
    });
    relations.dedup_by(|a, b| a.influencer == b.influencer && a.influenced == b.influenced);
    relations
}

/// Generate economic invariants from discovered relations.
fn generate_invariants(
    relations: &[EconomicRelation],
    _program: &RawProgram,
) -> Vec<EconomicInvariant> {
    let mut invariants = Vec::new();

    for relation in relations {
        match &relation.kind {
            EconomicRelationKind::Conservation(c) => {
                invariants.push(EconomicInvariant {
                    invariant_id: format!("inv:conservation:{}", c.conserved_var),
                    state_vars: vec![c.conserved_var.clone()],
                    functions: c
                        .inflow_functions
                        .iter()
                        .chain(c.outflow_functions.iter())
                        .cloned()
                        .collect(),
                    kind: InvariantKind::Conservation,
                    is_satisfied: true,
                    evidence: vec![format!(
                        "Total '{}' is conserved across all operations",
                        c.conserved_var
                    )],
                });
            }
            EconomicRelationKind::Collateral(c) => {
                invariants.push(EconomicInvariant {
                    invariant_id: format!(
                        "inv:collateral:{}:{}",
                        c.collateral_var, c.constrained_var
                    ),
                    state_vars: vec![c.collateral_var.clone(), c.constrained_var.clone()],
                    functions: c.enforcing_functions.clone(),
                    kind: InvariantKind::Collateralization,
                    is_satisfied: true,
                    evidence: vec![format!(
                        "'{}' must be sufficient to cover '{}'",
                        c.collateral_var, c.constrained_var
                    )],
                });
            }
            EconomicRelationKind::Debt(d) => {
                invariants.push(EconomicInvariant {
                    invariant_id: format!("inv:solvency:{}", d.debt_var),
                    state_vars: vec![d.debt_var.clone()],
                    functions: d
                        .borrowing_functions
                        .iter()
                        .chain(d.repayment_functions.iter())
                        .cloned()
                        .collect(),
                    kind: InvariantKind::Solvency,
                    is_satisfied: true,
                    evidence: vec![format!("Debt '{}' must be fully backed", d.debt_var)],
                });
            }
            EconomicRelationKind::Dependency(_) => {
                // Dependencies don't directly generate invariants
                // They inform Phase 11 adversarial modeling
            }
        }
    }

    invariants.sort_by(|a, b| a.invariant_id.cmp(&b.invariant_id));
    invariants
}

/// Build summary statistics.
fn build_summary(
    relations: &[EconomicRelation],
    invariants: &[EconomicInvariant],
) -> EconomicSummary {
    EconomicSummary {
        total_relations: relations.len(),
        conservation_count: relations
            .iter()
            .filter(|r| matches!(r.kind, EconomicRelationKind::Conservation(_)))
            .count(),
        collateral_count: relations
            .iter()
            .filter(|r| matches!(r.kind, EconomicRelationKind::Collateral(_)))
            .count(),
        debt_count: relations
            .iter()
            .filter(|r| matches!(r.kind, EconomicRelationKind::Debt(_)))
            .count(),
        dependency_count: relations
            .iter()
            .filter(|r| matches!(r.kind, EconomicRelationKind::Dependency(_)))
            .count(),
        total_invariants: invariants.len(),
        satisfied_invariants: invariants.iter().filter(|i| i.is_satisfied).count(),
        violated_invariants: invariants.iter().filter(|i| !i.is_satisfied).count(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("JSON parse error: {0}")]
    Parse(String),
}

impl From<serde_json::Error> for AnalysisError {
    fn from(e: serde_json::Error) -> Self {
        AnalysisError::Parse(e.to_string())
    }
}

/// Serialize report to JSON.
pub fn report_to_json(report: &EconomicReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

/// Deserialize report from JSON.
pub fn report_from_json(json: &str) -> Result<EconomicReport, AnalysisError> {
    Ok(serde_json::from_str(json)?)
}
