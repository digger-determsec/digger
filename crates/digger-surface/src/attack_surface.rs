use digger_graph::analysis::{
    AuthorityBoundaryGraph, CrossProgramGraph, ExecutionGraph, StateDependencyGraph,
};
/// Attack Surface Representation Layer
///
/// Aggregates existing graph outputs into a structured attack surface view.
/// Does NOT compute new analysis — only organizes existing results.
use digger_ir::SystemIR;
use serde::{Deserialize, Serialize};

/// Structured attack surface derived from graph analysis.
///
/// This is a READ-ONLY aggregation — it does not modify SystemIR.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackSurface {
    /// Entry points: externally callable functions.
    pub entry_points: Vec<EntryPoint>,
    /// State mutation zones: functions that write state.
    pub state_mutations: Vec<StateMutationZone>,
    /// External interaction zones: calls / CPI / external calls.
    pub external_interactions: Vec<ExternalInteractionZone>,
    /// Authority-sensitive regions.
    pub authority_regions: Vec<AuthorityRegion>,
    /// Summary statistics.
    pub summary: AttackSurfaceSummary,
}

/// An entry point — externally callable function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntryPoint {
    /// Function name.
    pub function: String,
    /// Visibility (public, external, etc.).
    pub visibility: String,
    /// Whether this entry point has authority enforcement.
    pub has_authority: bool,
    /// Whether this entry point writes state.
    pub writes_state: bool,
    /// Whether this entry point makes external calls.
    pub makes_external_calls: bool,
}

/// A state mutation zone — function that writes state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateMutationZone {
    /// Function name.
    pub function: String,
    /// State variables written.
    pub state_vars: Vec<String>,
    /// Whether this zone has authority enforcement.
    pub has_authority: bool,
    /// Whether this zone is publicly accessible.
    pub is_public: bool,
}

/// An external interaction zone — function that calls outside.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalInteractionZone {
    /// Function name.
    pub function: String,
    /// External targets.
    pub targets: Vec<String>,
    /// Whether this is a CPI call.
    pub is_cpi: bool,
    /// Whether this is a signed CPI call.
    pub is_signed: bool,
    /// Whether this zone has authority enforcement.
    pub has_authority: bool,
}

/// An authority-sensitive region.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityRegion {
    /// Function name.
    pub function: String,
    /// Authority source (signer, pda, msg_sender, unknown).
    pub source: String,
    /// Whether authority is enforced.
    pub enforced: bool,
    /// What this function does that requires authority.
    pub sensitive_actions: Vec<String>,
}

/// Summary statistics for the attack surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackSurfaceSummary {
    /// Total entry points.
    pub total_entry_points: usize,
    /// Entry points without authority.
    pub unguarded_entry_points: usize,
    /// Total state mutation zones.
    pub total_mutation_zones: usize,
    /// Mutation zones without authority.
    pub unguarded_mutation_zones: usize,
    /// Total external interaction zones.
    pub total_external_zones: usize,
    /// External zones without authority.
    pub unguarded_external_zones: usize,
    /// Authority enforcement rate (0.0 to 1.0).
    pub enforcement_rate: f64,
}

impl AttackSurface {
    /// Build an attack surface from SystemIR.
    ///
    /// This is the ONLY entry point. It aggregates existing graph outputs.
    pub fn build(ir: &SystemIR) -> Self {
        let exec = ExecutionGraph::build(ir);
        let state_dep = StateDependencyGraph::build(ir);
        let auth = AuthorityBoundaryGraph::build(ir);
        let cross = CrossProgramGraph::build(ir);

        // Build entry points
        let entry_points: Vec<EntryPoint> = exec
            .entry_points
            .iter()
            .map(|name| {
                let has_authority = auth.is_enforced(name);
                let writes_state = !state_dep.states_written_by(name).is_empty();
                let makes_external_calls = cross.external_callers.contains(name);

                EntryPoint {
                    function: name.clone(),
                    visibility: "public".into(), // entry points are public by definition
                    has_authority,
                    writes_state,
                    makes_external_calls,
                }
            })
            .collect();

        // Build state mutation zones (sorted for deterministic output)
        let mut state_mutations = vec![];
        for (state_var, writers) in &state_dep.writers {
            for writer in writers {
                let has_authority = auth.is_enforced(writer);
                let is_public = exec.entry_points.contains(writer);

                state_mutations.push(StateMutationZone {
                    function: writer.clone(),
                    state_vars: vec![state_var.clone()],
                    has_authority,
                    is_public,
                });
            }
        }
        state_mutations.sort_by(|a, b| a.function.cmp(&b.function));

        // Build external interaction zones (sorted for deterministic output)
        let mut external_interactions = vec![];
        for call in &cross.external_calls {
            let has_authority = auth.is_enforced(&call.function);
            let is_cpi = call.risk_flags.contains(&"cpi".to_string());
            let is_signed = call.risk_flags.contains(&"signed".to_string());

            external_interactions.push(ExternalInteractionZone {
                function: call.function.clone(),
                targets: vec![call.target.clone()],
                is_cpi,
                is_signed,
                has_authority,
            });
        }
        external_interactions.sort_by(|a, b| a.function.cmp(&b.function));

        // Build authority regions
        let authority_regions: Vec<AuthorityRegion> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let digger_ir::Edge::Authority(a) = e {
                    let sensitive_actions: Vec<String> = state_dep.states_written_by(&a.function);
                    Some(AuthorityRegion {
                        function: a.function.clone(),
                        source: a.authority_source.clone(),
                        enforced: a.check_type == "enforced",
                        sensitive_actions,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Build summary
        let unguarded_entry_points = entry_points.iter().filter(|ep| !ep.has_authority).count();
        let unguarded_mutation_zones = state_mutations.iter().filter(|z| !z.has_authority).count();
        let unguarded_external_zones = external_interactions
            .iter()
            .filter(|z| !z.has_authority)
            .count();
        let total_auth = authority_regions.len();
        let enforced_auth = authority_regions.iter().filter(|r| r.enforced).count();
        let enforcement_rate = if total_auth > 0 {
            enforced_auth as f64 / total_auth as f64
        } else {
            0.0
        };

        AttackSurface {
            entry_points,
            state_mutations,
            external_interactions,
            authority_regions,
            summary: AttackSurfaceSummary {
                total_entry_points: exec.entry_points.len(),
                unguarded_entry_points,
                total_mutation_zones: state_dep.writers.len(),
                unguarded_mutation_zones,
                total_external_zones: cross.external_callers.len(),
                unguarded_external_zones,
                enforcement_rate,
            },
        }
    }
}
