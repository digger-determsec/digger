use super::auth_boundary::AuthorityBoundaryGraph;
use super::cross_program::CrossProgramGraph;
use super::execution::ExecutionGraph;
use super::state_dep::StateDependencyGraph;
/// Vulnerability path derivation — deterministic graph traversal.
///
/// Generates structured paths:
///   entry → call chain → state mutation → unsafe condition
///
/// Path types:
/// - Reentrancy: external call → state mutation → internal call
/// - Unauthorized modification: public → state write → no authority
/// - CPI trust violation: CPI call → no authority → state mutation
///
/// All paths are derived purely from existing IR edges.
/// No AI reasoning is used. No textual explanations are generated.
/// Only structured graph paths.
use digger_ir::{Edge, SystemIR};

/// A vulnerability path — a structured sequence of graph events.
///
/// This is a READ-ONLY analysis result — it does not modify SystemIR.
#[derive(Debug, Clone)]
pub struct VulnerabilityPath {
    /// Path type identifier.
    pub path_type: VulnerabilityPathType,
    /// The function where the vulnerability originates.
    pub entry_function: String,
    /// Ordered sequence of events in the path.
    pub events: Vec<PathEvent>,
    /// Severity classification.
    pub severity: PathSeverity,
}

/// Type of vulnerability path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulnerabilityPathType {
    /// External call before state update (reentrancy pattern).
    Reentrancy,
    /// Public function writes state without authority.
    UnauthorizedModification,
    /// CPI call without authority check.
    CpiTrustViolation,
    /// State mutation with missing authority on public function.
    MissingAuthority,
    /// External call without authority on public function.
    UntrustedExternal,
}

/// A single event in a vulnerability path.
#[derive(Debug, Clone)]
pub struct PathEvent {
    /// The function involved.
    pub function: String,
    /// What kind of event this is.
    pub event_type: PathEventType,
    /// Relevant details (state variable name, target name, etc.).
    pub detail: String,
}

/// Type of event in a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEventType {
    /// Function is called (entry point).
    EntryPoint,
    /// Function calls another function.
    InternalCall,
    /// Function makes an external call.
    ExternalCall,
    /// Function makes a CPI call.
    CpiCall,
    /// Function writes state.
    StateWrite,
    /// Function reads state.
    StateRead,
    /// Authority check present.
    AuthorityCheck,
    /// Authority check missing.
    MissingAuthority,
}

/// Severity classification for a path.
/// Path severity — re-exported from digger_ir for consistency.
pub use digger_ir::Severity as PathSeverity;

/// Vulnerability path analysis result.
#[derive(Debug, Clone)]
pub struct VulnerabilityPathAnalysis {
    /// All detected vulnerability paths.
    pub paths: Vec<VulnerabilityPath>,
    /// Reentrancy paths.
    pub reentrancy_paths: Vec<VulnerabilityPath>,
    /// Unauthorized modification paths.
    pub unauthorized_paths: Vec<VulnerabilityPath>,
    /// CPI trust violation paths.
    pub cpi_paths: Vec<VulnerabilityPath>,
}

impl VulnerabilityPathAnalysis {
    /// Derive vulnerability paths from SystemIR.
    ///
    /// This is the ONLY entry point. It combines all graph analyses
    /// to produce deterministic vulnerability paths.
    pub fn derive(ir: &SystemIR) -> Self {
        let exec = ExecutionGraph::build(ir);
        let state_dep = StateDependencyGraph::build(ir);
        let auth = AuthorityBoundaryGraph::build(ir);
        let cross = CrossProgramGraph::build(ir);

        let mut paths = vec![];

        // 1. Reentrancy paths: external call → state mutation
        paths.extend(derive_reentrancy_paths(ir, &exec, &state_dep, &cross));

        // 2. Unauthorized modification paths: public → state write → no authority
        paths.extend(derive_unauthorized_paths(ir, &auth, &state_dep));

        // 3. CPI trust violation paths: CPI → no authority → state mutation
        paths.extend(derive_cpi_paths(ir, &cross, &auth, &state_dep));

        // Categorize
        let reentrancy_paths: Vec<_> = paths
            .iter()
            .filter(|p| p.path_type == VulnerabilityPathType::Reentrancy)
            .cloned()
            .collect();
        let unauthorized_paths: Vec<_> = paths
            .iter()
            .filter(|p| {
                p.path_type == VulnerabilityPathType::UnauthorizedModification
                    || p.path_type == VulnerabilityPathType::MissingAuthority
            })
            .cloned()
            .collect();
        let cpi_paths: Vec<_> = paths
            .iter()
            .filter(|p| p.path_type == VulnerabilityPathType::CpiTrustViolation)
            .cloned()
            .collect();

        VulnerabilityPathAnalysis {
            paths,
            reentrancy_paths,
            unauthorized_paths,
            cpi_paths,
        }
    }
}

/// Derive reentrancy-like paths:
/// function has external call AND writes state → potential reentrancy.
fn derive_reentrancy_paths(
    ir: &SystemIR,
    _exec: &ExecutionGraph,
    state_dep: &StateDependencyGraph,
    cross: &CrossProgramGraph,
) -> Vec<VulnerabilityPath> {
    let mut paths = vec![];

    for f in &ir.functions {
        let has_external = cross.external_calls.iter().any(|e| e.function == f.name);
        let writes = state_dep.states_written_by(&f.name);
        let has_authority = ir.edges.iter().any(|e| {
            matches!(e, Edge::Authority(a) if a.function == f.name && a.check_type == "enforced")
        });

        if has_external && !writes.is_empty() {
            let severity = if has_authority {
                PathSeverity::Medium
            } else {
                PathSeverity::Critical
            };

            let mut events = vec![PathEvent {
                function: f.name.clone(),
                event_type: PathEventType::EntryPoint,
                detail: "function entry".into(),
            }];

            // External call event
            if let Some(ext) = cross.external_calls.iter().find(|e| e.function == f.name) {
                events.push(PathEvent {
                    function: f.name.clone(),
                    event_type: PathEventType::ExternalCall,
                    detail: ext.target.clone(),
                });
            }

            // State write events
            for state_var in &writes {
                events.push(PathEvent {
                    function: f.name.clone(),
                    event_type: PathEventType::StateWrite,
                    detail: state_var.clone(),
                });
            }

            // Authority event
            events.push(PathEvent {
                function: f.name.clone(),
                event_type: if has_authority {
                    PathEventType::AuthorityCheck
                } else {
                    PathEventType::MissingAuthority
                },
                detail: if has_authority { "enforced" } else { "missing" }.into(),
            });

            paths.push(VulnerabilityPath {
                path_type: VulnerabilityPathType::Reentrancy,
                entry_function: f.name.clone(),
                events,
                severity,
            });
        }
    }

    paths
}

/// Derive unauthorized modification paths:
/// public function writes state without authority check.
fn derive_unauthorized_paths(
    _ir: &SystemIR,
    auth: &AuthorityBoundaryGraph,
    _state_dep: &StateDependencyGraph,
) -> Vec<VulnerabilityPath> {
    let mut paths = vec![];

    for unguarded in &auth.unguarded_mutations {
        if unguarded.is_public {
            let mut events = vec![PathEvent {
                function: unguarded.function.clone(),
                event_type: PathEventType::EntryPoint,
                detail: "public entry".into(),
            }];

            for state_var in &unguarded.state_vars {
                events.push(PathEvent {
                    function: unguarded.function.clone(),
                    event_type: PathEventType::StateWrite,
                    detail: state_var.clone(),
                });
            }

            events.push(PathEvent {
                function: unguarded.function.clone(),
                event_type: PathEventType::MissingAuthority,
                detail: "no authority check on public mutation".into(),
            });

            paths.push(VulnerabilityPath {
                path_type: VulnerabilityPathType::UnauthorizedModification,
                entry_function: unguarded.function.clone(),
                events,
                severity: PathSeverity::Critical,
            });
        }
    }

    paths
}

/// Derive CPI trust violation paths:
/// function makes CPI call without authority, and writes state.
fn derive_cpi_paths(
    _ir: &SystemIR,
    cross: &CrossProgramGraph,
    auth: &AuthorityBoundaryGraph,
    state_dep: &StateDependencyGraph,
) -> Vec<VulnerabilityPath> {
    let mut paths = vec![];

    for cpi_call in &cross.cpi_calls {
        let fn_name = &cpi_call.function;
        let is_enforced = auth.is_enforced(fn_name);
        let writes = state_dep.states_written_by(fn_name);

        if !is_enforced {
            let mut events = vec![
                PathEvent {
                    function: fn_name.clone(),
                    event_type: PathEventType::EntryPoint,
                    detail: "CPI entry".into(),
                },
                PathEvent {
                    function: fn_name.clone(),
                    event_type: PathEventType::CpiCall,
                    detail: cpi_call.target.clone(),
                },
            ];

            for state_var in &writes {
                events.push(PathEvent {
                    function: fn_name.clone(),
                    event_type: PathEventType::StateWrite,
                    detail: state_var.clone(),
                });
            }

            events.push(PathEvent {
                function: fn_name.clone(),
                event_type: PathEventType::MissingAuthority,
                detail: "CPI without authority".into(),
            });

            paths.push(VulnerabilityPath {
                path_type: VulnerabilityPathType::CpiTrustViolation,
                entry_function: fn_name.clone(),
                events,
                severity: PathSeverity::High,
            });
        }
    }

    paths
}
