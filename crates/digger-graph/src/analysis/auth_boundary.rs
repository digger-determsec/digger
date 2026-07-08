/// Authority boundary graph analysis — derived from Authority edges.
///
/// Detects:
/// - Missing authorization checks on public functions
/// - Unsafe state mutation paths (write without authority)
/// - External trust assumptions (external call without authority)
/// - Authority enforcement gaps
///
/// All analysis is derived purely from existing Authority, State, and
/// External edges. No metadata is consumed.
use digger_ir::{AuthorityEdge, Edge, StateEdge, SystemIR};
use std::collections::{BTreeMap, BTreeSet};

/// Authority boundary analysis result.
///
/// This is a READ-ONLY analysis result — it does not modify SystemIR.
#[derive(Debug, Clone)]
pub struct AuthorityBoundaryGraph {
    /// Functions with enforced authority checks.
    pub enforced: Vec<String>,
    /// Functions missing authority checks.
    pub missing: Vec<String>,
    /// Authority source per function (signer, pda, msg_sender, unknown).
    pub sources: BTreeMap<String, String>,
    /// Public functions that mutate state without authority.
    pub unguarded_mutations: Vec<UnguardedPath>,
    /// Functions with external calls but no authority.
    pub unguarded_external: Vec<String>,
    /// Authority enforcement summary.
    pub enforcement_rate: f64,
}

/// An unguarded mutation path: function writes state without authority.
#[derive(Debug, Clone)]
pub struct UnguardedPath {
    /// The function name.
    pub function: String,
    /// State variables written without authority.
    pub state_vars: Vec<String>,
    /// Whether this function is publicly accessible.
    pub is_public: bool,
}

impl AuthorityBoundaryGraph {
    /// Build an authority boundary graph from SystemIR.
    pub fn build(ir: &SystemIR) -> Self {
        let auth_edges: Vec<AuthorityEdge> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let Edge::Authority(a) = e {
                    Some(a.clone())
                } else {
                    None
                }
            })
            .collect();

        let state_edges: Vec<StateEdge> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let Edge::State(s) = e {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect();

        let external_fns: BTreeSet<String> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let Edge::External(ext) = e {
                    Some(ext.function.clone())
                } else {
                    None
                }
            })
            .collect();

        // Build enforcement maps
        let enforced: Vec<String> = auth_edges
            .iter()
            .filter(|a| a.check_type == "enforced")
            .map(|a| a.function.clone())
            .collect();

        let missing: Vec<String> = auth_edges
            .iter()
            .filter(|a| a.check_type == "missing")
            .map(|a| a.function.clone())
            .collect();

        let sources: BTreeMap<String, String> = auth_edges
            .iter()
            .map(|a| (a.function.clone(), a.authority_source.clone()))
            .collect();

        // Find public functions with mutations but no authority
        let enforced_set: BTreeSet<String> = enforced.iter().cloned().collect();
        let public_fns: BTreeSet<String> = ir
            .functions
            .iter()
            .filter(|f| f.visibility == digger_ir::Visibility::Public)
            .map(|f| f.name.clone())
            .collect();

        // Build function → written state vars map
        let fn_writes: BTreeMap<String, Vec<String>> = state_edges
            .iter()
            .filter(|e| e.access == "write")
            .fold(BTreeMap::new(), |mut acc, e| {
                acc.entry(e.function.clone())
                    .or_default()
                    .push(e.state.clone());
                acc
            });

        // Unguarded mutations (sorted for deterministic output)
        let mut unguarded_mutations: Vec<UnguardedPath> = fn_writes
            .iter()
            .filter(|(fn_name, _)| !enforced_set.contains(*fn_name))
            .map(|(fn_name, state_vars)| UnguardedPath {
                function: fn_name.clone(),
                state_vars: state_vars.clone(),
                is_public: public_fns.contains(fn_name),
            })
            .collect();
        unguarded_mutations.sort_by(|a, b| a.function.cmp(&b.function));

        // Unguarded external calls (sorted for deterministic output)
        let mut unguarded_external: Vec<String> = external_fns
            .iter()
            .filter(|fn_name| !enforced_set.contains(*fn_name))
            .cloned()
            .collect();
        unguarded_external.sort();

        // Enforcement rate
        let total = auth_edges.len();
        let enforcement_rate = if total > 0 {
            enforced.len() as f64 / total as f64
        } else {
            0.0
        };

        AuthorityBoundaryGraph {
            enforced,
            missing,
            sources,
            unguarded_mutations,
            unguarded_external,
            enforcement_rate,
        }
    }

    /// Check if a specific function has authority enforcement.
    pub fn is_enforced(&self, fn_name: &str) -> bool {
        self.enforced.contains(&fn_name.to_string())
    }

    /// Get the authority source for a function.
    pub fn authority_source(&self, fn_name: &str) -> Option<&str> {
        self.sources.get(fn_name).map(|s| s.as_str())
    }

    /// Get all public functions that mutate state without authority.
    pub fn critical_unguarded_mutations(&self) -> Vec<&UnguardedPath> {
        self.unguarded_mutations
            .iter()
            .filter(|p| p.is_public)
            .collect()
    }
}
