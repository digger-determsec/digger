/// Cross-program graph analysis — unified external call model.
///
/// Unifies:
/// - Solidity external calls (.call, .delegatecall, .staticcall)
/// - Anchor CPI calls (invoke, invoke_signed)
/// - Rust inter-module calls
///
/// Into a single traversal model over existing External edges.
/// No new edge types are introduced.
use digger_ir::{Edge, ExternalCallEdge, SystemIR};
use std::collections::{BTreeMap, BTreeSet};

/// Cross-program analysis result.
///
/// This is a READ-ONLY analysis result — it does not modify SystemIR.
#[derive(Debug, Clone)]
pub struct CrossProgramGraph {
    /// All external call edges (unified across languages).
    pub external_calls: Vec<ExternalCallEdge>,
    /// Functions that make external calls.
    pub external_callers: Vec<String>,
    /// External targets (contracts/programs being called).
    pub external_targets: Vec<String>,
    /// CPI-specific calls (invoke/invoke_signed).
    pub cpi_calls: Vec<ExternalCallEdge>,
    /// Calls with signed invocation (invoke_signed).
    pub signed_calls: Vec<ExternalCallEdge>,
    /// Functions with external calls but no authority check.
    pub untrusted_external: Vec<String>,
    /// External call graph: caller → list of targets.
    pub call_graph: BTreeMap<String, Vec<String>>,
    /// Risk summary: target → risk flags.
    pub target_risks: BTreeMap<String, Vec<String>>,
}

impl CrossProgramGraph {
    /// Build a cross-program graph from SystemIR.
    pub fn build(ir: &SystemIR) -> Self {
        let external_edges: Vec<ExternalCallEdge> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let Edge::External(ext) = e {
                    Some(ext.clone())
                } else {
                    None
                }
            })
            .collect();

        // Authority-enforced functions
        let enforced_fns: BTreeSet<String> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let Edge::Authority(a) = e {
                    if a.check_type == "enforced" {
                        Some(a.function.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // External callers
        let mut external_callers: Vec<String> = external_edges
            .iter()
            .map(|e| e.function.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        external_callers.sort();

        // External targets
        let mut external_targets: Vec<String> = external_edges
            .iter()
            .map(|e| e.target.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        external_targets.sort();

        // CPI calls (contain "cpi" flag)
        let cpi_calls: Vec<ExternalCallEdge> = external_edges
            .iter()
            .filter(|e| e.risk_flags.contains(&"cpi".to_string()))
            .cloned()
            .collect();

        // Signed calls (contain "signed" flag)
        let signed_calls: Vec<ExternalCallEdge> = external_edges
            .iter()
            .filter(|e| e.risk_flags.contains(&"signed".to_string()))
            .cloned()
            .collect();

        // Untrusted external: functions with external calls but no authority
        let untrusted_external: Vec<String> = external_callers
            .iter()
            .filter(|fn_name| !enforced_fns.contains(*fn_name))
            .cloned()
            .collect();

        // Build call graph: caller → targets
        let mut call_graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for edge in &external_edges {
            call_graph
                .entry(edge.function.clone())
                .or_default()
                .push(edge.target.clone());
        }

        // Build risk summary: target → risk flags
        let mut target_risks: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for edge in &external_edges {
            let entry = target_risks.entry(edge.target.clone()).or_default();
            for flag in &edge.risk_flags {
                if !entry.contains(flag) {
                    entry.push(flag.clone());
                }
            }
        }

        CrossProgramGraph {
            external_calls: external_edges,
            external_callers,
            external_targets,
            cpi_calls,
            signed_calls,
            untrusted_external,
            call_graph,
            target_risks,
        }
    }

    /// Get all targets that a specific function calls externally.
    pub fn targets_of(&self, fn_name: &str) -> Vec<String> {
        self.call_graph.get(fn_name).cloned().unwrap_or_default()
    }

    /// Get all functions that call a specific external target.
    pub fn callers_to(&self, target: &str) -> Vec<String> {
        self.external_calls
            .iter()
            .filter(|e| e.target == target)
            .map(|e| e.function.clone())
            .collect()
    }

    /// Check if a function makes CPI calls.
    pub fn makes_cpi(&self, fn_name: &str) -> bool {
        self.cpi_calls.iter().any(|e| e.function == fn_name)
    }

    /// Check if a function makes signed CPI calls.
    pub fn makes_signed_cpi(&self, fn_name: &str) -> bool {
        self.signed_calls.iter().any(|e| e.function == fn_name)
    }

    /// Get risk flags for a specific external target.
    pub fn risks_for_target(&self, target: &str) -> Vec<String> {
        self.target_risks.get(target).cloned().unwrap_or_default()
    }

    /// Check if there is a trust boundary crossing from a function to a target.
    pub fn crosses_trust_boundary(&self, from: &str, to: &str) -> bool {
        self.external_calls
            .iter()
            .any(|e| e.function == from && e.target == to)
    }
}
