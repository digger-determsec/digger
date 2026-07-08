use digger_graph::analysis::{CrossProgramGraph, ExecutionGraph, VulnerabilityPathAnalysis};
/// Cross-Protocol Demo View Layer
///
/// Provides a unified view that allows:
/// - Displaying execution graph for a protocol
/// - Showing cross-chain interactions (Solidity ↔ Rust ↔ Anchor)
/// - Highlighting existing vulnerability paths
///
/// This is purely a visualization/data structuring layer.
use digger_ir::SystemIR;
use serde::{Deserialize, Serialize};

/// Cross-protocol unified view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrossProtocolView {
    /// Program identifier.
    pub program_id: String,
    /// Language detected.
    pub language: String,
    /// Execution graph nodes.
    pub nodes: Vec<ExecutionNode>,
    /// Execution graph edges.
    pub edges: Vec<ExecutionEdge>,
    /// Cross-program interactions.
    pub cross_program: Vec<CrossProgramInteraction>,
    /// Highlighted vulnerability paths.
    pub highlighted_paths: Vec<HighlightedPath>,
    /// Summary.
    pub summary: StructuralSummary,
}

/// A node in the execution graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionNode {
    /// Function name.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Node type (entry, internal, leaf, external).
    pub node_type: String,
    /// Whether this node has authority.
    pub has_authority: bool,
    /// Whether this node writes state.
    pub writes_state: bool,
}

/// An edge in the execution graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionEdge {
    /// Source function.
    pub from: String,
    /// Target function.
    pub to: String,
    /// Edge type (call, external, cpi).
    pub edge_type: String,
}

/// A cross-program interaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrossProgramInteraction {
    /// Calling function.
    pub caller: String,
    /// Target program/contract.
    pub target: String,
    /// Interaction type (external_call, cpi, signed_cpi).
    pub interaction_type: String,
    /// Risk flags.
    pub risk_flags: Vec<String>,
}

/// A highlighted vulnerability path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HighlightedPath {
    /// Path identifier.
    pub id: String,
    /// Path type.
    pub path_type: String,
    /// Severity.
    pub severity: String,
    /// Sequence of function names in the path.
    pub sequence: Vec<String>,
}

/// Structural summary of cross-program analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructuralSummary {
    /// Total functions.
    pub total_functions: usize,
    /// Total edges.
    pub total_edges: usize,
    /// Entry points.
    pub entry_points: usize,
    /// External interactions.
    pub external_interactions: usize,
    /// Vulnerability paths detected.
    pub vulnerability_paths: usize,
}

impl CrossProtocolView {
    /// Build a cross-protocol view from SystemIR.
    pub fn build(ir: &SystemIR) -> Self {
        let exec = ExecutionGraph::build(ir);
        let cross = CrossProgramGraph::build(ir);
        let vuln = VulnerabilityPathAnalysis::derive(ir);

        // Build nodes
        let nodes: Vec<ExecutionNode> = ir.functions.iter().map(|f| {
            let is_entry = exec.entry_points.contains(&f.name);
            let is_leaf = exec.leaf_functions.contains(&f.name);
            let has_authority = ir.edges.iter().any(|e| {
                matches!(e, digger_ir::Edge::Authority(a) if a.function == f.name && a.check_type == "enforced")
            });
            let writes_state = ir.edges.iter().any(|e| {
                matches!(e, digger_ir::Edge::State(s) if s.function == f.name && s.access == "write")
            });

            let node_type = if is_entry {
                "entry"
            } else if is_leaf {
                "leaf"
            } else {
                "internal"
            };

            ExecutionNode {
                id: f.name.clone(),
                label: f.name.clone(),
                node_type: node_type.into(),
                has_authority,
                writes_state,
            }
        }).collect();

        // Build edges
        let edges: Vec<ExecutionEdge> = exec
            .edges
            .iter()
            .map(|e| ExecutionEdge {
                from: e.from.clone(),
                to: e.to.clone(),
                edge_type: "call".into(),
            })
            .collect();

        // Build cross-program interactions
        let cross_program: Vec<CrossProgramInteraction> = cross
            .external_calls
            .iter()
            .map(|e| {
                let interaction_type = if e.risk_flags.contains(&"signed".to_string()) {
                    "signed_cpi"
                } else if e.risk_flags.contains(&"cpi".to_string()) {
                    "cpi"
                } else {
                    "external_call"
                };

                CrossProgramInteraction {
                    caller: e.function.clone(),
                    target: e.target.clone(),
                    interaction_type: interaction_type.into(),
                    risk_flags: e.risk_flags.clone(),
                }
            })
            .collect();

        // Build highlighted paths
        let highlighted_paths: Vec<HighlightedPath> = vuln.paths.iter().map(|p| {
            let path_type = match p.path_type {
                digger_graph::analysis::vuln_path::VulnerabilityPathType::Reentrancy => "reentrancy",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::UnauthorizedModification => "unauthorized",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::CpiTrustViolation => "cpi_trust",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::MissingAuthority => "missing_auth",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::UntrustedExternal => "untrusted",
            };

            let severity = match p.severity {
                digger_graph::analysis::vuln_path::PathSeverity::Critical => "CRITICAL",
                digger_graph::analysis::vuln_path::PathSeverity::High => "HIGH",
                digger_graph::analysis::vuln_path::PathSeverity::Medium => "MEDIUM",
                digger_graph::analysis::vuln_path::PathSeverity::Low => "LOW",
                digger_graph::analysis::vuln_path::PathSeverity::Info => "INFO",
            };

            let sequence: Vec<String> = p.events.iter()
                .map(|e| e.function.clone())
                .collect();

            HighlightedPath {
                id: format!("{}-{}", path_type.to_uppercase(), p.entry_function),
                path_type: path_type.into(),
                severity: severity.into(),
                sequence,
            }
        }).collect();

        let summary = StructuralSummary {
            total_functions: ir.functions.len(),
            total_edges: ir.edges.len(),
            entry_points: exec.entry_points.len(),
            external_interactions: cross.external_calls.len(),
            vulnerability_paths: vuln.paths.len(),
        };

        CrossProtocolView {
            program_id: ir.program_id.clone(),
            language: format!("{:?}", ir.language),
            nodes,
            edges,
            cross_program,
            highlighted_paths,
            summary,
        }
    }
}
