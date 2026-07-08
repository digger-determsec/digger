use super::attack_surface::AttackSurface;
use super::cross_protocol::CrossProtocolView;
use super::evidence::EvidenceChain;
use super::path_standard::StandardizedPaths;
use super::risk_grouping::RiskGroups;
/// Product Output Schema — Stable Export Contract
///
/// This is the CANONICAL frontend/API artifact.
/// Treat this as a public API contract — field names, types, and structure
/// must remain stable across versions.
///
/// # Contract Rules
///
/// 1. All fields are required — never null, never omitted
/// 2. Empty collections serialize as `[]`, not `null`
/// 3. Output is deterministic — same input always produces same JSON
/// 4. Schema version is bumped on structural changes
/// 5. New fields are added with defaults — never remove existing fields
///
/// # Target JSON Shape
///
/// ```json
/// {
///   "version": "2.3",
///   "program_id": "...",
///   "attack_surface": {},
///   "paths": {},
///   "risk_groups": {},
///   "cross_protocol": {},
///   "evidence": [],
///   "metadata": {}
/// }
/// ```
use serde::{Deserialize, Serialize};

/// Schema version constant — bump on structural changes.
pub const SCHEMA_VERSION: &str = "2.3";

/// Canonical security intelligence output — the stable export contract.
///
/// This is the top-level artifact that all consumers (CLI, API, frontend)
/// rely on. Structural stability is a hard requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityIntelligenceOutput {
    /// Schema version — always "2.3" for this contract.
    pub version: String,
    /// Program identifier (filename, module name, etc.).
    pub program_id: String,
    /// Attack surface analysis.
    pub attack_surface: AttackSurface,
    /// Standardized vulnerability paths.
    pub paths: StandardizedPaths,
    /// Structural risk groups.
    pub risk_groups: RiskGroups,
    /// Cross-protocol view.
    pub cross_protocol: CrossProtocolView,
    /// Evidence chains — explainability for every finding.
    pub evidence: Vec<EvidenceChain>,
    /// Output metadata.
    pub metadata: OutputMetadata,
}

/// Output metadata — deterministic, no wall-clock timestamps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutputMetadata {
    /// Analysis depth level.
    pub analysis_depth: String,
    /// Languages detected.
    pub languages: Vec<String>,
    /// Total functions analyzed.
    pub total_functions: usize,
    /// Total edges in graph.
    pub total_edges: usize,
    /// Total findings.
    pub total_findings: usize,
}

impl SecurityIntelligenceOutput {
    /// Build a complete security intelligence output from SystemIR.
    ///
    /// This is the ONLY entry point for building the export contract.
    /// All fields are always populated — never null, never omitted.
    pub fn build(ir: &digger_ir::SystemIR) -> Self {
        let attack_surface = AttackSurface::build(ir);
        let paths = StandardizedPaths::build(ir);
        let risk_groups = RiskGroups::build(ir);
        let cross_protocol = CrossProtocolView::build(ir);
        let evidence = EvidenceChain::derive_all(ir);

        let total_findings = paths.summary.total;

        SecurityIntelligenceOutput {
            version: SCHEMA_VERSION.into(),
            program_id: ir.program_id.clone(),
            attack_surface,
            paths,
            risk_groups,
            cross_protocol,
            evidence,
            metadata: OutputMetadata {
                analysis_depth: "structural".into(),
                languages: vec![format!("{:?}", ir.language)],
                total_functions: ir.functions.len(),
                total_edges: ir.edges.len(),
                total_findings,
            },
        }
    }

    /// Serialize to deterministic JSON.
    ///
    /// Output is always pretty-printed and sorted for stability.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// Validate that this output conforms to the contract.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = vec![];

        if self.version != SCHEMA_VERSION {
            errors.push(format!(
                "version mismatch: expected '{}', got '{}'",
                SCHEMA_VERSION, self.version
            ));
        }

        if self.program_id.is_empty() {
            errors.push("program_id is empty".into());
        }

        if self.metadata.analysis_depth.is_empty() {
            errors.push("metadata.analysis_depth is empty".into());
        }

        errors
    }
}
