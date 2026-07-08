use digger_graph::analysis::VulnerabilityPathAnalysis;
/// Execution Path Standardization Layer
///
/// Standardizes representation of existing vulnerability paths.
/// Does NOT introduce new path detection logic — only formats existing paths.
use digger_ir::SystemIR;
use serde::{Deserialize, Serialize};

/// Standardized vulnerability paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandardizedPaths {
    /// All paths in standardized format.
    pub paths: Vec<StandardPath>,
    /// Grouped by path type.
    pub by_type: PathTypeGroups,
    /// Summary.
    pub summary: PathSummary,
}

/// A standardized vulnerability path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandardPath {
    /// Unique path identifier.
    pub id: String,
    /// Path type.
    pub path_type: String,
    /// Severity label.
    pub severity: String,
    /// Entry function.
    pub entry: String,
    /// Ordered sequence of steps.
    pub steps: Vec<PathStep>,
    /// Human-readable description.
    pub description: String,
}

/// A single step in a standardized path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathStep {
    /// Step number (1-indexed).
    pub step: usize,
    /// Function involved.
    pub function: String,
    /// What happens at this step.
    pub action: String,
    /// Relevant detail (state var, target, etc.).
    pub detail: String,
}

/// Paths grouped by type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathTypeGroups {
    /// Reentrancy paths.
    pub reentrancy: Vec<StandardPath>,
    /// Unauthorized modification paths.
    pub unauthorized: Vec<StandardPath>,
    /// CPI trust violation paths.
    pub cpi_trust: Vec<StandardPath>,
    /// Other paths.
    pub other: Vec<StandardPath>,
}

/// Summary of standardized paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathSummary {
    /// Total paths.
    pub total: usize,
    /// Count by type.
    pub reentrancy_count: usize,
    pub unauthorized_count: usize,
    pub cpi_trust_count: usize,
    pub other_count: usize,
}

impl StandardizedPaths {
    /// Standardize vulnerability paths from SystemIR.
    pub fn build(ir: &SystemIR) -> Self {
        let vuln = VulnerabilityPathAnalysis::derive(ir);

        let paths: Vec<StandardPath> = vuln.paths.iter().enumerate().map(|(i, path)| {
            let path_type = match path.path_type {
                digger_graph::analysis::vuln_path::VulnerabilityPathType::Reentrancy => "reentrancy",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::UnauthorizedModification => "unauthorized_modification",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::CpiTrustViolation => "cpi_trust_violation",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::MissingAuthority => "missing_authority",
                digger_graph::analysis::vuln_path::VulnerabilityPathType::UntrustedExternal => "untrusted_external",
            };

            let severity = match path.severity {
                digger_graph::analysis::vuln_path::PathSeverity::Critical => "CRITICAL",
                digger_graph::analysis::vuln_path::PathSeverity::High => "HIGH",
                digger_graph::analysis::vuln_path::PathSeverity::Medium => "MEDIUM",
                digger_graph::analysis::vuln_path::PathSeverity::Low => "LOW",
                digger_graph::analysis::vuln_path::PathSeverity::Info => "INFO",
            };

            let steps: Vec<PathStep> = path.events.iter().enumerate().map(|(j, event)| {
                let action = match event.event_type {
                    digger_graph::analysis::vuln_path::PathEventType::EntryPoint => "entry",
                    digger_graph::analysis::vuln_path::PathEventType::InternalCall => "internal_call",
                    digger_graph::analysis::vuln_path::PathEventType::ExternalCall => "external_call",
                    digger_graph::analysis::vuln_path::PathEventType::CpiCall => "cpi_call",
                    digger_graph::analysis::vuln_path::PathEventType::StateWrite => "state_write",
                    digger_graph::analysis::vuln_path::PathEventType::StateRead => "state_read",
                    digger_graph::analysis::vuln_path::PathEventType::AuthorityCheck => "authority_check",
                    digger_graph::analysis::vuln_path::PathEventType::MissingAuthority => "missing_authority",
                };

                PathStep {
                    step: j + 1,
                    function: event.function.clone(),
                    action: action.into(),
                    detail: event.detail.clone(),
                }
            }).collect();

            let description = format_path_description(path_type, &path.entry_function, &steps);

            StandardPath {
                id: format!("PATH-{}-{}", path_type.to_uppercase(), i + 1),
                path_type: path_type.into(),
                severity: severity.into(),
                entry: path.entry_function.clone(),
                steps,
                description,
            }
        }).collect();

        // Group by type
        let reentrancy: Vec<_> = paths
            .iter()
            .filter(|p| p.path_type == "reentrancy")
            .cloned()
            .collect();
        let unauthorized: Vec<_> = paths
            .iter()
            .filter(|p| {
                p.path_type == "unauthorized_modification" || p.path_type == "missing_authority"
            })
            .cloned()
            .collect();
        let cpi_trust: Vec<_> = paths
            .iter()
            .filter(|p| p.path_type == "cpi_trust_violation")
            .cloned()
            .collect();
        let other: Vec<_> = paths
            .iter()
            .filter(|p| {
                ![
                    "reentrancy",
                    "unauthorized_modification",
                    "missing_authority",
                    "cpi_trust_violation",
                ]
                .contains(&p.path_type.as_str())
            })
            .cloned()
            .collect();

        let summary = PathSummary {
            total: paths.len(),
            reentrancy_count: reentrancy.len(),
            unauthorized_count: unauthorized.len(),
            cpi_trust_count: cpi_trust.len(),
            other_count: other.len(),
        };

        StandardizedPaths {
            paths,
            by_type: PathTypeGroups {
                reentrancy,
                unauthorized,
                cpi_trust,
                other,
            },
            summary,
        }
    }
}

fn format_path_description(path_type: &str, entry: &str, steps: &[PathStep]) -> String {
    let step_desc: Vec<String> = steps
        .iter()
        .map(|s| format!("{}. {} → {}", s.step, s.function, s.action))
        .collect();

    format!(
        "[{}] {}: {}",
        path_type.to_uppercase(),
        entry,
        step_desc.join(" → ")
    )
}
