use digger_graph::analysis::{CrossProgramGraph, ExecutionGraph, StateDependencyGraph};
/// Structural Risk Grouping Layer
///
/// Groups existing graph nodes into structural clusters.
/// Does NOT assign scores or rank vulnerabilities.
/// Only organizes by structural properties.
use digger_ir::SystemIR;
use serde::{Deserialize, Serialize};

/// Structural risk groups derived from graph analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskGroups {
    /// High fan-in functions (many callers).
    pub high_fan_in: Vec<FanGroup>,
    /// High fan-out functions (many external calls).
    pub high_fan_out: Vec<FanGroup>,
    /// High state mutation density.
    pub high_state_density: Vec<StateDensityGroup>,
    /// External interaction density.
    pub external_density: Vec<ExternalDensityGroup>,
    /// Summary.
    pub summary: GroupSummary,
}

/// A fan-in/fan-out group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FanGroup {
    /// Function name.
    pub function: String,
    /// Number of callers (fan-in) or callees (fan-out).
    pub count: usize,
    /// Names of callers or callees.
    pub related: Vec<String>,
}

/// A state mutation density group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateDensityGroup {
    /// Function name.
    pub function: String,
    /// Number of state variables written.
    pub state_count: usize,
    /// Names of state variables.
    pub state_vars: Vec<String>,
}

/// An external interaction density group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalDensityGroup {
    /// Function name.
    pub function: String,
    /// Number of external targets.
    pub target_count: usize,
    /// External target names.
    pub targets: Vec<String>,
}

/// Summary of risk groups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupSummary {
    /// Number of high fan-in functions.
    pub high_fan_in_count: usize,
    /// Number of high fan-out functions.
    pub high_fan_out_count: usize,
    /// Number of high state density functions.
    pub high_state_density_count: usize,
    /// Number of high external density functions.
    pub high_external_density_count: usize,
}

impl RiskGroups {
    /// Build risk groups from SystemIR.
    pub fn build(ir: &SystemIR) -> Self {
        let exec = ExecutionGraph::build(ir);
        let state_dep = StateDependencyGraph::build(ir);
        let cross = CrossProgramGraph::build(ir);

        // High fan-in: functions called by 2+ other functions
        let mut fan_in_counts: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for edge in &exec.edges {
            fan_in_counts
                .entry(edge.to.clone())
                .or_default()
                .push(edge.from.clone());
        }
        let mut high_fan_in: Vec<FanGroup> = fan_in_counts
            .iter()
            .filter(|(_, callers)| callers.len() >= 2)
            .map(|(func, callers)| FanGroup {
                function: func.clone(),
                count: callers.len(),
                related: callers.clone(),
            })
            .collect();
        high_fan_in.sort_by(|a, b| a.function.cmp(&b.function));

        // High fan-out: functions that call 2+ others
        let mut fan_out_counts: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for edge in &exec.edges {
            fan_out_counts
                .entry(edge.from.clone())
                .or_default()
                .push(edge.to.clone());
        }
        let mut high_fan_out: Vec<FanGroup> = fan_out_counts
            .iter()
            .filter(|(_, callees)| callees.len() >= 2)
            .map(|(func, callees)| FanGroup {
                function: func.clone(),
                count: callees.len(),
                related: callees.clone(),
            })
            .collect();
        high_fan_out.sort_by(|a, b| a.function.cmp(&b.function));

        // High state mutation density: functions that write 2+ state vars
        let mut high_state_density: Vec<StateDensityGroup> = state_dep
            .writers
            .iter()
            .fold(
                std::collections::BTreeMap::<String, Vec<String>>::new(),
                |mut acc, (state, writers)| {
                    for writer in writers {
                        acc.entry(writer.clone()).or_default().push(state.clone());
                    }
                    acc
                },
            )
            .iter()
            .filter(|(_, states)| states.len() >= 2)
            .map(|(func, states)| StateDensityGroup {
                function: func.clone(),
                state_count: states.len(),
                state_vars: states.clone(),
            })
            .collect();
        high_state_density.sort_by(|a, b| a.function.cmp(&b.function));

        // External interaction density: functions with 2+ external targets
        let mut external_density: Vec<ExternalDensityGroup> = cross
            .call_graph
            .iter()
            .filter(|(_, targets)| targets.len() >= 2)
            .map(|(func, targets)| ExternalDensityGroup {
                function: func.clone(),
                target_count: targets.len(),
                targets: targets.clone(),
            })
            .collect();
        external_density.sort_by(|a, b| a.function.cmp(&b.function));

        let summary = GroupSummary {
            high_fan_in_count: high_fan_in.len(),
            high_fan_out_count: high_fan_out.len(),
            high_state_density_count: high_state_density.len(),
            high_external_density_count: external_density.len(),
        };

        RiskGroups {
            high_fan_in,
            high_fan_out,
            high_state_density,
            external_density,
            summary,
        }
    }
}
