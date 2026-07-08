/// Execution graph analysis — unified call chain traversal.
///
/// Treats ALL CallEdges uniformly regardless of source language:
/// - Solidity function calls
/// - Rust internal calls
/// - Anchor CPI calls
///
/// Provides:
/// - Call chain construction
/// - Cycle detection
/// - Call depth computation
/// - Entry point identification
/// - Leaf function identification
use digger_ir::{CallEdge, Edge, SystemIR};

/// A unified call chain derived from SystemIR edges.
///
/// This is a READ-ONLY analysis result — it does not modify SystemIR.
#[derive(Debug, Clone)]
pub struct ExecutionGraph {
    /// All call edges in the program.
    pub edges: Vec<CallEdge>,
    /// Functions that are never called by anyone (entry points).
    pub entry_points: Vec<String>,
    /// Functions that never call anything else (leaf functions).
    pub leaf_functions: Vec<String>,
    /// Detected cycles (list of function name chains forming cycles).
    pub cycles: Vec<Vec<String>>,
    /// Maximum call depth from any entry point.
    pub max_depth: usize,
    /// Per-function call depth from nearest entry point.
    pub depths: std::collections::BTreeMap<String, usize>,
}

impl ExecutionGraph {
    /// Build an execution graph from SystemIR.
    ///
    /// This is the ONLY entry point. It reads existing Call edges
    /// and derives all analysis from them.
    pub fn build(ir: &SystemIR) -> Self {
        let edges: Vec<CallEdge> = ir
            .edges
            .iter()
            .filter_map(|e| {
                if let Edge::Call(call) = e {
                    Some(call.clone())
                } else {
                    None
                }
            })
            .collect();

        // Collect all function names
        let all_names: Vec<String> = ir.functions.iter().map(|f| f.name.clone()).collect();

        // Build adjacency list
        let callers: std::collections::HashSet<String> =
            edges.iter().map(|e| e.from.clone()).collect();
        let callees: std::collections::HashSet<String> =
            edges.iter().map(|e| e.to.clone()).collect();

        // Entry points: functions that are never called by anyone
        let entry_points: Vec<String> = all_names
            .iter()
            .filter(|name| !callees.contains(*name))
            .cloned()
            .collect();

        // Leaf functions: functions that never call anything else
        let leaf_functions: Vec<String> = all_names
            .iter()
            .filter(|name| !callers.contains(*name))
            .cloned()
            .collect();

        // Detect cycles using DFS
        let cycles = detect_cycles(&edges, &all_names);

        // Compute call depths
        let (max_depth, depths) = compute_depths(&edges, &entry_points, &all_names);

        ExecutionGraph {
            edges,
            entry_points,
            leaf_functions,
            cycles,
            max_depth,
            depths,
        }
    }

    /// Get the call chain from a specific function to all reachable functions.
    pub fn call_chain_from(&self, from: &str) -> Vec<String> {
        let mut visited = std::collections::HashSet::new();
        let mut chain = vec![];
        self.dfs_collect(from, &mut visited, &mut chain);
        chain
    }

    /// Get all functions that directly call the given function.
    pub fn callers_of(&self, target: &str) -> Vec<String> {
        self.edges
            .iter()
            .filter(|e| e.to == target)
            .map(|e| e.from.clone())
            .collect()
    }

    /// Get all functions that the given function directly calls.
    pub fn callees_of(&self, source: &str) -> Vec<String> {
        self.edges
            .iter()
            .filter(|e| e.from == source)
            .map(|e| e.to.clone())
            .collect()
    }

    /// Check if there is a path from `from` to `to`.
    pub fn has_path(&self, from: &str, to: &str) -> bool {
        let chain = self.call_chain_from(from);
        chain.contains(&to.to_string())
    }

    fn dfs_collect(
        &self,
        current: &str,
        visited: &mut std::collections::HashSet<String>,
        chain: &mut Vec<String>,
    ) {
        if visited.contains(current) {
            return;
        }
        visited.insert(current.to_string());
        chain.push(current.to_string());

        for edge in &self.edges {
            if edge.from == current {
                self.dfs_collect(&edge.to, visited, chain);
            }
        }
    }
}

/// Detect cycles in the call graph using DFS.
fn detect_cycles(edges: &[CallEdge], all_names: &[String]) -> Vec<Vec<String>> {
    let mut cycles = vec![];
    let mut visited = std::collections::HashSet::new();
    let mut in_stack = std::collections::HashSet::new();
    let mut path = vec![];

    for name in all_names {
        if !visited.contains(name) {
            dfs_cycle(
                name,
                edges,
                &mut visited,
                &mut in_stack,
                &mut path,
                &mut cycles,
                0,
            );
        }
    }

    cycles
}

fn dfs_cycle(
    current: &str,
    edges: &[CallEdge],
    visited: &mut std::collections::HashSet<String>,
    in_stack: &mut std::collections::HashSet<String>,
    path: &mut Vec<String>,
    cycles: &mut Vec<Vec<String>>,
    depth: usize,
) {
    if depth > 200 {
        return;
    }
    if in_stack.contains(current) {
        // Found a cycle — extract it
        let Some(cycle_start) = path.iter().position(|p| p == current) else {
            return;
        };
        let cycle: Vec<String> = path[cycle_start..].to_vec();
        if !cycle.is_empty() {
            cycles.push(cycle);
        }
        return;
    }
    if visited.contains(current) {
        return;
    }

    visited.insert(current.to_string());
    in_stack.insert(current.to_string());
    path.push(current.to_string());

    for edge in edges {
        if edge.from == current {
            dfs_cycle(&edge.to, edges, visited, in_stack, path, cycles, depth + 1);
        }
    }

    path.pop();
    in_stack.remove(current);
}

/// Compute call depths from entry points using BFS.
fn compute_depths(
    edges: &[CallEdge],
    entry_points: &[String],
    all_names: &[String],
) -> (usize, std::collections::BTreeMap<String, usize>) {
    let mut depths: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut queue = std::collections::VecDeque::new();

    // Initialize entry points at depth 0
    for ep in entry_points {
        depths.insert(ep.clone(), 0);
        queue.push_back((ep.clone(), 0));
    }

    // BFS
    while let Some((current, depth)) = queue.pop_front() {
        for edge in edges {
            if edge.from == current {
                let new_depth = depth + 1;
                let existing = depths.get(&edge.to).copied().unwrap_or(usize::MAX);
                if new_depth < existing {
                    depths.insert(edge.to.clone(), new_depth);
                    queue.push_back((edge.to.clone(), new_depth));
                }
            }
        }
    }

    // Any function not reachable from an entry point gets depth 0
    for name in all_names {
        depths.entry(name.clone()).or_insert(0);
    }

    let max_depth = depths.values().copied().max().unwrap_or(0);
    (max_depth, depths)
}
