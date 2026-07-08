/// State dependency graph analysis — derived from State edges.
///
/// Computes:
/// - Which functions write to which state variables
/// - Indirect state mutation chains (function A writes state, function B reads it)
/// - Multi-hop state influence paths
/// - State isolation (variables only touched by one function)
///
/// All analysis is derived purely from existing State edges.
/// No new IR types are introduced.
use digger_ir::{Edge, StateEdge, SystemIR};
use std::collections::{BTreeMap, BTreeSet};

/// State dependency analysis result.
///
/// This is a READ-ONLY analysis result — it does not modify SystemIR.
#[derive(Debug, Clone)]
pub struct StateDependencyGraph {
    /// State variable name → functions that write to it.
    pub writers: BTreeMap<String, Vec<String>>,
    /// State variable name → functions that read from it.
    pub readers: BTreeMap<String, Vec<String>>,
    /// Functions that write state but have no authority check.
    pub unguarded_writers: Vec<String>,
    /// State variables written by multiple functions (shared mutation).
    pub shared_mutations: Vec<String>,
    /// State variables touched by only one function (isolated).
    pub isolated_state: Vec<String>,
    /// Indirect influence chains: (writer_fn, state, reader_fn).
    pub influence_chains: Vec<(String, String, String)>,
    /// Multi-hop paths: (start_fn, [state_vars], end_fn).
    pub multi_hop_paths: Vec<(String, Vec<String>, String)>,
}

impl StateDependencyGraph {
    /// Build a state dependency graph from SystemIR.
    pub fn build(ir: &SystemIR) -> Self {
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

        // Authority edges for checking unguarded writers
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

        // Build writer/reader maps
        let mut writers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut readers: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for edge in &state_edges {
            if edge.access == "write" {
                writers
                    .entry(edge.state.clone())
                    .or_default()
                    .push(edge.function.clone());
            } else {
                readers
                    .entry(edge.state.clone())
                    .or_default()
                    .push(edge.function.clone());
            }
        }

        // Unguarded writers: functions that write state but have no authority check
        let mut unguarded_writers: Vec<String> = state_edges
            .iter()
            .filter(|e| e.access == "write")
            .map(|e| e.function.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|fn_name| !enforced_fns.contains(fn_name))
            .collect();
        unguarded_writers.sort();

        // Shared mutations: state variables written by 2+ functions
        let mut shared_mutations: Vec<String> = writers
            .iter()
            .filter(|(_, fns)| fns.len() >= 2)
            .map(|(state, _)| state.clone())
            .collect();
        shared_mutations.sort();

        // Isolated state: state variables touched by only one function
        let isolated_state: Vec<String> = ir
            .state
            .iter()
            .filter(|s| {
                let total_touchers = state_edges
                    .iter()
                    .filter(|e| e.state == s.name)
                    .map(|e| e.function.clone())
                    .collect::<BTreeSet<_>>()
                    .len();
                total_touchers == 1
            })
            .map(|s| s.name.clone())
            .collect();

        // Influence chains: writer → state → reader (indirect dependency)
        let mut influence_chains = vec![];
        let mut sorted_states: Vec<&String> = writers.keys().collect();
        sorted_states.sort();
        for state in &sorted_states {
            if let Some(fns_readers) = readers.get(*state) {
                if let Some(fns_writers) = writers.get(*state) {
                    let mut sorted_writers = fns_writers.clone();
                    sorted_writers.sort();
                    let mut sorted_readers = fns_readers.clone();
                    sorted_readers.sort();
                    for writer in &sorted_writers {
                        for reader in &sorted_readers {
                            if writer != reader {
                                influence_chains.push((
                                    writer.clone(),
                                    (*state).clone(),
                                    reader.clone(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Multi-hop paths: writer → state1 → reader_writer → state2 → reader
        let multi_hop_paths = find_multi_hop_paths(&state_edges, &writers, &readers);

        StateDependencyGraph {
            writers,
            readers,
            unguarded_writers,
            shared_mutations,
            isolated_state,
            influence_chains,
            multi_hop_paths,
        }
    }

    /// Get all state variables written by a specific function.
    pub fn states_written_by(&self, fn_name: &str) -> Vec<String> {
        let mut result: Vec<String> = self
            .writers
            .iter()
            .filter(|(_, fns)| fns.contains(&fn_name.to_string()))
            .map(|(state, _)| state.clone())
            .collect();
        result.sort();
        result
    }

    /// Get all functions that read a specific state variable.
    pub fn readers_of(&self, state: &str) -> Vec<String> {
        self.readers.get(state).cloned().unwrap_or_default()
    }

    /// Check if a state mutation path exists from writer to reader.
    pub fn has_influence_path(&self, from: &str, to: &str) -> bool {
        self.influence_chains
            .iter()
            .any(|(writer, _, reader)| writer == from && reader == to)
    }
}

/// Find multi-hop state influence paths.
///
/// A multi-hop path is: function A writes state X, function B reads X and
/// writes state Y, function C reads Y.
fn find_multi_hop_paths(
    state_edges: &[StateEdge],
    writers: &BTreeMap<String, Vec<String>>,
    _readers: &BTreeMap<String, Vec<String>>,
) -> Vec<(String, Vec<String>, String)> {
    let mut paths = vec![];

    // Find functions that both read and write (intermediate nodes)
    let fns_with_reads: BTreeMap<String, Vec<String>> = state_edges
        .iter()
        .filter(|e| e.access == "read")
        .fold(BTreeMap::new(), |mut acc, e| {
            acc.entry(e.function.clone())
                .or_default()
                .push(e.state.clone());
            acc
        });
    let fns_with_writes: BTreeMap<String, Vec<String>> = state_edges
        .iter()
        .filter(|e| e.access == "write")
        .fold(BTreeMap::new(), |mut acc, e| {
            acc.entry(e.function.clone())
                .or_default()
                .push(e.state.clone());
            acc
        });

    // Find intermediate functions (read + write)
    let mut intermediates: Vec<String> = fns_with_reads
        .keys()
        .filter(|k| fns_with_writes.contains_key(*k))
        .cloned()
        .collect();
    intermediates.sort();

    // For each intermediate, check if any writer feeds into it
    for intermediate in &intermediates {
        let Some(reads) = fns_with_reads.get(intermediate) else {
            continue;
        };
        let Some(writes) = fns_with_writes.get(intermediate) else {
            continue;
        };

        for read_state in reads {
            // Find who writes the state this intermediate reads
            if let Some(feeders) = writers.get(read_state) {
                for feeder in feeders {
                    if feeder != intermediate {
                        // feeder → read_state → intermediate → writes → ...
                        for write_state in writes {
                            paths.push((
                                feeder.clone(),
                                vec![read_state.clone(), write_state.clone()],
                                intermediate.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }

    paths
}
