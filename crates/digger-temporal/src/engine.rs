use crate::models::*;
/// Temporal Reasoning Engine — multi-transaction analysis.
///
/// Analyzes function pairs to discover temporal dependencies
/// and detect ordering violations.
///
/// Deterministic: same inputs → same output.
/// No AI, no inference, no heuristics.
/// Bounded: max 2 transactions per sequence, max 100 sequences.
use digger_parser::model::*;
use digger_state_transitions::StateTransitionReport;

/// Maximum sequences to generate per protocol.
const MAX_SEQUENCES: usize = 100;

/// Analyze temporal dependencies for a program.
pub fn analyze_temporal(
    program: &RawProgram,
    _transitions: &StateTransitionReport,
    protocol_id: &str,
) -> TemporalReport {
    // Build function profile: function -> (reads, writes, has_external, has_authority)
    let profiles = build_function_profiles(program, _transitions);

    // Generate 2-transaction sequences for public function pairs
    let sequences = generate_sequences(&profiles, program);

    // Discover temporal dependencies
    let dependencies = discover_dependencies(&profiles, &sequences);

    // Detect anomalies
    let anomalies = detect_anomalies(&sequences, &dependencies);

    // Update is_valid based on anomalies
    let mut sequences = sequences;
    for seq in &mut sequences {
        let has_anomaly = anomalies.iter().any(|a| a.sequence_id == seq.sequence_id);
        seq.is_valid = !has_anomaly;
    }

    // Build summary
    let functions_with_dependencies: std::collections::HashSet<String> = dependencies
        .iter()
        .flat_map(|d| vec![d.predecessor.clone(), d.successor.clone()])
        .collect();

    let summary = TemporalSummary {
        total_sequences: sequences.len(),
        total_dependencies: dependencies.len(),
        total_anomalies: anomalies.len(),
        functions_with_dependencies: functions_with_dependencies.len(),
    };

    TemporalReport {
        protocol_id: protocol_id.into(),
        dependencies,
        sequences,
        anomalies,
        summary,
    }
}

/// Profile of a function for temporal analysis.
#[derive(Debug, Clone)]
struct FunctionProfile {
    name: String,
    reads: Vec<String>,
    writes: Vec<String>,
    has_external_call: bool,
    has_authority: bool,
    is_public: bool,
}

/// Build function profiles from operations and transitions.
fn build_function_profiles(
    program: &RawProgram,
    _transitions: &StateTransitionReport,
) -> Vec<FunctionProfile> {
    let mut profiles = Vec::new();

    // Group operations by function
    let mut func_ops: std::collections::BTreeMap<String, Vec<&RawOperation>> =
        std::collections::BTreeMap::new();
    for op in &program.operations {
        func_ops.entry(op.function.clone()).or_default().push(op);
    }

    for func in &program.functions {
        let is_public = func.visibility == "public" || func.visibility == "external";

        let ops = func_ops.get(&func.name).cloned().unwrap_or_default();

        let reads: Vec<String> = ops
            .iter()
            .filter(|o| o.kind == OperationKind::StateRead)
            .map(|o| o.target.clone())
            .collect();
        let writes: Vec<String> = ops
            .iter()
            .filter(|o| o.kind == OperationKind::StateWrite)
            .map(|o| o.target.clone())
            .collect();
        let has_external_call = ops.iter().any(|o| o.kind == OperationKind::ExternalCall);
        let has_authority = ops.iter().any(|o| o.kind == OperationKind::AuthorityCheck);

        profiles.push(FunctionProfile {
            name: func.name.clone(),
            reads,
            writes,
            has_external_call,
            has_authority,
            is_public,
        });
    }

    profiles
}

/// Generate 2-transaction sequences for public function pairs with shared state.
fn generate_sequences(
    profiles: &[FunctionProfile],
    _program: &RawProgram,
) -> Vec<TransactionSequence> {
    let mut sequences = Vec::new();

    let public_fns: Vec<&FunctionProfile> = profiles.iter().filter(|p| p.is_public).collect();

    for (i, a) in public_fns.iter().enumerate() {
        for (j, b) in public_fns.iter().enumerate() {
            if i == j {
                continue;
            }
            if sequences.len() >= MAX_SEQUENCES {
                break;
            }

            // Only analyze pairs with shared state
            let shared_state = find_shared_state(a, b);
            if shared_state.is_empty() {
                continue;
            }

            let step_a = TransactionStep {
                function: a.name.clone(),
                index: 0,
                reads: a.reads.clone(),
                writes: a.writes.clone(),
                has_external_call: a.has_external_call,
                has_authority: a.has_authority,
            };
            let step_b = TransactionStep {
                function: b.name.clone(),
                index: 1,
                reads: b.reads.clone(),
                writes: b.writes.clone(),
                has_external_call: b.has_external_call,
                has_authority: b.has_authority,
            };

            let sequence_id = format!("seq:{}:{}", a.name, b.name);

            sequences.push(TransactionSequence {
                sequence_id,
                steps: vec![step_a, step_b],
                dependencies: Vec::new(), // filled later
                is_valid: true,           // determined later
            });
        }
    }

    sequences
}

/// Find shared state variables between two function profiles.
fn find_shared_state(a: &FunctionProfile, b: &FunctionProfile) -> Vec<String> {
    let writes_a: std::collections::HashSet<&String> = a.writes.iter().collect();
    let reads_b: std::collections::HashSet<&String> = b.reads.iter().collect();
    let reads_a: std::collections::HashSet<&String> = a.reads.iter().collect();
    let writes_b: std::collections::HashSet<&String> = b.writes.iter().collect();

    let mut shared = Vec::new();

    // A writes, B reads
    for var in &writes_a {
        if reads_b.contains(*var) {
            shared.push((*var).clone());
        }
    }
    // A reads, B writes
    for var in &reads_a {
        if writes_b.contains(*var) && !shared.contains(*var) {
            shared.push((*var).clone());
        }
    }

    shared
}

/// Discover temporal dependencies from function profiles and sequences.
fn discover_dependencies(
    profiles: &[FunctionProfile],
    sequences: &[TransactionSequence],
) -> Vec<TemporalDependency> {
    let mut dependencies = Vec::new();
    let profile_map: std::collections::BTreeMap<&str, &FunctionProfile> =
        profiles.iter().map(|p| (p.name.as_str(), p)).collect();

    for seq in sequences {
        if seq.steps.len() < 2 {
            continue;
        }
        let a = &seq.steps[0];
        let b = &seq.steps[1];

        let profile_a = profile_map.get(a.function.as_str());
        let profile_b = profile_map.get(b.function.as_str());

        if let (Some(pa), Some(pb)) = (profile_a, profile_b) {
            // Pattern 1: A writes state that B reads → A must precede B
            for var in &pa.writes {
                if pb.reads.contains(var) {
                    dependencies.push(TemporalDependency {
                        predecessor: a.function.clone(),
                        successor: b.function.clone(),
                        state_var: var.clone(),
                        reason: DependencyReason::StateUpdateBeforeRead,
                        is_enforced: false, // not enforced by default
                    });
                }
            }

            // Pattern 2: A has authority, B mutates same state without authority
            if pa.has_authority && !pb.has_authority {
                for var in &pb.writes {
                    if pa.reads.contains(var) || pa.writes.contains(var) {
                        dependencies.push(TemporalDependency {
                            predecessor: a.function.clone(),
                            successor: b.function.clone(),
                            state_var: var.clone(),
                            reason: DependencyReason::AuthorityBeforeMutation,
                            is_enforced: false,
                        });
                    }
                }
            }

            // Pattern 3: A writes state, B has external call on same state
            if pb.has_external_call {
                for var in &pa.writes {
                    if pb.reads.contains(var) {
                        dependencies.push(TemporalDependency {
                            predecessor: a.function.clone(),
                            successor: b.function.clone(),
                            state_var: var.clone(),
                            reason: DependencyReason::StateUpdateBeforeExternal,
                            is_enforced: false,
                        });
                    }
                }
            }
        }
    }

    // Sort for deterministic output
    dependencies.sort_by(|a, b| {
        a.predecessor
            .cmp(&b.predecessor)
            .then(a.successor.cmp(&b.successor))
            .then(a.state_var.cmp(&b.state_var))
    });
    dependencies.dedup_by(|a, b| {
        a.predecessor == b.predecessor && a.successor == b.successor && a.state_var == b.state_var
    });

    dependencies
}

/// Detect temporal anomalies from sequences and dependencies.
fn detect_anomalies(
    sequences: &[TransactionSequence],
    dependencies: &[TemporalDependency],
) -> Vec<TemporalAnomaly> {
    let mut anomalies = Vec::new();

    for seq in sequences {
        if seq.steps.len() < 2 {
            continue;
        }
        let a = &seq.steps[0];
        let b = &seq.steps[1];

        // Check if any dependency requires A before B but B is called first
        // (In our model, sequences are always [A, B], so we check if the
        // reverse dependency exists — meaning [B, A] would be unsafe)
        for dep in dependencies {
            if dep.predecessor == b.function && dep.successor == a.function {
                // The dependency says B must precede A, but our sequence has A before B
                // This means A→B is the WRONG order for this dependency
                anomalies.push(TemporalAnomaly {
                    sequence_id: seq.sequence_id.clone(),
                    kind: AnomalyKind::ReorderingAttack,
                    predecessor: dep.predecessor.clone(),
                    successor: dep.successor.clone(),
                    state_var: dep.state_var.clone(),
                    severity: digger_ir::Severity::High,
                });
            }
        }
    }

    // Sort for deterministic output
    anomalies.sort_by(|a, b| {
        a.sequence_id
            .cmp(&b.sequence_id)
            .then(a.predecessor.cmp(&b.predecessor))
            .then(a.successor.cmp(&b.successor))
    });
    anomalies.dedup_by(|a, b| {
        a.sequence_id == b.sequence_id
            && a.predecessor == b.predecessor
            && a.successor == b.successor
            && a.state_var == b.state_var
    });

    anomalies
}

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("JSON parse error: {0}")]
    Parse(String),
}

impl From<serde_json::Error> for AnalysisError {
    fn from(e: serde_json::Error) -> Self {
        AnalysisError::Parse(e.to_string())
    }
}

/// Serialize report to JSON.
pub fn report_to_json(report: &TemporalReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

/// Deserialize report from JSON.
pub fn report_from_json(json: &str) -> Result<TemporalReport, AnalysisError> {
    Ok(serde_json::from_str(json)?)
}
