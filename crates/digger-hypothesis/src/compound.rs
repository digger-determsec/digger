use crate::models::*;
/// Compound Hypothesis Engine — Deterministic Exploit Chain Derivation
///
/// Combines multiple atomic hypotheses into larger exploit narratives.
///
/// # Rules
///
/// 1. Consumes only HypothesisResult — does NOT re-derive from graph
/// 2. Deterministic: same input → same output
/// 3. No AI, no probabilities, no ranking
/// 4. Every compound hypothesis references source hypotheses and evidence
/// 5. Additive only — does NOT modify existing hypotheses
use serde::{Deserialize, Serialize};

/// Unique compound hypothesis identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompoundHypothesisId(pub String);

impl std::fmt::Display for CompoundHypothesisId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Compound hypothesis type — what kind of exploit chain this represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompoundHypothesisType {
    /// Reentrancy + Authority bypass — external call before state update, no access control.
    ReentrancyAuthorityChain,
    /// CPI trust violation + Authority bypass — CPI without authority, no access control.
    CPIAuthorityChain,
    /// State corruption + Authority bypass — multiple writers, no coordination.
    StateCorruptionChain,
    /// Multiple compatible hypotheses sharing functions, state, or paths.
    MultiPathExploitChain,
}

impl std::fmt::Display for CompoundHypothesisType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReentrancyAuthorityChain => write!(f, "ReentrancyAuthorityChain"),
            Self::CPIAuthorityChain => write!(f, "CPIAuthorityChain"),
            Self::StateCorruptionChain => write!(f, "StateCorruptionChain"),
            Self::MultiPathExploitChain => write!(f, "MultiPathExploitChain"),
        }
    }
}

/// Evidence supporting a compound hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundHypothesisEvidence {
    /// Source hypothesis IDs that compose this chain.
    pub source_hypothesis_ids: Vec<HypothesisId>,
    /// Source hypothesis types.
    pub source_types: Vec<HypothesisType>,
    /// Shared functions across the chain.
    pub shared_functions: Vec<String>,
    /// Shared state variables across the chain.
    pub shared_state: Vec<String>,
    /// Path IDs referenced by source hypotheses.
    pub path_ids: Vec<String>,
    /// Evidence chain IDs referenced by source hypotheses.
    pub evidence_chain_ids: Vec<String>,
    /// Graph facts from all source hypotheses.
    pub graph_facts: Vec<GraphFact>,
}

/// A compound hypothesis — an exploit chain combining multiple atomic hypotheses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundHypothesis {
    /// Unique identifier.
    pub id: CompoundHypothesisId,
    /// Type of compound hypothesis.
    pub compound_type: CompoundHypothesisType,
    /// Severity — highest severity of source hypotheses.
    pub severity: HypothesisSeverity,
    /// Human-readable description.
    pub description: String,
    /// Structural explanation of the chain.
    pub structural_explanation: String,
    /// Evidence from source hypotheses.
    pub evidence: CompoundHypothesisEvidence,
}

/// Result of compound hypothesis derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundHypothesisResult {
    /// Program identifier.
    pub program_id: String,
    /// All derived compound hypotheses.
    pub compound_hypotheses: Vec<CompoundHypothesis>,
    /// Summary statistics.
    pub summary: CompoundHypothesisSummary,
}

/// Summary statistics for compound hypothesis derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundHypothesisSummary {
    /// Total compound hypotheses derived.
    pub total: usize,
    /// Count by type.
    pub reentrancy_authority_count: usize,
    pub cpi_authority_count: usize,
    pub state_corruption_count: usize,
    pub multi_path_count: usize,
}

/// Derive compound hypotheses from atomic HypothesisResult.
///
/// This is the ONLY entry point. Consumes existing hypotheses only.
pub fn derive_compound(result: &HypothesisResult) -> CompoundHypothesisResult {
    let mut compounds = vec![];

    // 1. ReentrancyAuthorityChain: ReentrancyCandidate + AuthorityBypassCandidate
    compounds.extend(derive_reentrancy_authority_chains(result));

    // 2. CPIAuthorityChain: CPITrustViolationCandidate + AuthorityBypassCandidate
    compounds.extend(derive_cpi_authority_chains(result));

    // 3. StateCorruptionChain: StateCorruptionCandidate + AuthorityBypassCandidate
    compounds.extend(derive_state_corruption_chains(result));

    // 4. MultiPathExploitChain: 2+ compatible hypotheses sharing functions/state
    compounds.extend(derive_multi_path_chains(result));

    let summary = build_compound_summary(&compounds);

    CompoundHypothesisResult {
        program_id: result.program_id.clone(),
        compound_hypotheses: compounds,
        summary,
    }
}

/// Derive ReentrancyAuthorityChain: reentrancy + authority bypass on same or related functions.
fn derive_reentrancy_authority_chains(result: &HypothesisResult) -> Vec<CompoundHypothesis> {
    let reentrancy: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::ReentrancyCandidate)
        .collect();
    let auth_bypass: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();

    let mut chains = vec![];

    for re in &reentrancy {
        for auth in &auth_bypass {
            // Check if they share functions or state
            let shared_functions = find_shared_functions(re, auth);
            let shared_state = find_shared_state(re, auth);

            if !shared_functions.is_empty() || !shared_state.is_empty() {
                let all_path_ids = collect_path_ids(re, auth);
                let all_chain_ids = collect_chain_ids(re, auth);
                let all_facts = collect_graph_facts(re, auth);

                let severity = std::cmp::max(re.severity.clone(), auth.severity.clone());

                chains.push(CompoundHypothesis {
                    id: CompoundHypothesisId(format!(
                        "COMP-REAUTH-{}-{}", re.primary_function, auth.primary_function
                    )),
                    compound_type: CompoundHypothesisType::ReentrancyAuthorityChain,
                    severity,
                    description: format!(
                        "Reentrancy + authority bypass chain: '{}' has external call before state update, \
                         '{}' mutates state without authority",
                        re.primary_function, auth.primary_function
                    ),
                    structural_explanation: format!(
                        "Compound exploit chain combining:\n\
                         1. Reentrancy in '{}': external call before state update\n\
                         2. Authority bypass in '{}': public function mutates state without access control\n\
                         Shared elements: functions=[{}], state=[{}]\n\
                         An attacker could exploit the reentrancy vector while the authority bypass \
                         ensures no access control prevents the attack.",
                        re.primary_function, auth.primary_function,
                        shared_functions.join(", "),
                        shared_state.join(", ")
                    ),
                    evidence: CompoundHypothesisEvidence {
                        source_hypothesis_ids: vec![re.id.clone(), auth.id.clone()],
                        source_types: vec![re.hypothesis_type.clone(), auth.hypothesis_type.clone()],
                        shared_functions,
                        shared_state,
                        path_ids: all_path_ids,
                        evidence_chain_ids: all_chain_ids,
                        graph_facts: all_facts,
                    },
                });
            }
        }
    }

    chains
}

/// Derive CPIAuthorityChain: CPI trust violation + authority bypass.
fn derive_cpi_authority_chains(result: &HypothesisResult) -> Vec<CompoundHypothesis> {
    let cpi: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::CPITrustViolationCandidate)
        .collect();
    let auth_bypass: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();

    let mut chains = vec![];

    for cp in &cpi {
        for auth in &auth_bypass {
            let shared_functions = find_shared_functions(cp, auth);
            let shared_state = find_shared_state(cp, auth);

            if !shared_functions.is_empty() || !shared_state.is_empty() {
                let all_path_ids = collect_path_ids(cp, auth);
                let all_chain_ids = collect_chain_ids(cp, auth);
                let all_facts = collect_graph_facts(cp, auth);

                let severity = std::cmp::max(cp.severity.clone(), auth.severity.clone());

                chains.push(CompoundHypothesis {
                    id: CompoundHypothesisId(format!(
                        "COMP-CPIAUTH-{}-{}", cp.primary_function, auth.primary_function
                    )),
                    compound_type: CompoundHypothesisType::CPIAuthorityChain,
                    severity,
                    description: format!(
                        "CPI trust + authority bypass chain: '{}' makes CPI without authority, \
                         '{}' mutates state without authority",
                        cp.primary_function, auth.primary_function
                    ),
                    structural_explanation: format!(
                        "Compound exploit chain combining:\n\
                         1. CPI trust violation in '{}': cross-program call without authority\n\
                         2. Authority bypass in '{}': public function mutates state without access control\n\
                         Shared elements: functions=[{}], state=[{}]\n\
                         An attacker could exploit the CPI trust boundary while the authority bypass \
                         ensures no access control prevents state corruption.",
                        cp.primary_function, auth.primary_function,
                        shared_functions.join(", "),
                        shared_state.join(", ")
                    ),
                    evidence: CompoundHypothesisEvidence {
                        source_hypothesis_ids: vec![cp.id.clone(), auth.id.clone()],
                        source_types: vec![cp.hypothesis_type.clone(), auth.hypothesis_type.clone()],
                        shared_functions,
                        shared_state,
                        path_ids: all_path_ids,
                        evidence_chain_ids: all_chain_ids,
                        graph_facts: all_facts,
                    },
                });
            }
        }
    }

    chains
}

/// Derive StateCorruptionChain: state corruption + authority bypass.
fn derive_state_corruption_chains(result: &HypothesisResult) -> Vec<CompoundHypothesis> {
    let state_corrupt: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::StateCorruptionCandidate)
        .collect();
    let auth_bypass: Vec<_> = result
        .hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .collect();

    let mut chains = vec![];

    for sc in &state_corrupt {
        for auth in &auth_bypass {
            let shared_functions = find_shared_functions(sc, auth);
            let shared_state = find_shared_state(sc, auth);

            if !shared_functions.is_empty() || !shared_state.is_empty() {
                let all_path_ids = collect_path_ids(sc, auth);
                let all_chain_ids = collect_chain_ids(sc, auth);
                let all_facts = collect_graph_facts(sc, auth);

                let severity = std::cmp::max(sc.severity.clone(), auth.severity.clone());

                chains.push(CompoundHypothesis {
                    id: CompoundHypothesisId(format!(
                        "COMP-STATEAUTH-{}-{}", sc.primary_function, auth.primary_function
                    )),
                    compound_type: CompoundHypothesisType::StateCorruptionChain,
                    severity,
                    description: format!(
                        "State corruption + authority bypass chain: '{}' has multiple writers, \
                         '{}' bypasses authority",
                        sc.primary_function, auth.primary_function
                    ),
                    structural_explanation: format!(
                        "Compound exploit chain combining:\n\
                         1. State corruption in '{}': multiple writers without coordination\n\
                         2. Authority bypass in '{}': public function mutates state without access control\n\
                         Shared elements: functions=[{}], state=[{}]\n\
                         An attacker could exploit the uncoordinated writes while the authority bypass \
                         ensures no access control prevents state manipulation.",
                        sc.primary_function, auth.primary_function,
                        shared_functions.join(", "),
                        shared_state.join(", ")
                    ),
                    evidence: CompoundHypothesisEvidence {
                        source_hypothesis_ids: vec![sc.id.clone(), auth.id.clone()],
                        source_types: vec![sc.hypothesis_type.clone(), auth.hypothesis_type.clone()],
                        shared_functions,
                        shared_state,
                        path_ids: all_path_ids,
                        evidence_chain_ids: all_chain_ids,
                        graph_facts: all_facts,
                    },
                });
            }
        }
    }

    chains
}

/// Derive MultiPathExploitChain: 2+ compatible hypotheses sharing functions or state.
fn derive_multi_path_chains(result: &HypothesisResult) -> Vec<CompoundHypothesis> {
    let mut chains = vec![];
    let hypotheses = &result.hypotheses;

    // Find pairs of hypotheses that share functions or state
    for i in 0..hypotheses.len() {
        for j in (i + 1)..hypotheses.len() {
            let a = &hypotheses[i];
            let b = &hypotheses[j];

            // Skip if already covered by specific chain types
            if is_specific_chain_pair(a, b) {
                continue;
            }

            let shared_functions = find_shared_functions(a, b);
            let shared_state = find_shared_state(a, b);

            if !shared_functions.is_empty() || !shared_state.is_empty() {
                let all_path_ids = collect_path_ids(a, b);
                let all_chain_ids = collect_chain_ids(a, b);
                let all_facts = collect_graph_facts(a, b);

                let severity = std::cmp::max(a.severity.clone(), b.severity.clone());

                chains.push(CompoundHypothesis {
                    id: CompoundHypothesisId(format!(
                        "COMP-MULTI-{}-{}", a.primary_function, b.primary_function
                    )),
                    compound_type: CompoundHypothesisType::MultiPathExploitChain,
                    severity,
                    description: format!(
                        "Multi-path exploit chain: '{}' ({}) and '{}' ({}) share structural elements",
                        a.primary_function, a.hypothesis_type,
                        b.primary_function, b.hypothesis_type
                    ),
                    structural_explanation: format!(
                        "Compound exploit chain combining:\n\
                         1. '{}' ({}): {}\n\
                         2. '{}' ({}): {}\n\
                         Shared elements: functions=[{}], state=[{}]\n\
                         These hypotheses share structural elements that could be combined \
                         into a multi-step exploit.",
                        a.primary_function, a.hypothesis_type, a.description,
                        b.primary_function, b.hypothesis_type, b.description,
                        shared_functions.join(", "),
                        shared_state.join(", ")
                    ),
                    evidence: CompoundHypothesisEvidence {
                        source_hypothesis_ids: vec![a.id.clone(), b.id.clone()],
                        source_types: vec![a.hypothesis_type.clone(), b.hypothesis_type.clone()],
                        shared_functions,
                        shared_state,
                        path_ids: all_path_ids,
                        evidence_chain_ids: all_chain_ids,
                        graph_facts: all_facts,
                    },
                });
            }
        }
    }

    chains
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/// Check if a pair is already covered by a specific chain type.
fn is_specific_chain_pair(a: &Hypothesis, b: &Hypothesis) -> bool {
    let types = [&a.hypothesis_type, &b.hypothesis_type];
    let has_reentrancy = types
        .iter()
        .any(|t| **t == HypothesisType::ReentrancyCandidate);
    let has_auth = types
        .iter()
        .any(|t| **t == HypothesisType::AuthorityBypassCandidate);
    let has_cpi = types
        .iter()
        .any(|t| **t == HypothesisType::CPITrustViolationCandidate);
    let has_state = types
        .iter()
        .any(|t| **t == HypothesisType::StateCorruptionCandidate);

    (has_reentrancy && has_auth) || (has_cpi && has_auth) || (has_state && has_auth)
}

/// Find shared functions between two hypotheses.
fn find_shared_functions(a: &Hypothesis, b: &Hypothesis) -> Vec<String> {
    let fns_a: std::collections::HashSet<_> = a
        .evidence
        .iter()
        .flat_map(|e| e.involved_functions.iter())
        .collect();
    let fns_b: std::collections::HashSet<_> = b
        .evidence
        .iter()
        .flat_map(|e| e.involved_functions.iter())
        .collect();

    fns_a.intersection(&fns_b).map(|s| s.to_string()).collect()
}

/// Find shared state variables between two hypotheses.
fn find_shared_state(a: &Hypothesis, b: &Hypothesis) -> Vec<String> {
    let state_a: std::collections::HashSet<_> = a
        .evidence
        .iter()
        .flat_map(|e| e.graph_facts.iter())
        .filter(|f| f.fact_type == "state_write")
        .map(|f| &f.detail)
        .collect();
    let state_b: std::collections::HashSet<_> = b
        .evidence
        .iter()
        .flat_map(|e| e.graph_facts.iter())
        .filter(|f| f.fact_type == "state_write")
        .map(|f| &f.detail)
        .collect();

    state_a
        .intersection(&state_b)
        .map(|s| s.to_string())
        .collect()
}

/// Collect all path IDs from two hypotheses.
fn collect_path_ids(a: &Hypothesis, b: &Hypothesis) -> Vec<String> {
    let mut ids: Vec<String> = a
        .evidence
        .iter()
        .map(|e| e.path_id.clone())
        .chain(b.evidence.iter().map(|e| e.path_id.clone()))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Collect all evidence chain IDs from two hypotheses.
fn collect_chain_ids(a: &Hypothesis, b: &Hypothesis) -> Vec<String> {
    let mut ids: Vec<String> = a
        .evidence
        .iter()
        .map(|e| e.evidence_chain_id.clone())
        .chain(b.evidence.iter().map(|e| e.evidence_chain_id.clone()))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Collect all graph facts from two hypotheses.
fn collect_graph_facts(a: &Hypothesis, b: &Hypothesis) -> Vec<GraphFact> {
    let mut facts: Vec<GraphFact> = a
        .evidence
        .iter()
        .flat_map(|e| e.graph_facts.iter().cloned())
        .chain(
            b.evidence
                .iter()
                .flat_map(|e| e.graph_facts.iter().cloned()),
        )
        .collect();

    // Deduplicate by (fact_type, function, detail)
    facts.sort_by(|x, y| {
        (&x.fact_type, &x.function, &x.detail).cmp(&(&y.fact_type, &y.function, &y.detail))
    });
    facts.dedup_by(|x, y| {
        x.fact_type == y.fact_type && x.function == y.function && x.detail == y.detail
    });
    facts
}

/// Build summary statistics.
fn build_compound_summary(compounds: &[CompoundHypothesis]) -> CompoundHypothesisSummary {
    CompoundHypothesisSummary {
        total: compounds.len(),
        reentrancy_authority_count: compounds
            .iter()
            .filter(|c| c.compound_type == CompoundHypothesisType::ReentrancyAuthorityChain)
            .count(),
        cpi_authority_count: compounds
            .iter()
            .filter(|c| c.compound_type == CompoundHypothesisType::CPIAuthorityChain)
            .count(),
        state_corruption_count: compounds
            .iter()
            .filter(|c| c.compound_type == CompoundHypothesisType::StateCorruptionChain)
            .count(),
        multi_path_count: compounds
            .iter()
            .filter(|c| c.compound_type == CompoundHypothesisType::MultiPathExploitChain)
            .count(),
    }
}
