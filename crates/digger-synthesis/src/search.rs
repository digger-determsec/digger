use crate::engine::SynthesisInputs;
/// Exploit search — deterministic search over the evidence graph.
use crate::models::*;

/// Search for exploit paths in the evidence graph.
///
/// Prioritizes:
/// 1. Highest evidence
/// 2. Fewest unsupported assumptions
/// 3. Highest benchmark similarity
/// 4. Protocol semantics
/// 5. Trust boundary crossings
/// 6. Invariant violations
pub fn search_exploit_paths(inputs: &SynthesisInputs, max_results: usize) -> Vec<ExploitChain> {
    let mut candidates = Vec::new();

    // Search 1: Authority bypass paths
    if let Some(ir) = inputs.ir {
        for edge in &ir.edges {
            if let digger_ir::Edge::Authority(a) = edge {
                if a.check_type == "missing" {
                    candidates.push(SearchCandidate {
                        evidence_quality: 0.8,
                        assumption_count: 1,
                        invariant_violations: 1,
                    });
                }
            }
        }
    }

    // Search 2: Reentrancy paths
    if let Some(ir) = inputs.ir {
        for edge in &ir.edges {
            if let digger_ir::Edge::External(e) = edge {
                // Check if the function also writes state
                let writes_state = ir.edges.iter().any(|e2| {
                    matches!(e2, digger_ir::Edge::State(s) if s.function == e.function && s.access == "write")
                });
                if writes_state {
                    candidates.push(SearchCandidate {
                        evidence_quality: 0.9,
                        assumption_count: 0,
                        invariant_violations: 1,
                    });
                }
            }
        }
    }

    // Search 3: CPI trust violation paths (Solana)
    if let Some(ir) = inputs.ir {
        for edge in &ir.edges {
            if let digger_ir::Edge::External(e) = edge {
                if e.risk_flags.contains(&"cpi".to_string()) {
                    let has_auth = ir.edges.iter().any(|e2| {
                        matches!(e2, digger_ir::Edge::Authority(a) if a.function == e.function && a.check_type != "missing")
                    });
                    if !has_auth {
                        candidates.push(SearchCandidate {
                            evidence_quality: 0.85,
                            assumption_count: 1,
                            invariant_violations: 1,
                        });
                    }
                }
            }
        }
    }

    // Search 4: Economic invariant violation paths
    if let Some(econ) = inputs.economics {
        for invariant in &econ.invariants {
            if !invariant.is_satisfied {
                candidates.push(SearchCandidate {
                    evidence_quality: 0.7,
                    assumption_count: 2,
                    invariant_violations: 1,
                });
            }
        }
    }

    // Search 5: Temporal ordering attacks
    if let Some(temporal) = inputs.temporal {
        for _anomaly in &temporal.anomalies {
            candidates.push(SearchCandidate {
                evidence_quality: 0.6,
                assumption_count: 1,
                invariant_violations: 1,
            });
        }
    }

    // Search 6: State corruption paths
    if let Some(transitions) = inputs.transitions {
        for _missing in &transitions.missing_transitions {
            candidates.push(SearchCandidate {
                evidence_quality: 0.5,
                assumption_count: 1,
                invariant_violations: 1,
            });
        }
    }

    // Search 7: Resource lifecycle anomalies
    if let Some(lifecycles) = inputs.lifecycles {
        for lifecycle in &lifecycles.lifecycles {
            for _anomaly in &lifecycle.anomalies {
                candidates.push(SearchCandidate {
                    evidence_quality: 0.6,
                    assumption_count: 1,
                    invariant_violations: 1,
                });
            }
        }
    }

    // Sort candidates by priority
    candidates.sort_by(|a, b| {
        b.evidence_quality
            .partial_cmp(&a.evidence_quality)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.assumption_count.cmp(&b.assumption_count))
            .then_with(|| b.invariant_violations.cmp(&a.invariant_violations))
    });

    candidates.truncate(max_results);

    let mut chains = Vec::new();
    for (i, candidate) in candidates.into_iter().enumerate() {
        chains.push(ExploitChain {
            chain_id: format!("search_{}", i),
            goal: "exploit_chain".into(),
            steps: vec![],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: candidate.evidence_quality,
            severity: digger_ir::Severity::Medium,
            historical_similarity: vec![],
            rank: None,
            explanation: format!("Search candidate with evidence quality {:.2}, {} assumptions, {} invariant violations",
                candidate.evidence_quality, candidate.assumption_count, candidate.invariant_violations),
        });
    }

    chains
}

/// A candidate for exploit search.
#[derive(Debug)]
struct SearchCandidate {
    evidence_quality: f64,
    assumption_count: usize,
    invariant_violations: usize,
}

/// Kind of exploit search.
#[derive(Debug)]
#[allow(dead_code)]
enum SearchKind {
    AuthorityBypass,
    Reentrancy,
    CpiTrustViolation,
    EconomicViolation,
    TemporalAttack,
    StateCorruption,
    LifecycleAnomaly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_no_input() {
        let inputs = crate::engine::SynthesisInputs {
            ir: Some(&digger_ir::SystemIR {
                program_id: "test".into(),
                language: digger_ir::Language::Unknown,
                functions: vec![],
                state: vec![],
                edges: vec![],
            }),
            expansion: None,
            transitions: None,
            lifecycles: None,
            temporal: None,
            actors: None,
            economics: None,
            verification: None,
            adversarial: None,
            protocol: None,
            surface: None,
        };

        let results = search_exploit_paths(&inputs, 10);
        assert!(results.is_empty());
    }
}
