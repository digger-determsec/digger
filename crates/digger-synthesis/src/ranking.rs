/// Exploit chain ranking — deterministic scoring and explanation generation.
use crate::models::*;

/// Rank exploit chains using deterministic scoring.
pub fn rank_chains(chains: &[ExploitChain]) -> Vec<ExploitRanking> {
    let mut rankings: Vec<ExploitRanking> = chains
        .iter()
        .map(|chain| {
            let factors = compute_ranking_factors(chain);
            let score = compute_overall_score(&factors);

            ExploitRanking {
                chain_id: chain.chain_id.clone(),
                score,
                factors,
                rank: 0, // Set after sorting
            }
        })
        .collect();

    // Sort by score descending, then by chain_id for determinism
    rankings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.chain_id.cmp(&b.chain_id))
    });

    // Assign ranks
    for (i, ranking) in rankings.iter_mut().enumerate() {
        ranking.rank = i + 1;
    }

    rankings
}

/// Compute individual ranking factors for a chain.
pub fn compute_ranking_factors(chain: &ExploitChain) -> RankingFactors {
    // Evidence quality: based on number and diversity of evidence references
    let evidence_count = chain.evidence_provenance.len() as f64;
    let evidence_sources: usize = chain
        .evidence_provenance
        .iter()
        .map(|e| e.source.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let evidence_quality = (evidence_count * 0.2 + evidence_sources as f64 * 0.3).min(1.0);

    // Assumption support: fewer assumptions = higher score
    let assumption_count = chain.assumptions.len() as f64;
    let assumption_support = (1.0 - assumption_count * 0.1).max(0.0);

    // Contradiction score: no contradictions = 1.0
    // (In full implementation, check against verification properties)
    let contradiction_score = 1.0;

    // Historical similarity: based on pre-computed similarity
    let historical_similarity = if chain.historical_similarity.is_empty() {
        0.0
    } else {
        chain
            .historical_similarity
            .iter()
            .map(|s| s.similarity)
            .sum::<f64>()
            / chain.historical_similarity.len() as f64
    };

    // Reasoning depth: based on step count and evidence depth
    let reasoning_depth = (chain.steps.len() as f64 * 0.1).min(1.0);

    // Protocol semantics: based on confidence from evidence
    let protocol_semantics = chain.confidence;

    // Trust boundary: more trust boundary crossings = more interesting
    let trust_boundary_score = chain
        .evidence_provenance
        .iter()
        .filter(|e| matches!(e.kind, EvidenceRefKind::GraphAnalysis))
        .count() as f64
        * 0.15;

    // Economic impact: based on severity
    let economic_impact = match chain.severity {
        digger_ir::Severity::Critical => 1.0,
        digger_ir::Severity::High => 0.8,
        digger_ir::Severity::Medium => 0.5,
        digger_ir::Severity::Low => 0.3,
        digger_ir::Severity::Info => 0.1,
    };

    RankingFactors {
        evidence_quality,
        assumption_support,
        contradiction_score,
        historical_similarity,
        reasoning_depth,
        protocol_semantics,
        trust_boundary_score,
        economic_impact,
    }
}

/// Compute overall score from individual factors.
fn compute_overall_score(factors: &RankingFactors) -> f64 {
    // Weighted average of all factors
    let weights = [
        (factors.evidence_quality, 0.20),
        (factors.assumption_support, 0.15),
        (factors.contradiction_score, 0.10),
        (factors.historical_similarity, 0.15),
        (factors.reasoning_depth, 0.10),
        (factors.protocol_semantics, 0.15),
        (factors.trust_boundary_score, 0.05),
        (factors.economic_impact, 0.10),
    ];

    let weighted_sum: f64 = weights.iter().map(|(score, weight)| score * weight).sum();
    let weight_sum: f64 = weights.iter().map(|(_, weight)| weight).sum();

    (weighted_sum / weight_sum).clamp(0.0, 1.0)
}

/// Generate a human-readable explanation for an exploit chain.
pub fn explain_chain(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> ExploitExplanation {
    let summary = generate_summary(chain);
    let step_explanations: Vec<StepExplanation> = chain
        .steps
        .iter()
        .map(|step| explain_step(step, inputs))
        .collect();
    let feasibility = explain_feasibility(chain, inputs);
    let danger = explain_danger(chain);
    let mitigation = suggest_mitigation(chain);
    let historical = explain_historical_context(chain);

    ExploitExplanation {
        chain_id: chain.chain_id.clone(),
        summary,
        step_explanations,
        feasibility_reasoning: feasibility,
        danger_reasoning: danger,
        mitigation,
        historical_context: historical,
    }
}

fn generate_summary(chain: &ExploitChain) -> String {
    let step_count = chain.steps.len();
    let caps: Vec<String> = chain
        .required_capabilities
        .iter()
        .map(|c| c.to_string())
        .collect();

    format!(
        "Exploit chain achieves '{}' through {} step(s) requiring capabilities: [{}]. Confidence: {:.0}%, Severity: {:?}.",
        chain.goal,
        step_count,
        caps.join(", "),
        chain.confidence * 100.0,
        chain.severity,
    )
}

fn explain_step(step: &ExploitStep, inputs: &crate::engine::SynthesisInputs) -> StepExplanation {
    let explanation = format!(
        "Step {}: {} — {} (capability: {}, affected: [{}])",
        step.index + 1,
        step.function,
        step.action,
        step.required_capability,
        step.affected_state.join(", "),
    );

    let supporting_evidence = step
        .evidence_refs
        .iter()
        .map(|r| format!("Evidence: {}", r))
        .collect();

    let success_reason = if let Some(ir) = inputs.ir {
        // Check if this function has missing authority
        let has_missing_auth = ir.edges.iter().any(|e| {
            matches!(e, digger_ir::Edge::Authority(a) if a.function == step.function && a.check_type == "missing")
        });

        if has_missing_auth {
            format!("Function '{}' has no authority check", step.function)
        } else {
            step.explanation.clone()
        }
    } else {
        step.explanation.clone()
    };

    StepExplanation {
        step: step.index,
        explanation,
        supporting_evidence,
        success_reason,
    }
}

fn explain_feasibility(chain: &ExploitChain, inputs: &crate::engine::SynthesisInputs) -> String {
    let mut reasons = Vec::new();

    // Check capability availability
    if let Some(adv) = inputs.adversarial {
        for cap in &chain.required_capabilities {
            let available = adv.capabilities.iter().any(|_n| {
                matches!(
                    cap,
                    ExploitCapability::WriteState
                        | ExploitCapability::CrossContractCall
                        | ExploitCapability::CrossProgramInvocation
                )
            });
            if available {
                reasons.push(format!("Capability '{}' is available", cap));
            } else {
                reasons.push(format!("Capability '{}' must be obtained", cap));
            }
        }
    }

    // Check authority gaps
    let auth_gaps: Vec<String> = chain
        .steps
        .iter()
        .filter(|s| s.required_capability == ExploitCapability::AuthorityEscalation)
        .map(|s| s.function.clone())
        .collect();
    if !auth_gaps.is_empty() {
        reasons.push(format!("Authority gaps in: {}", auth_gaps.join(", ")));
    }

    if reasons.is_empty() {
        "Exploit chain appears feasible based on available evidence".into()
    } else {
        format!("Feasibility factors: {}", reasons.join("; "))
    }
}

fn explain_danger(chain: &ExploitChain) -> String {
    let invariant_count = chain.violated_invariants.len();
    let severity_desc = match chain.severity {
        digger_ir::Severity::Critical => "Critical — can drain all protocol funds",
        digger_ir::Severity::High => "High — significant fund loss or privilege escalation",
        digger_ir::Severity::Medium => "Medium — state corruption or logic bypass",
        digger_ir::Severity::Low => "Low — limited impact",
        digger_ir::Severity::Info => "Informational only",
    };

    format!(
        "{}. Violates {} invariant(s). Requires {} capabilities.",
        severity_desc,
        invariant_count,
        chain.required_capabilities.len()
    )
}

fn suggest_mitigation(chain: &ExploitChain) -> String {
    let mut mitigations: Vec<String> = Vec::new();

    for cap in &chain.required_capabilities {
        match cap {
            ExploitCapability::AuthorityEscalation => {
                mitigations.push("Add authority checks to all state-mutating functions".into());
            }
            ExploitCapability::FlashLoan => {
                mitigations.push("Add flash loan guards or reentrancy protection".into());
            }
            ExploitCapability::OracleInfluence => {
                mitigations.push("Use TWAP oracles or multi-source price feeds".into());
            }
            ExploitCapability::MultiTransaction => {
                mitigations.push("Add atomic transaction checks or sequence validation".into());
            }
            ExploitCapability::TransferAssets => {
                mitigations.push("Validate transfer amounts and recipients".into());
            }
            _ => {}
        }
    }

    if mitigations.is_empty() {
        "Review all state mutations and add appropriate access controls".into()
    } else {
        mitigations.join(". ")
    }
}

fn explain_historical_context(chain: &ExploitChain) -> String {
    if chain.historical_similarity.is_empty() {
        "No similar historical exploits found in the knowledge base".into()
    } else {
        let similar: Vec<String> = chain
            .historical_similarity
            .iter()
            .map(|s| {
                format!(
                    "Similar to {} ({}, {}% similar) — {}",
                    s.exploit_id,
                    s.protocol,
                    (s.similarity * 100.0) as u32,
                    s.shared_technique
                )
            })
            .collect();
        format!("Historical context: {}", similar.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranking_deterministic() {
        let chains = vec![
            ExploitChain {
                chain_id: "b".into(),
                goal: "test".into(),
                steps: vec![],
                required_capabilities: vec![],
                assumptions: vec![],
                violated_invariants: vec![],
                evidence_provenance: vec![],
                confidence: 0.7,
                severity: digger_ir::Severity::High,
                historical_similarity: vec![],
                rank: None,
                explanation: "test".into(),
            },
            ExploitChain {
                chain_id: "a".into(),
                goal: "test".into(),
                steps: vec![],
                required_capabilities: vec![],
                assumptions: vec![],
                violated_invariants: vec![],
                evidence_provenance: vec![],
                confidence: 0.7,
                severity: digger_ir::Severity::High,
                historical_similarity: vec![],
                rank: None,
                explanation: "test".into(),
            },
        ];

        let rankings = rank_chains(&chains);
        assert_eq!(rankings.len(), 2);
        assert_eq!(rankings[0].rank, 1);
        assert_eq!(rankings[1].rank, 2);
        // Same confidence → tiebreak by chain_id
        assert!(rankings[0].chain_id <= rankings[1].chain_id);
    }

    #[test]
    fn test_score_computation() {
        let factors = RankingFactors {
            evidence_quality: 0.8,
            assumption_support: 0.9,
            contradiction_score: 1.0,
            historical_similarity: 0.5,
            reasoning_depth: 0.6,
            protocol_semantics: 0.7,
            trust_boundary_score: 0.3,
            economic_impact: 0.8,
        };
        let score = compute_overall_score(&factors);
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_compute_ranking_factors() {
        let chain = ExploitChain {
            chain_id: "chain-test-001".into(),
            goal: "DrainAssets".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "withdraw".into(),
                action: "Drain via withdraw".into(),
                required_capability: ExploitCapability::TransferAssets,
                affected_state: vec!["balance".into()],
                affected_assets: vec!["USDC".into()],
                prerequisites: vec![],
                mutations: vec!["decrease balance".into()],
                evidence_refs: vec!["ir:withdraw".into()],
                confidence: 0.8,
                explanation: "Missing authority check".into(),
            }],
            required_capabilities: vec![ExploitCapability::TransferAssets],
            assumptions: vec!["Attacker has wallet".into()],
            violated_invariants: vec!["Conservation of funds".into()],
            evidence_provenance: vec![EvidenceReference {
                kind: EvidenceRefKind::GraphAnalysis,
                ref_id: "withdraw".into(),
                source: "digger-graph".into(),
                derivation: "Authority gap".into(),
            }],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "Test chain".into(),
        };
        let factors = compute_ranking_factors(&chain);
        assert!(factors.evidence_quality >= 0.0 && factors.evidence_quality <= 1.0);
        assert!(factors.assumption_support >= 0.0 && factors.assumption_support <= 1.0);
        assert!(factors.contradiction_score >= 0.0 && factors.contradiction_score <= 1.0);
        assert!(factors.historical_similarity >= 0.0 && factors.historical_similarity <= 1.0);
        assert!(factors.reasoning_depth >= 0.0 && factors.reasoning_depth <= 1.0);
        assert!(factors.protocol_semantics >= 0.0 && factors.protocol_semantics <= 1.0);
        assert!(factors.trust_boundary_score >= 0.0 && factors.trust_boundary_score <= 1.0);
        assert!(factors.economic_impact >= 0.0 && factors.economic_impact <= 1.0);
    }

    #[test]
    fn test_explain_chain() {
        let chain = ExploitChain {
            chain_id: "chain-test-002".into(),
            goal: "GainUnauthorizedControl".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "upgrade".into(),
                action: "Upgrade proxy".into(),
                required_capability: ExploitCapability::UpgradeProxy,
                affected_state: vec!["implementation".into()],
                affected_assets: vec![],
                prerequisites: vec![],
                mutations: vec!["change implementation".into()],
                evidence_refs: vec!["ir:upgrade".into()],
                confidence: 0.9,
                explanation: "No access control on upgrade".into(),
            }],
            required_capabilities: vec![ExploitCapability::UpgradeProxy],
            assumptions: vec![],
            violated_invariants: vec!["Proxy upgrade authorization".into()],
            evidence_provenance: vec![EvidenceReference {
                kind: EvidenceRefKind::GraphAnalysis,
                ref_id: "upgrade".into(),
                source: "digger-graph".into(),
                derivation: "Missing auth".into(),
            }],
            confidence: 0.9,
            severity: digger_ir::Severity::Critical,
            historical_similarity: vec![],
            rank: None,
            explanation: "Test".into(),
        };
        let inputs = crate::engine::SynthesisInputs {
            ir: None,
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
        let explanation = explain_chain(&chain, &inputs);
        assert_eq!(explanation.chain_id, "chain-test-002");
        assert!(!explanation.summary.is_empty());
        assert!(!explanation.feasibility_reasoning.is_empty());
        assert!(!explanation.danger_reasoning.is_empty());
        assert!(!explanation.mitigation.is_empty());
        assert_eq!(explanation.step_explanations.len(), 1);
    }
}
