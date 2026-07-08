use crate::economic::EconomicValidationResult;
/// Generation 3.1d — Exploit Feasibility Scoring (Enhanced)
///
/// Computes deterministic feasibility metrics with per-factor explanations,
/// cross-validation between subsystems, and sensitivity analysis.
use crate::models::*;
use crate::preconditions::PreconditionResult;
use crate::state_validation::StateValidationResult;

/// Per-factor scoring breakdown with explanations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FactorBreakdown {
    /// Factor name.
    pub name: String,
    /// Raw score (0.0 - 1.0).
    pub score: f64,
    /// Weight in overall score.
    pub weight: f64,
    /// Weighted contribution.
    pub contribution: f64,
    /// Explanation for this factor.
    pub explanation: String,
    /// Confidence in this factor assessment.
    pub confidence: f64,
}

/// Cross-validation result between subsystems.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossValidation {
    /// Conflicts between precondition and state validation.
    pub conflicts: Vec<String>,
    /// Corroborations between subsystems.
    pub corroborations: Vec<String>,
    /// Consistency score (0.0 - 1.0).
    pub consistency: f64,
}

/// Extended feasibility result with detailed breakdown.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtendedFeasibilityResult {
    /// Base feasibility score.
    pub base: FeasibilityScore,
    /// Per-factor breakdown.
    pub factors: Vec<FactorBreakdown>,
    /// Cross-validation between subsystems.
    pub cross_validation: CrossValidation,
    /// Risk factors identified.
    pub risk_factors: Vec<String>,
    /// Confidence intervals.
    pub confidence_range: (f64, f64),
}

/// Compute feasibility score for an exploit chain.
pub fn score_feasibility(
    chain: &ExploitChain,
    precondition_result: &PreconditionResult,
    state_result: &StateValidationResult,
    economic_result: &EconomicValidationResult,
) -> FeasibilityScore {
    let breakdown =
        compute_factor_breakdown(chain, precondition_result, state_result, economic_result);
    let cross_validation = cross_validate(precondition_result, state_result, economic_result);

    // Weighted overall score from breakdown
    let overall: f64 = breakdown.iter().map(|f| f.contribution).sum();
    let overall = overall.clamp(0.0, 1.0);

    // Adjust for cross-validation consistency
    let adjusted = overall * 0.9 + cross_validation.consistency * 0.1;
    let adjusted = adjusted.clamp(0.0, 1.0);

    let verdict = match adjusted {
        x if x >= 0.8 => FeasibilityVerdict::HighlyFeasible,
        x if x >= 0.6 => FeasibilityVerdict::Feasible,
        x if x >= 0.4 => FeasibilityVerdict::PossiblyFeasible,
        x if x >= 0.2 => FeasibilityVerdict::Unlikely,
        _ => FeasibilityVerdict::Infeasible,
    };

    let explanation = generate_detailed_explanation(&breakdown, &cross_validation, adjusted);

    // Confidence range based on variance of factor scores
    let factor_scores: Vec<f64> = breakdown.iter().map(|f| f.score).collect();
    let mean = factor_scores.iter().sum::<f64>() / factor_scores.len() as f64;
    let variance = factor_scores
        .iter()
        .map(|s| (s - mean).powi(2))
        .sum::<f64>()
        / factor_scores.len() as f64;
    let std_dev = variance.sqrt();
    let _confidence_range = ((adjusted - std_dev).max(0.0), (adjusted + std_dev).min(1.0));

    FeasibilityScore {
        chain_id: chain.chain_id.clone(),
        overall: adjusted,
        components: FeasibilityComponents {
            precondition_score: breakdown
                .iter()
                .find(|f| f.name == "preconditions")
                .map(|f| f.score)
                .unwrap_or(0.0),
            state_reachability: breakdown
                .iter()
                .find(|f| f.name == "state_reachability")
                .map(|f| f.score)
                .unwrap_or(0.0),
            invariant_violations: breakdown
                .iter()
                .find(|f| f.name == "invariant_violations")
                .map(|f| f.score)
                .unwrap_or(0.0),
            trust_boundary_score: breakdown
                .iter()
                .find(|f| f.name == "trust_boundaries")
                .map(|f| f.score)
                .unwrap_or(0.0),
            economic_viability: breakdown
                .iter()
                .find(|f| f.name == "economic_viability")
                .map(|f| f.score)
                .unwrap_or(0.0),
            assumption_violations: breakdown
                .iter()
                .find(|f| f.name == "assumption_support")
                .map(|f| f.score)
                .unwrap_or(0.0),
            evidence_quality: breakdown
                .iter()
                .find(|f| f.name == "evidence_quality")
                .map(|f| f.score)
                .unwrap_or(0.0),
            step_efficiency: breakdown
                .iter()
                .find(|f| f.name == "step_efficiency")
                .map(|f| f.score)
                .unwrap_or(0.0),
        },
        explanation,
        verdict,
    }
}

/// Compute factor-by-factor breakdown.
fn compute_factor_breakdown(
    chain: &ExploitChain,
    precondition_result: &PreconditionResult,
    state_result: &StateValidationResult,
    economic_result: &EconomicValidationResult,
) -> Vec<FactorBreakdown> {
    let mut factors = Vec::new();

    // 1. Precondition score
    let pre_score = if precondition_result.preconditions.is_empty() {
        (
            0.5,
            "No preconditions checked — using default assumption".into(),
            0.6,
        )
    } else {
        let rate =
            precondition_result.satisfied as f64 / precondition_result.preconditions.len() as f64;
        let missing = precondition_result.missing;
        let explanation = if missing == 0 {
            format!(
                "All {} preconditions satisfied",
                precondition_result.satisfied
            )
        } else {
            format!(
                "{}/{} satisfied, {} missing — some capabilities may be unavailable",
                precondition_result.satisfied,
                precondition_result.preconditions.len(),
                missing
            )
        };
        (rate, explanation, 0.9)
    };
    factors.push(FactorBreakdown {
        name: "preconditions".into(),
        score: pre_score.0,
        weight: 0.25,
        contribution: pre_score.0 * 0.25,
        explanation: pre_score.1,
        confidence: pre_score.2,
    });

    // 2. State reachability
    let state_score = if state_result.transitions.is_empty() {
        (0.5, "No state transitions to validate".into(), 0.5)
    } else {
        let rate = state_result.valid_count as f64 / state_result.transitions.len() as f64;
        let explanation = if state_result.all_valid {
            format!(
                "All {} state transitions are reachable",
                state_result.valid_count
            )
        } else {
            format!(
                "{}/{} transitions valid — {} unreachable",
                state_result.valid_count,
                state_result.transitions.len(),
                state_result.invalid_count
            )
        };
        (rate, explanation, 0.95)
    };
    factors.push(FactorBreakdown {
        name: "state_reachability".into(),
        score: state_score.0,
        weight: 0.20,
        contribution: state_score.0 * 0.20,
        explanation: state_score.1,
        confidence: state_score.2,
    });

    // 3. Invariant violations
    let inv_count = chain.violated_invariants.len();
    let inv_score = (inv_count as f64 * 0.3).min(1.0);
    factors.push(FactorBreakdown {
        name: "invariant_violations".into(),
        score: inv_score,
        weight: 0.15,
        contribution: inv_score * 0.15,
        explanation: format!(
            "{} invariant(s) violated — {}",
            inv_count,
            if inv_count == 0 {
                "no impact".into()
            } else if inv_count == 1 {
                "single critical violation".into()
            } else {
                format!("{} cascading violations", inv_count)
            }
        ),
        confidence: 0.85,
    });

    // 4. Trust boundaries
    let tb_count = chain
        .evidence_provenance
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EvidenceRefKind::GraphAnalysis | EvidenceRefKind::VerificationProperty
            )
        })
        .count();
    let tb_score = (tb_count as f64 * 0.2).min(1.0);
    factors.push(FactorBreakdown {
        name: "trust_boundaries".into(),
        score: tb_score,
        weight: 0.05,
        contribution: tb_score * 0.05,
        explanation: format!(
            "{} trust boundary crossing(s) identified from graph analysis",
            tb_count
        ),
        confidence: 0.8,
    });

    // 5. Economic viability
    let econ_score = if economic_result.economically_viable {
        (
            1.0,
            format!(
                "Economically viable — net profit across {} asset(s)",
                economic_result.net_profit.len()
            ),
            0.9,
        )
    } else if economic_result.net_profit.values().any(|v| *v > 0.0) {
        let profitable: Vec<String> = economic_result
            .net_profit
            .iter()
            .filter(|(_, v)| **v > 0.0)
            .map(|(k, _)| k.clone())
            .collect();
        (
            0.5,
            format!(
                "Partially viable — profit only in: {}",
                profitable.join(", ")
            ),
            0.7,
        )
    } else {
        (
            0.0,
            "Not economically viable — costs exceed gains".into(),
            0.85,
        )
    };
    factors.push(FactorBreakdown {
        name: "economic_viability".into(),
        score: econ_score.0,
        weight: 0.15,
        contribution: econ_score.0 * 0.15,
        explanation: econ_score.1,
        confidence: econ_score.2,
    });

    // 6. Assumption support
    let ass_count = chain.assumptions.len();
    let ass_score = (1.0 - ass_count as f64 * 0.15).max(0.0);
    factors.push(FactorBreakdown {
        name: "assumption_support".into(),
        score: ass_score,
        weight: 0.05,
        contribution: ass_score * 0.05,
        explanation: format!(
            "{} assumption(s) required — {}",
            ass_count,
            if ass_count == 0 {
                "no assumptions"
            } else {
                "some unverified conditions"
            }
        ),
        confidence: 0.7,
    });

    // 7. Evidence quality
    let ev_count = chain.evidence_provenance.len();
    let ev_sources: usize = chain
        .evidence_provenance
        .iter()
        .map(|e| e.source.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let ev_score = (ev_count as f64 * 0.2).min(0.6) + (ev_sources as f64 * 0.1).min(0.4);
    factors.push(FactorBreakdown {
        name: "evidence_quality".into(),
        score: ev_score,
        weight: 0.10,
        contribution: ev_score * 0.10,
        explanation: format!(
            "{} evidence references from {} distinct sources",
            ev_count, ev_sources
        ),
        confidence: 0.85,
    });

    // 8. Step efficiency
    let step_count = chain.steps.len();
    let step_score = (1.0 - step_count as f64 * 0.08).max(0.0);
    factors.push(FactorBreakdown {
        name: "step_efficiency".into(),
        score: step_score,
        weight: 0.10,
        contribution: step_score * 0.10,
        explanation: format!(
            "{} step(s) — {}",
            step_count,
            if step_count <= 2 {
                "concise chain".to_string()
            } else if step_count <= 5 {
                "moderate complexity".to_string()
            } else {
                "complex multi-step attack".to_string()
            }
        ),
        confidence: 0.95,
    });

    factors
}

/// Cross-validate between subsystems.
fn cross_validate(
    preconditions: &PreconditionResult,
    state: &StateValidationResult,
    economic: &EconomicValidationResult,
) -> CrossValidation {
    let mut conflicts = Vec::new();
    let mut corroborations = Vec::new();

    // Conflict: preconditions say satisfied but state says invalid
    if preconditions.all_satisfied && !state.all_valid {
        conflicts.push("Preconditions satisfied but state transitions are invalid — possible hidden constraint".into());
    }

    // Conflict: state valid but economically impossible
    if state.all_valid && !economic.economically_viable {
        conflicts.push(
            "State transitions valid but economics don't work — attack may be unprofitable".into(),
        );
    }

    // Corroboration: all systems agree
    if preconditions.all_satisfied && state.all_valid && economic.economically_viable {
        corroborations.push(
            "All subsystems agree: preconditions met, state reachable, economically viable".into(),
        );
    }

    if preconditions.all_satisfied && state.all_valid && !economic.economically_viable {
        corroborations.push(
            "Structurally valid but economically unviable — technical feasibility confirmed".into(),
        );
    }

    if preconditions.missing > 0 && state.invalid_count > 0 {
        corroborations.push(
            "Missing preconditions correlate with invalid state transitions — consistent picture"
                .into(),
        );
    }

    let consistency = if conflicts.is_empty() {
        1.0
    } else {
        (1.0 - conflicts.len() as f64 * 0.2).max(0.0)
    };

    CrossValidation {
        conflicts,
        corroborations,
        consistency,
    }
}

/// Generate detailed explanation.
fn generate_detailed_explanation(
    breakdown: &[FactorBreakdown],
    cross_validation: &CrossValidation,
    overall: f64,
) -> String {
    let mut parts = Vec::new();

    parts.push(format!("Overall feasibility: {:.0}%", overall * 100.0));

    // Find strongest and weakest factors
    if let Some(strongest) = breakdown.iter().max_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    }) {
        parts.push(format!(
            "Strongest factor: {} ({:.0}%)",
            strongest.name,
            strongest.score * 100.0
        ));
    }
    if let Some(weakest) = breakdown.iter().min_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    }) {
        parts.push(format!(
            "Weakest factor: {} ({:.0}%)",
            weakest.name,
            weakest.score * 100.0
        ));
    }

    // Cross-validation
    if !cross_validation.conflicts.is_empty() {
        parts.push(format!(
            "Conflicts: {}",
            cross_validation.conflicts.join("; ")
        ));
    }
    if !cross_validation.corroborations.is_empty() {
        parts.push(format!(
            "Corroborations: {}",
            cross_validation.corroborations[0]
        ));
    }

    parts.join("; ")
}

/// Compute extended feasibility with full breakdown.
pub fn score_feasibility_extended(
    chain: &ExploitChain,
    precondition_result: &PreconditionResult,
    state_result: &StateValidationResult,
    economic_result: &EconomicValidationResult,
) -> ExtendedFeasibilityResult {
    let breakdown =
        compute_factor_breakdown(chain, precondition_result, state_result, economic_result);
    let cross_validation = cross_validate(precondition_result, state_result, economic_result);

    let overall: f64 = breakdown.iter().map(|f| f.contribution).sum();
    let overall = overall.clamp(0.0, 1.0);
    let adjusted = overall * 0.9 + cross_validation.consistency * 0.1;
    let adjusted = adjusted.clamp(0.0, 1.0);

    let verdict = match adjusted {
        x if x >= 0.8 => FeasibilityVerdict::HighlyFeasible,
        x if x >= 0.6 => FeasibilityVerdict::Feasible,
        x if x >= 0.4 => FeasibilityVerdict::PossiblyFeasible,
        x if x >= 0.2 => FeasibilityVerdict::Unlikely,
        _ => FeasibilityVerdict::Infeasible,
    };

    let mut risk_factors = Vec::new();
    for f in &breakdown {
        if f.score < 0.3 && f.weight >= 0.10 {
            risk_factors.push(format!(
                "Low {}: {:.0}% — {}",
                f.name,
                f.score * 100.0,
                f.explanation
            ));
        }
    }

    let factor_scores: Vec<f64> = breakdown.iter().map(|f| f.score).collect();
    let mean = factor_scores.iter().sum::<f64>() / factor_scores.len() as f64;
    let variance = factor_scores
        .iter()
        .map(|s| (s - mean).powi(2))
        .sum::<f64>()
        / factor_scores.len() as f64;
    let std_dev = variance.sqrt();

    let explanation = generate_detailed_explanation(&breakdown, &cross_validation, adjusted);

    ExtendedFeasibilityResult {
        base: FeasibilityScore {
            chain_id: chain.chain_id.clone(),
            overall: adjusted,
            components: FeasibilityComponents {
                precondition_score: breakdown
                    .iter()
                    .find(|f| f.name == "preconditions")
                    .map(|f| f.score)
                    .unwrap_or(0.0),
                state_reachability: breakdown
                    .iter()
                    .find(|f| f.name == "state_reachability")
                    .map(|f| f.score)
                    .unwrap_or(0.0),
                invariant_violations: breakdown
                    .iter()
                    .find(|f| f.name == "invariant_violations")
                    .map(|f| f.score)
                    .unwrap_or(0.0),
                trust_boundary_score: breakdown
                    .iter()
                    .find(|f| f.name == "trust_boundaries")
                    .map(|f| f.score)
                    .unwrap_or(0.0),
                economic_viability: breakdown
                    .iter()
                    .find(|f| f.name == "economic_viability")
                    .map(|f| f.score)
                    .unwrap_or(0.0),
                assumption_violations: breakdown
                    .iter()
                    .find(|f| f.name == "assumption_support")
                    .map(|f| f.score)
                    .unwrap_or(0.0),
                evidence_quality: breakdown
                    .iter()
                    .find(|f| f.name == "evidence_quality")
                    .map(|f| f.score)
                    .unwrap_or(0.0),
                step_efficiency: breakdown
                    .iter()
                    .find(|f| f.name == "step_efficiency")
                    .map(|f| f.score)
                    .unwrap_or(0.0),
            },
            explanation,
            verdict,
        },
        factors: breakdown,
        cross_validation,
        risk_factors,
        confidence_range: ((adjusted - std_dev).max(0.0), (adjusted + std_dev).min(1.0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_test_chain() -> ExploitChain {
        ExploitChain {
            chain_id: "test".into(),
            goal: "DrainAssets".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::Execution,
                function: "withdraw".into(),
                action: "call withdraw".into(),
                required_capability: ExploitCapability::TransferAssets,
                affected_state: vec!["balance".into()],
                affected_assets: vec!["USDC".into()],
                prerequisites: vec![],
                mutations: vec!["reduce balance".into()],
                evidence_refs: vec!["test:evidence".into()],
                confidence: 0.7,
                explanation: "no auth check".into(),
            }],
            required_capabilities: vec![ExploitCapability::TransferAssets],
            assumptions: vec![],
            violated_invariants: vec!["balance".into()],
            evidence_provenance: vec![
                EvidenceReference {
                    kind: EvidenceRefKind::AuditFinding,
                    ref_id: "f1".into(),
                    source: "audit".into(),
                    derivation: "test".into(),
                },
                EvidenceReference {
                    kind: EvidenceRefKind::GraphAnalysis,
                    ref_id: "g1".into(),
                    source: "graph".into(),
                    derivation: "test".into(),
                },
            ],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        }
    }

    fn make_test_preconditions(satisfied: usize, missing: usize) -> PreconditionResult {
        let mut preconditions = Vec::new();
        for i in 0..satisfied {
            preconditions.push(crate::preconditions::Precondition {
                kind: crate::preconditions::PreconditionKind::Permission,
                description: format!("precondition {}", i),
                status: crate::preconditions::PreconditionStatus::Satisfied,
                evidence: vec![],
                step_index: None,
            });
        }
        for i in 0..missing {
            preconditions.push(crate::preconditions::Precondition {
                kind: crate::preconditions::PreconditionKind::Permission,
                description: format!("missing {}", i),
                status: crate::preconditions::PreconditionStatus::Missing,
                evidence: vec![],
                step_index: None,
            });
        }
        PreconditionResult {
            chain_id: "test".into(),
            preconditions,
            satisfied,
            missing,
            unknown: 0,
            all_satisfied: missing == 0,
        }
    }

    #[test]
    fn test_feasibility_breakdown() {
        let chain = make_test_chain();
        let preconditions = make_test_preconditions(3, 0);
        let state = StateValidationResult {
            chain_id: "test".into(),
            transitions: vec![],
            all_valid: true,
            valid_count: 1,
            invalid_count: 0,
        };
        let economic = EconomicValidationResult {
            chain_id: "test".into(),
            step_flows: vec![],
            estimated_gain: BTreeMap::new(),
            estimated_cost: BTreeMap::new(),
            net_profit: BTreeMap::new(),
            value_conserved: true,
            economically_viable: false,
            conservation_violations: vec![],
            explanation: "test".into(),
        };

        let result = score_feasibility_extended(&chain, &preconditions, &state, &economic);
        assert_eq!(result.factors.len(), 8);
        assert!(result.base.overall >= 0.0 && result.base.overall <= 1.0);
        assert!(result.confidence_range.0 <= result.confidence_range.1);
        assert!(!result.base.explanation.is_empty());
    }

    #[test]
    fn test_cross_validation_conflict() {
        let preconditions = make_test_preconditions(5, 0);
        let state = StateValidationResult {
            chain_id: "test".into(),
            transitions: vec![crate::state_validation::StateTransitionValidation {
                step_index: 0,
                valid: false,
                pre_state: BTreeMap::new(),
                post_state: BTreeMap::new(),
                changes: vec![],
                invalid_reason: Some("test".into()),
            }],
            all_valid: false,
            valid_count: 0,
            invalid_count: 1,
        };

        let economic = EconomicValidationResult {
            chain_id: "test".into(),
            step_flows: vec![],
            estimated_gain: BTreeMap::new(),
            estimated_cost: BTreeMap::new(),
            net_profit: BTreeMap::new(),
            value_conserved: true,
            economically_viable: true,
            conservation_violations: vec![],
            explanation: "test".into(),
        };

        let cv = cross_validate(&preconditions, &state, &economic);
        assert!(!cv.conflicts.is_empty());
        assert!(cv.consistency < 1.0);
    }

    #[test]
    fn test_cross_validation_corroboration() {
        let preconditions = make_test_preconditions(3, 0);
        let state = StateValidationResult {
            chain_id: "test".into(),
            transitions: vec![],
            all_valid: true,
            valid_count: 0,
            invalid_count: 0,
        };
        let economic = EconomicValidationResult {
            chain_id: "test".into(),
            step_flows: vec![],
            estimated_gain: BTreeMap::new(),
            estimated_cost: BTreeMap::new(),
            net_profit: BTreeMap::new(),
            value_conserved: true,
            economically_viable: true,
            conservation_violations: vec![],
            explanation: "test".into(),
        };

        let cv = cross_validate(&preconditions, &state, &economic);
        assert!(!cv.corroborations.is_empty());
        assert!(cv.consistency >= 0.8);
    }
}
