/// Generation 3 — Exploit Synthesis Engine
///
/// Orchestrates the complete Gen 3 pipeline:
/// 1. Collect evidence from Gen 1/2 outputs
/// 2. Build capability graph
/// 3. Synthesize exploit chains
/// 4. Solve preconditions
/// 5. Validate state transitions
/// 6. Validate economics
/// 7. Score feasibility
/// 8. Eliminate infeasible chains
/// 9. Rank surviving chains
/// 10. Generate attack plans
/// 11. Generate simulation specs
/// 12. Generate explanations
use crate::attack_plan;
use crate::chain;
use crate::confirmation;
use crate::economic;
use crate::execution_engine;
use crate::execution_prep;
use crate::feasibility;
use crate::models::*;
use crate::preconditions;
use crate::ranking;
use crate::simulation;
use crate::simulation_plan;
use crate::state_validation;
use crate::validation;
use std::collections::BTreeMap;

use crate::attack_plan::DetailedAttackPlan;

/// Configuration for the synthesis engine.
#[derive(Debug, Clone)]
pub struct SynthesisConfig {
    /// Maximum chains to synthesize.
    pub max_chains: usize,
    /// Maximum steps per chain.
    pub max_steps: usize,
    /// Minimum confidence threshold for viable chains.
    pub min_confidence: f64,
    /// Whether to run full simulation.
    pub simulate: bool,
}

impl Default for SynthesisConfig {
    fn default() -> Self {
        Self {
            max_chains: 50,
            max_steps: 10,
            min_confidence: 0.3,
            simulate: true,
        }
    }
}

/// Inputs to the synthesis engine from Gen 1/2.
pub struct SynthesisInputs<'a> {
    /// SystemIR from the parser.
    pub ir: Option<&'a digger_ir::SystemIR>,
    /// Executed operations from Gen 2.
    pub expansion: Option<&'a digger_expansion::ExpansionReport>,
    /// State transitions.
    pub transitions: Option<&'a digger_state_transitions::StateTransitionReport>,
    /// Resource lifecycle.
    pub lifecycles: Option<&'a digger_resource_lifecycle::ResourceLifecycleReport>,
    /// Temporal analysis.
    pub temporal: Option<&'a digger_temporal::TemporalReport>,
    /// Actor analysis.
    pub actors: Option<&'a digger_actors::MultiActorReport>,
    /// Economic analysis.
    pub economics: Option<&'a digger_economics::EconomicReport>,
    /// Verification properties.
    pub verification: Option<&'a digger_verification::VerificationReport>,
    /// Adversarial capability report.
    pub adversarial: Option<&'a digger_adversarial::CapabilityReport>,
    /// Protocol analysis.
    pub protocol: Option<&'a digger_gen2_protocol::ProtocolIR>,
    /// Security intelligence output.
    pub surface: Option<&'a digger_surface::SecurityIntelligenceOutput>,
}

/// Run the complete Gen 3 synthesis pipeline.
pub fn synthesize(inputs: &SynthesisInputs, config: &SynthesisConfig) -> ExploitSearchReport {
    let protocol_id = inputs
        .ir
        .as_ref()
        .map(|ir| ir.program_id.clone())
        .unwrap_or_default();

    // 1. Build capability graph from all Gen 2 outputs
    let capability_graph = chain::build_capability_graph(inputs);

    // 2. Synthesize candidate exploit chains
    let mut chains = chain::synthesize_chains(inputs, &capability_graph, config);

    // 3. Validate each chain through the full pipeline
    let mut viable_chains = Vec::new();
    let mut eliminated_count = 0;

    for chain in chains.drain(..) {
        // 3a. Solve preconditions
        let preconditions = preconditions::solve_preconditions(&chain, inputs);

        // 3b. Validate state transitions
        let state_validation = state_validation::validate_state_transitions(&chain, inputs);

        // 3c. Validate economics
        let economic_validation = economic::validate_economics(&chain, inputs);

        // 3d. Score feasibility
        let feasibility_score = feasibility::score_feasibility(
            &chain,
            &preconditions,
            &state_validation,
            &economic_validation,
        );

        // 3e. Skip chains that are infeasible
        if matches!(feasibility_score.verdict, FeasibilityVerdict::Infeasible) {
            eliminated_count += 1;
            continue;
        }

        // 3f. Run simulation (logical state evolution)
        let sim = simulation::simulate_chain(&chain, inputs);

        // 3g. If simulation fails, reduce confidence
        let mut chain = chain;
        if !sim.success {
            chain.confidence *= 0.3;
        }

        // 3h. If precondition score is very low, eliminate
        if !preconditions.preconditions.is_empty()
            && feasibility_score.components.precondition_score < 0.3
        {
            eliminated_count += 1;
            continue;
        }

        viable_chains.push((chain, preconditions, feasibility_score));
    }

    // 4. Sort viable by feasibility score descending
    viable_chains.sort_by(|a, b| {
        b.2.overall
            .partial_cmp(&a.2.overall)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.chain_id.cmp(&b.0.chain_id))
    });

    // 5. Take top chains
    let viable_count = viable_chains.len();
    let top_count = viable_count.min(10);
    let top: Vec<_> = viable_chains.into_iter().take(top_count).collect();

    // 6. Generate outputs for top chains
    let mut rankings: Vec<ExploitRanking> = top
        .iter()
        .enumerate()
        .map(|(i, (chain, _, feasibility))| ExploitRanking {
            chain_id: chain.chain_id.clone(),
            score: feasibility.overall,
            factors: ranking::compute_ranking_factors(chain),
            rank: i + 1,
        })
        .collect();

    let explanations: Vec<ExploitExplanation> = top
        .iter()
        .map(|(chain, _, _)| ranking::explain_chain(chain, inputs))
        .collect();

    let simulations: Vec<ExploitSimulation> = top
        .iter()
        .map(|(chain, _, _)| simulation::simulate_chain(chain, inputs))
        .collect();

    let attack_plans: Vec<AttackPlan> = top
        .iter()
        .map(|(chain, preconditions, feasibility)| {
            attack_plan::generate_attack_plan(chain, preconditions, feasibility)
        })
        .collect();

    let detailed_plans: Vec<DetailedAttackPlan> = top
        .iter()
        .map(|(chain, preconditions, feasibility)| {
            attack_plan::generate_detailed_attack_plan(chain, preconditions, feasibility)
        })
        .collect();

    let simulation_specs: Vec<SimulationSpec> = detailed_plans
        .iter()
        .map(|plan| {
            let ext = simulation_plan::generate_foundry_spec(plan);
            ext.base
        })
        .collect();

    let feasibility_scores: Vec<FeasibilityScore> = top.iter().map(|(_, _, f)| f.clone()).collect();

    // 7. Run validation on each viable chain
    let validation_reports: Vec<ValidationReport> = top
        .iter()
        .map(|(chain, _, _)| validation::validate_exploit(chain, inputs))
        .collect();

    // 8. Generate execution packages for validated chains
    let execution_packages: Vec<ExecutionPackage> = top
        .iter()
        .zip(validation_reports.iter())
        .map(|((chain, _, _), vr)| execution_prep::prepare_execution(chain, vr, inputs))
        .collect();

    // 9. Adjust scores based on validation
    for (i, report) in validation_reports.iter().enumerate() {
        if i < rankings.len() {
            rankings[i].score = rankings[i].score * 0.7 + report.validation_score * 0.3;
        }
    }
    // Re-sort after validation adjustment
    rankings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.chain_id.cmp(&b.chain_id))
    });
    for (i, ranking) in rankings.iter_mut().enumerate() {
        ranking.rank = i + 1;
    }

    // 10. Execute validated chains (Gen 4)
    let exec_config = execution_engine::ExecutionConfig::default();
    let execution_transcripts: Vec<ExecutionTranscript> = execution_packages
        .iter()
        .map(|pkg| execution_engine::execute_exploit(pkg, &exec_config))
        .collect();

    // 11. Differential analysis
    let differential_analyses: Vec<DifferentialAnalysis> = top
        .iter()
        .zip(execution_transcripts.iter())
        .map(|((chain, _, _), transcript)| {
            let invariants = chain.violated_invariants.clone();
            crate::differential::analyze_differential(
                transcript,
                &BTreeMap::new(),
                &BTreeMap::new(),
                &BTreeMap::new(),
                &invariants,
            )
        })
        .collect();

    // 12. Confirm exploits
    let confirmations: Vec<ExecutionConfirmation> = top
        .iter()
        .zip(execution_transcripts.iter())
        .zip(differential_analyses.iter())
        .map(|(((chain, _, _), transcript), diff)| {
            confirmation::confirm_exploit(transcript, diff, chain)
        })
        .collect();

    // 13. Final score adjustment based on confirmation
    for (i, conf) in confirmations.iter().enumerate() {
        if i < rankings.len() {
            let conf_bonus = match conf.status {
                ConfirmationStatus::Verified => 0.15,
                ConfirmationStatus::VerifiedWithCaveats => 0.10,
                ConfirmationStatus::PartialSuccess => 0.05,
                _ => -0.05,
            };
            rankings[i].score = (rankings[i].score + conf_bonus).clamp(0.0, 1.0);
        }
    }
    rankings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.chain_id.cmp(&b.chain_id))
    });
    for (i, ranking) in rankings.iter_mut().enumerate() {
        ranking.rank = i + 1;
    }

    // 14. Assemble report
    let confirmed_count = confirmations
        .iter()
        .filter(|c| {
            matches!(
                c.status,
                ConfirmationStatus::Verified | ConfirmationStatus::VerifiedWithCaveats
            )
        })
        .count();

    ExploitSearchReport {
        protocol_id,
        total_chains: viable_count + eliminated_count,
        viable_chains: top.len(),
        eliminated_chains: eliminated_count,
        rankings,
        explanations,
        simulations,
        attack_plans,
        simulation_specs,
        feasibility_scores,
        validation_reports,
        execution_packages,
        execution_transcripts,
        differential_analyses,
        confirmations,
        search_metadata: SearchMetadata {
            search_steps: (viable_count + eliminated_count) * 4 + top.len() * 3,
            pruning_ops: eliminated_count,
            elimination_checks: viable_count + eliminated_count,
            search_explanation: format!(
                "Synthesized {} candidates, eliminated {}, {} viable, {} confirmed",
                viable_count + eliminated_count,
                eliminated_count,
                top.len(),
                confirmed_count
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_inputs() -> SynthesisInputs<'static> {
        SynthesisInputs {
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
        }
    }

    fn populated_inputs() -> SynthesisInputs<'static> {
        let ir = Box::leak(Box::new(digger_ir::SystemIR {
            program_id: "test_protocol".into(),
            language: digger_ir::Language::Solidity,
            functions: vec![digger_ir::Function {
                id: "fn_0".into(),
                name: "vulnerable_function".into(),
                contract: String::new(),
                visibility: digger_ir::Visibility::Public,
                inputs: vec![],
                outputs: vec![],
                modifiers: vec![],
                effects: digger_ir::Effects {
                    state_mutation: true,
                    external_call: true,
                    value_transfer: true,
                    authority_required: false,
                    has_arithmetic: false,
                    has_temporal_guard: false,
                    value_flow: None,
                    has_unchecked_arithmetic: false,
                    writes_caller_scoped_state: false,
                    has_precision_loss_ordering: false,
                },
            }],
            state: vec![digger_ir::StateVariable {
                id: "sv_0".into(),
                name: "totalSupply".into(),
                ty: "uint256".into(),
                mutable: true,
            }],
            edges: vec![digger_ir::Edge::Authority(digger_ir::AuthorityEdge {
                function: "vulnerable_function".into(),
                check_type: "missing".into(),
                authority_source: "none".into(),
            })],
        }));
        SynthesisInputs {
            ir: Some(ir),
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
        }
    }

    fn default_config() -> SynthesisConfig {
        SynthesisConfig::default()
    }

    #[test]
    fn test_synthesize_main_entry() {
        let report = synthesize(&empty_inputs(), &default_config());
        assert_eq!(report.protocol_id, "");
        assert!(report.viable_chains <= report.total_chains);
        assert!(report.search_metadata.search_steps > 0 || report.total_chains == 0);
    }

    #[test]
    fn test_synthesis_output_cannot_be_mistaken_for_engine_verdict() {
        let report = synthesize(&populated_inputs(), &default_config());

        assert!(
            !report.rankings.is_empty(),
            "populated inputs must produce >=1 ranking for non-vacuous guard"
        );

        for ranking in &report.rankings {
            assert!(
                ranking.score >= 0.0 && ranking.score <= 1.0,
                "ranking score must be in [0.0, 1.0], got {}",
                ranking.score
            );
        }

        for conf in &report.confirmations {
            match conf.status {
                ConfirmationStatus::Verified
                | ConfirmationStatus::VerifiedWithCaveats
                | ConfirmationStatus::PartialSuccess
                | ConfirmationStatus::Failed
                | ConfirmationStatus::FailedWithExplanation => {}
            }
            assert!(
                conf.confidence >= 0.0 && conf.confidence <= 1.0,
                "confirmation confidence must be in [0.0, 1.0], got {}",
                conf.confidence
            );
        }

        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("Graduated"),
            "full synthesis report JSON must not contain Graduated"
        );
        assert!(
            !json.contains("Confirmed"),
            "full synthesis report JSON must not contain Confirmed"
        );
    }

    #[test]
    fn test_synthesis_determinism() {
        let report1 = synthesize(&populated_inputs(), &default_config());
        let report2 = synthesize(&populated_inputs(), &default_config());

        assert!(
            !report1.rankings.is_empty(),
            "populated inputs must produce rankings for determinism test"
        );

        let json1 = serde_json::to_string(&report1).unwrap();
        let json2 = serde_json::to_string(&report2).unwrap();
        assert_eq!(
            json1, json2,
            "synthesize must produce byte-identical output for identical inputs"
        );
    }

    #[test]
    fn test_synthesis_round_trip() {
        let report = synthesize(&populated_inputs(), &default_config());

        assert!(
            !report.rankings.is_empty(),
            "populated inputs must produce rankings for round-trip test"
        );

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: ExploitSearchReport = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            json, json2,
            "ExploitSearchReport must survive JSON round-trip"
        );
    }
}
