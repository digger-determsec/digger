use crate::models::*;
/// Multi-Actor Reasoning Engine — how participants interact.
///
/// Identifies actor roles, detects shared state interactions,
/// and flags adversarial patterns.
///
/// Deterministic: same inputs → same output.
/// No AI, no inference, no heuristics.
/// Bounded: max 5 actors, max 100 interactions.
use digger_parser::model::*;
use digger_state_transitions::StateTransitionReport;
use digger_temporal::*;

/// Maximum interactions to detect per protocol.
const MAX_INTERACTIONS: usize = 100;

/// Analyze multi-actor interactions for a program.
pub fn analyze_actors(
    program: &RawProgram,
    _transitions: &StateTransitionReport,
    temporal: &TemporalReport,
    protocol_id: &str,
) -> MultiActorReport {
    // Step 1: Identify actors from function patterns
    let actors = identify_actors(program);

    // Step 2: Detect shared state interactions
    let interactions = detect_interactions(program, &actors, temporal);

    // Step 3: Detect adversarial patterns
    let adversarial_patterns = detect_adversarial_patterns(&actors, &interactions, temporal);

    // Step 4: Build summary
    let actors_with_adversarial_potential = adversarial_patterns
        .iter()
        .map(|p| p.attacker.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    let summary = MultiActorSummary {
        total_actors: actors.len(),
        total_interactions: interactions.len(),
        total_adversarial: adversarial_patterns.len(),
        actors_with_adversarial_potential,
    };

    MultiActorReport {
        protocol_id: protocol_id.into(),
        actors,
        interactions,
        adversarial_patterns,
        summary,
    }
}

/// Identify actors from function patterns.
fn identify_actors(program: &RawProgram) -> Vec<Actor> {
    let mut actors = Vec::new();

    // Collect all public functions
    let public_fns: Vec<String> = program
        .functions
        .iter()
        .filter(|f| f.visibility == "public" || f.visibility == "external")
        .map(|f| f.name.clone())
        .collect();

    // Infer roles from function names and patterns
    let mut admin_fns = Vec::new();
    let mut liquidator_fns = Vec::new();
    let mut governance_fns = Vec::new();
    let mut user_fns = Vec::new();

    for func in &program.functions {
        let name_lower = func.name.to_lowercase();

        if name_lower.contains("admin")
            || name_lower.contains("owner")
            || name_lower.contains("set")
            || name_lower.contains("upgrade")
            || name_lower.contains("pause")
            || name_lower.contains("config")
        {
            admin_fns.push(func.name.clone());
        } else if name_lower.contains("liquidat") {
            liquidator_fns.push(func.name.clone());
        } else if name_lower.contains("vote")
            || name_lower.contains("governance")
            || name_lower.contains("propose")
            || name_lower.contains("delegate")
        {
            governance_fns.push(func.name.clone());
        } else if func.visibility == "public" || func.visibility == "external" {
            user_fns.push(func.name.clone());
        }
    }

    // Collect affected state per role
    let all_state: Vec<String> = program.state.iter().map(|s| s.name.clone()).collect();

    if !admin_fns.is_empty() {
        actors.push(Actor {
            actor_id: "admin".into(),
            role: ActorRole::Admin,
            callable_functions: admin_fns.clone(),
            affected_state: all_state.clone(),
        });
    }

    if !liquidator_fns.is_empty() {
        actors.push(Actor {
            actor_id: "liquidator".into(),
            role: ActorRole::Liquidator,
            callable_functions: liquidator_fns.clone(),
            affected_state: all_state.clone(),
        });
    }

    if !governance_fns.is_empty() {
        actors.push(Actor {
            actor_id: "governance".into(),
            role: ActorRole::Governance,
            callable_functions: governance_fns.clone(),
            affected_state: all_state.clone(),
        });
    }

    // User actor always exists
    actors.push(Actor {
        actor_id: "user".into(),
        role: ActorRole::User,
        callable_functions: user_fns.clone(),
        affected_state: all_state.clone(),
    });

    // Attacker actor can call any public function
    actors.push(Actor {
        actor_id: "attacker".into(),
        role: ActorRole::Attacker,
        callable_functions: public_fns,
        affected_state: all_state,
    });

    actors.sort_by(|a, b| a.actor_id.cmp(&b.actor_id));
    actors
}

/// Detect shared state interactions between actors.
fn detect_interactions(
    program: &RawProgram,
    actors: &[Actor],
    _temporal: &TemporalReport,
) -> Vec<ActorInteraction> {
    let mut interactions = Vec::new();

    // Group operations by function
    let mut func_ops: std::collections::BTreeMap<String, Vec<&RawOperation>> =
        std::collections::BTreeMap::new();
    for op in &program.operations {
        func_ops.entry(op.function.clone()).or_default().push(op);
    }

    // For each actor's function, check if it affects state that other actors' functions use
    for actor in actors {
        for func_name in &actor.callable_functions {
            let ops = func_ops
                .get(func_name.as_str())
                .cloned()
                .unwrap_or_default();

            let writes: Vec<String> = ops
                .iter()
                .filter(|o| o.kind == OperationKind::StateWrite)
                .map(|o| o.target.clone())
                .collect();

            if writes.is_empty() {
                continue;
            }

            // Find other actors affected by these writes
            let mut affected_actors = Vec::new();
            for other_actor in actors {
                if other_actor.actor_id == actor.actor_id {
                    continue;
                }
                for other_func in &other_actor.callable_functions {
                    let other_ops = func_ops
                        .get(other_func.as_str())
                        .cloned()
                        .unwrap_or_default();
                    let other_reads: Vec<String> = other_ops
                        .iter()
                        .filter(|o| o.kind == OperationKind::StateRead)
                        .map(|o| o.target.clone())
                        .collect();

                    // Check if other actor reads any state that this actor writes
                    let shared: Vec<String> = writes
                        .iter()
                        .filter(|w| other_reads.contains(w))
                        .cloned()
                        .collect();

                    if !shared.is_empty() && !affected_actors.contains(&other_actor.actor_id) {
                        affected_actors.push(other_actor.actor_id.clone());
                    }
                }
            }

            if !affected_actors.is_empty() {
                let kind = classify_interaction(func_name, program);

                interactions.push(ActorInteraction {
                    actor: actor.actor_id.clone(),
                    function: func_name.clone(),
                    affected_state: writes.clone(),
                    affected_actors,
                    is_adversarial: actor.role == ActorRole::Attacker,
                    kind,
                });
            }
        }
    }

    // Sort for deterministic output
    interactions.sort_by(|a, b| a.actor.cmp(&b.actor).then(a.function.cmp(&b.function)));

    // Bound
    interactions.truncate(MAX_INTERACTIONS);

    interactions
}

/// Classify the kind of interaction based on function name.
fn classify_interaction(func_name: &str, _program: &RawProgram) -> InteractionKind {
    let name_lower = func_name.to_lowercase();

    if name_lower.contains("liquidat") {
        InteractionKind::Liquidation
    } else if name_lower.contains("swap") || name_lower.contains("price") {
        InteractionKind::PriceManipulation
    } else if name_lower.contains("transfer")
        || name_lower.contains("withdraw")
        || name_lower.contains("deposit")
        || name_lower.contains("send")
    {
        InteractionKind::AssetTransfer
    } else if name_lower.contains("config")
        || name_lower.contains("set")
        || name_lower.contains("upgrade")
        || name_lower.contains("pause")
    {
        InteractionKind::ConfigurationChange
    } else {
        InteractionKind::StateModification
    }
}

/// Detect adversarial patterns from actors and interactions.
fn detect_adversarial_patterns(
    actors: &[Actor],
    interactions: &[ActorInteraction],
    temporal: &TemporalReport,
) -> Vec<AdversarialPattern> {
    let mut patterns = Vec::new();

    // Find the attacker actor
    let attacker = actors.iter().find(|a| a.role == ActorRole::Attacker);

    if let Some(attacker) = attacker {
        // Check each interaction for adversarial potential
        for interaction in interactions {
            if interaction.actor != attacker.actor_id {
                continue;
            }

            // Check if attacker's interaction affects other actors
            for affected in &interaction.affected_actors {
                // Pattern 1: State manipulation — attacker writes state that others read
                for state_var in &interaction.affected_state {
                    patterns.push(AdversarialPattern {
                        kind: AdversarialKind::StateManipulation,
                        attacker: attacker.actor_id.clone(),
                        victim: affected.clone(),
                        function: interaction.function.clone(),
                        state_var: state_var.clone(),
                        severity: digger_ir::Severity::High,
                    });
                }

                // Pattern 2: Front-running — if temporal dependencies exist
                // between attacker's function and victim's function
                for dep in &temporal.dependencies {
                    if dep.predecessor == interaction.function {
                        patterns.push(AdversarialPattern {
                            kind: AdversarialKind::FrontRunning,
                            attacker: attacker.actor_id.clone(),
                            victim: affected.clone(),
                            function: interaction.function.clone(),
                            state_var: dep.state_var.clone(),
                            severity: digger_ir::Severity::High,
                        });
                    }
                }
            }
        }
    }

    // Sort for deterministic output
    patterns.sort_by(|a, b| {
        a.kind
            .to_string()
            .cmp(&b.kind.to_string())
            .then(a.attacker.cmp(&b.attacker))
            .then(a.victim.cmp(&b.victim))
    });

    // Deduplicate
    patterns.dedup_by(|a, b| {
        a.kind == b.kind
            && a.attacker == b.attacker
            && a.victim == b.victim
            && a.state_var == b.state_var
    });

    patterns
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
pub fn report_to_json(report: &MultiActorReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
}

/// Deserialize report from JSON.
pub fn report_from_json(json: &str) -> Result<MultiActorReport, AnalysisError> {
    Ok(serde_json::from_str(json)?)
}
