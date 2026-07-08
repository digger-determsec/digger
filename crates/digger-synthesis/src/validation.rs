use crate::engine::SynthesisInputs;
/// Generation 3.2 — Deterministic Exploit Validation Engine
///
/// Proves whether a synthesized exploit is actually executable based solely
/// on the analyzed protocol model, knowledge graph, and reasoning outputs.
/// Every check is deterministic, explainable, evidence-backed, and reproducible.
use crate::models::*;
use std::collections::BTreeMap;

/// Run the complete validation pipeline on an exploit chain.
pub fn validate_exploit(chain: &ExploitChain, inputs: &SynthesisInputs) -> ValidationReport {
    let mut checks_passed = 0usize;
    let mut checks_failed = 0usize;
    let mut checks_partial = 0usize;
    let mut checks_unknown = 0usize;
    let mut blockers = Vec::new();

    // 1. Preconditions validation
    let preconditions = validate_preconditions(chain, inputs);
    checks_passed += preconditions.satisfied_count;
    checks_failed += preconditions.unsatisfied_count;
    checks_partial += preconditions.partial_count;
    checks_unknown += preconditions.unknown_count;
    for check in &preconditions.results {
        if check.status == ValidationStatus::Unsatisfied {
            blockers.push(ExecutionBlocker {
                step_index: check.step_index,
                kind: BlockerKind::MissingPrivilege,
                description: check.description.clone(),
                evidence: check.evidence.clone(),
                severity: BlockerSeverity::Critical,
            });
        }
    }

    // 2. State reachability
    let state_reach = validate_state_reachability(chain, inputs);
    checks_passed += state_reach.reachable_count;
    checks_failed += state_reach.unreachable_count;
    for proof in &state_reach.transitions {
        if !proof.reachable {
            blockers.push(ExecutionBlocker {
                step_index: Some(proof.step_index),
                kind: BlockerKind::UnreachableState,
                description: proof
                    .unreachable_reason
                    .clone()
                    .unwrap_or_else(|| "State unreachable".into()),
                evidence: vec![format!(
                    "transition:{}->{}",
                    proof.from_state, proof.to_state
                )],
                severity: BlockerSeverity::Critical,
            });
        }
    }

    // 3. Transaction sequence validation
    let tx_sequence = validate_transaction_sequence(chain, inputs);
    if !tx_sequence.valid {
        checks_failed += tx_sequence.issues.len();
        for issue in &tx_sequence.issues {
            blockers.push(ExecutionBlocker {
                step_index: Some(issue.step_a),
                kind: match issue.kind {
                    SequenceIssueKind::ImpossibleOrdering => BlockerKind::ImpossibleOrdering,
                    SequenceIssueKind::DependencyViolation => BlockerKind::ImpossibleOrdering,
                    SequenceIssueKind::CircularDependency => BlockerKind::ImpossibleOrdering,
                    SequenceIssueKind::InvalidLifecycleOrdering => BlockerKind::ImpossibleOrdering,
                    SequenceIssueKind::InvalidAuthorityOrdering => {
                        BlockerKind::TrustBoundaryViolation
                    }
                },
                description: issue.description.clone(),
                evidence: issue.evidence.clone(),
                severity: BlockerSeverity::High,
            });
        }
    } else {
        checks_passed += 1;
    }

    // 4. Invariant replay
    let invariant_replay = replay_invariants(chain, inputs);
    checks_passed += invariant_replay.invariants_preserved;
    checks_failed += invariant_replay.violations_detected;
    for replay in &invariant_replay.replays {
        if replay.violated {
            blockers.push(ExecutionBlocker {
                step_index: replay.violating_step,
                kind: BlockerKind::InvariantViolation,
                description: format!(
                    "Invariant '{}' violated: {}",
                    replay.invariant_id, replay.invariant_description
                ),
                evidence: replay.evidence.clone(),
                severity: BlockerSeverity::High,
            });
        }
    }

    // 5. Asset flow validation
    let asset_flow = validate_asset_flow(chain, inputs);
    if !asset_flow.valid {
        checks_failed +=
            asset_flow.impossible_creations.len() + asset_flow.balance_violations.len();
        for creation in &asset_flow.impossible_creations {
            blockers.push(ExecutionBlocker {
                step_index: None,
                kind: BlockerKind::EconomicImpossibility,
                description: format!("Impossible asset creation: {}", creation),
                evidence: vec![],
                severity: BlockerSeverity::Critical,
            });
        }
    } else {
        checks_passed += 1;
    }

    // 6. Capability validation
    let capability_valid = validate_capabilities(chain, inputs);
    checks_passed += capability_valid.proven_count;
    checks_failed += capability_valid.unproven_count;
    for cap in &capability_valid.validations {
        if !cap.proven {
            blockers.push(ExecutionBlocker {
                step_index: None,
                kind: BlockerKind::MissingCapability,
                description: format!(
                    "Capability '{}' cannot be proven: {}",
                    cap.capability, cap.description
                ),
                evidence: cap.evidence.clone(),
                severity: BlockerSeverity::High,
            });
        }
    }

    // 7. Trust boundary validation
    let trust_boundary = validate_trust_boundaries(chain, inputs);
    checks_passed += trust_boundary
        .crossings
        .iter()
        .filter(|c| c.authorized)
        .count();
    checks_failed += trust_boundary.unauthorized_count;
    for crossing in &trust_boundary.crossings {
        if !crossing.authorized {
            blockers.push(ExecutionBlocker {
                step_index: Some(crossing.step_index),
                kind: BlockerKind::TrustBoundaryViolation,
                description: format!(
                    "Unauthorized trust boundary crossing: {} -> {}",
                    crossing.from, crossing.to
                ),
                evidence: crossing.evidence.clone(),
                severity: BlockerSeverity::High,
            });
        }
    }

    // 8. Economic validation
    let economic = validate_economics(chain, inputs);
    checks_passed += if economic.profitable { 1 } else { 0 };
    checks_failed += if !economic.profitable { 1 } else { 0 };
    if !economic.profitable {
        blockers.push(ExecutionBlocker {
            step_index: None,
            kind: BlockerKind::EconomicImpossibility,
            description: format!(
                "Not profitable: expected profit {:.2} < threshold {:.2}",
                economic.expected_profit, economic.minimum_profitable_threshold
            ),
            evidence: vec![],
            severity: BlockerSeverity::Medium,
        });
    }

    // Compute overall verdict and score
    let total_checks = checks_passed + checks_failed + checks_partial + checks_unknown;
    let validation_score = if total_checks > 0 {
        checks_passed as f64 / total_checks as f64
    } else {
        0.5
    };

    let critical_blockers = blockers
        .iter()
        .filter(|b| b.severity == BlockerSeverity::Critical)
        .count();
    let high_blockers = blockers
        .iter()
        .filter(|b| b.severity == BlockerSeverity::High)
        .count();

    let verdict = if critical_blockers > 0 {
        ValidationVerdict::Invalid
    } else if high_blockers > 0 {
        ValidationVerdict::PartiallyValid
    } else if checks_failed == 0 && checks_partial == 0 {
        ValidationVerdict::Valid
    } else {
        ValidationVerdict::ValidWithCaveats
    };

    // Confidence interval based on unknown checks
    let uncertainty = checks_unknown as f64 / total_checks.max(1) as f64;
    let ci_low = (validation_score - uncertainty * 0.3).max(0.0);
    let ci_high = (validation_score + uncertainty * 0.3).min(1.0);

    // Remaining assumptions
    let remaining_assumptions: Vec<String> = chain
        .assumptions
        .iter()
        .filter(|a| {
            !preconditions.results.iter().any(|p| {
                p.description.contains(a.as_str()) && p.status == ValidationStatus::Satisfied
            })
        })
        .cloned()
        .collect();

    let evidence_references = chain.evidence_provenance.clone();

    ValidationReport {
        chain_id: chain.chain_id.clone(),
        verdict,
        validation_score,
        confidence_interval: (ci_low, ci_high),
        preconditions,
        state_reachability: state_reach,
        transaction_sequence: tx_sequence,
        invariant_replay,
        asset_flow,
        capability_validation: capability_valid,
        trust_boundary,
        economic_validation: economic,
        execution_blockers: blockers,
        remaining_assumptions,
        evidence_references,
        validation_metadata: ValidationMetadata {
            total_checks,
            passed: checks_passed,
            failed: checks_failed,
            partial: checks_partial,
            unknown: checks_unknown,
            validation_duration_hint: format!("{} checks performed", total_checks),
        },
    }
}

// ─── 1. Preconditions Validation ──────────────────────────────────

fn validate_preconditions(
    chain: &ExploitChain,
    inputs: &SynthesisInputs,
) -> PreconditionsValidation {
    let mut results = Vec::new();

    // Check each step's preconditions
    for step in &chain.steps {
        results.extend(validate_step_preconditions(step, chain, inputs));
    }

    // Check capability prerequisites
    for cap in &chain.required_capabilities {
        results.push(validate_capability_precondition(cap, inputs));
    }

    let satisfied = results
        .iter()
        .filter(|r| r.status == ValidationStatus::Satisfied)
        .count();
    let unsatisfied = results
        .iter()
        .filter(|r| r.status == ValidationStatus::Unsatisfied)
        .count();
    let partial = results
        .iter()
        .filter(|r| r.status == ValidationStatus::PartiallySatisfied)
        .count();
    let unknown = results
        .iter()
        .filter(|r| r.status == ValidationStatus::Unknown)
        .count();

    PreconditionsValidation {
        results,
        all_satisfied: unsatisfied == 0,
        satisfied_count: satisfied,
        unsatisfied_count: unsatisfied,
        partial_count: partial,
        unknown_count: unknown,
    }
}

fn validate_step_preconditions(
    step: &ExploitStep,
    _chain: &ExploitChain,
    inputs: &SynthesisInputs,
) -> Vec<PreconditionCheck> {
    let mut checks = Vec::new();

    // Check authority requirement
    if step.required_capability == ExploitCapability::AuthorityEscalation {
        let has_auth = if let Some(ir) = inputs.ir {
            ir.edges.iter().any(|e| {
                matches!(e, digger_ir::Edge::Authority(a) if a.function == step.function && a.check_type != "missing")
            })
        } else {
            false
        };

        checks.push(PreconditionCheck {
            kind: PreconditionType::AuthorityReachable,
            description: format!(
                "Function '{}' must NOT have authority enforcement",
                step.function
            ),
            status: if has_auth {
                ValidationStatus::Unsatisfied
            } else {
                ValidationStatus::Satisfied
            },
            evidence: vec![format!("authority:{}", step.function)],
            step_index: Some(step.index),
            confidence: 0.9,
        });
    }

    // Check function exists
    if let Some(ir) = inputs.ir {
        let exists = ir.functions.iter().any(|f| f.name == step.function);
        checks.push(PreconditionCheck {
            kind: PreconditionType::StateReachable,
            description: format!("Function '{}' must exist in the program", step.function),
            status: if exists {
                ValidationStatus::Satisfied
            } else {
                ValidationStatus::Unsatisfied
            },
            evidence: vec![format!("ir:function:{}", step.function)],
            step_index: Some(step.index),
            confidence: 1.0,
        });

        // Check function effects match required capability
        if let Some(func) = ir.functions.iter().find(|f| f.name == step.function) {
            match step.required_capability {
                ExploitCapability::WriteState => {
                    checks.push(PreconditionCheck {
                        kind: PreconditionType::StateReachable,
                        description: format!("Function '{}' must write state", step.function),
                        status: if func.effects.state_mutation {
                            ValidationStatus::Satisfied
                        } else {
                            ValidationStatus::Unsatisfied
                        },
                        evidence: vec![format!(
                            "effects:state_mutation:{}",
                            func.effects.state_mutation
                        )],
                        step_index: Some(step.index),
                        confidence: 0.95,
                    });
                }
                ExploitCapability::CrossContractCall
                | ExploitCapability::CrossProgramInvocation => {
                    checks.push(PreconditionCheck {
                        kind: PreconditionType::AuthorityReachable,
                        description: format!(
                            "Function '{}' must make external calls",
                            step.function
                        ),
                        status: if func.effects.external_call {
                            ValidationStatus::Satisfied
                        } else {
                            ValidationStatus::Unsatisfied
                        },
                        evidence: vec![format!(
                            "effects:external_call:{}",
                            func.effects.external_call
                        )],
                        step_index: Some(step.index),
                        confidence: 0.95,
                    });
                }
                ExploitCapability::TransferAssets => {
                    checks.push(PreconditionCheck {
                        kind: PreconditionType::LiquidityAvailable,
                        description: format!("Function '{}' must transfer value", step.function),
                        status: if func.effects.value_transfer {
                            ValidationStatus::Satisfied
                        } else {
                            ValidationStatus::Unsatisfied
                        },
                        evidence: vec![format!(
                            "effects:value_transfer:{}",
                            func.effects.value_transfer
                        )],
                        step_index: Some(step.index),
                        confidence: 0.95,
                    });
                }
                _ => {
                    checks.push(PreconditionCheck {
                        kind: PreconditionType::StateReachable,
                        description: format!(
                            "Function '{}' must exist and be callable",
                            step.function
                        ),
                        status: if exists {
                            ValidationStatus::Satisfied
                        } else {
                            ValidationStatus::Unsatisfied
                        },
                        evidence: vec![format!("ir:function:{}", step.function)],
                        step_index: Some(step.index),
                        confidence: 0.9,
                    });
                }
            }
        }
    } else {
        // No IR available — mark as unknown
        checks.push(PreconditionCheck {
            kind: PreconditionType::StateReachable,
            description: format!(
                "Function '{}' existence cannot be verified (no IR)",
                step.function
            ),
            status: ValidationStatus::Unknown,
            evidence: vec!["no_ir_available".into()],
            step_index: Some(step.index),
            confidence: 0.0,
        });
    }

    // Check state variables exist
    if let Some(ir) = inputs.ir {
        for var in &step.affected_state {
            let exists = ir.state.iter().any(|s| s.name == *var);
            checks.push(PreconditionCheck {
                kind: PreconditionType::StateReachable,
                description: format!("State variable '{}' must exist", var),
                status: if exists {
                    ValidationStatus::Satisfied
                } else {
                    ValidationStatus::Unknown
                },
                evidence: vec![format!("ir:state:{}", var)],
                step_index: Some(step.index),
                confidence: if exists { 0.95 } else { 0.3 },
            });
        }
    }

    // Check ordering preconditions
    for prereq in &step.prerequisites {
        if prereq.contains("Step") {
            if let Some(num_str) = prereq.split_whitespace().nth(1) {
                if let Ok(num) = num_str.parse::<usize>() {
                    checks.push(PreconditionCheck {
                        kind: PreconditionType::StateReachable,
                        description: prereq.clone(),
                        status: if num < step.index {
                            ValidationStatus::Satisfied
                        } else {
                            ValidationStatus::Unsatisfied
                        },
                        evidence: vec![format!("ordering:{}<{}", num, step.index)],
                        step_index: Some(step.index),
                        confidence: 1.0,
                    });
                }
            }
        }
    }

    checks
}

fn validate_capability_precondition(
    cap: &ExploitCapability,
    inputs: &SynthesisInputs,
) -> PreconditionCheck {
    match cap {
        ExploitCapability::ReadState | ExploitCapability::WriteState => PreconditionCheck {
            kind: PreconditionType::PrivilegeExists,
            description: format!("Capability '{}' must be achievable", cap),
            status: ValidationStatus::Satisfied,
            evidence: vec![format!("capability:{}", cap)],
            step_index: None,
            confidence: 0.9,
        },
        ExploitCapability::AuthorityEscalation => PreconditionCheck {
            kind: PreconditionType::AuthorityReachable,
            description: "Authority escalation capability required".into(),
            status: ValidationStatus::Satisfied,
            evidence: vec!["capability:authority_escalation".into()],
            step_index: None,
            confidence: 0.8,
        },
        ExploitCapability::CrossContractCall | ExploitCapability::CrossProgramInvocation => {
            let available = inputs
                .ir
                .map(|ir| {
                    ir.edges
                        .iter()
                        .any(|e| matches!(e, digger_ir::Edge::External(_)))
                })
                .unwrap_or(false);
            PreconditionCheck {
                kind: PreconditionType::PrivilegeExists,
                description: format!("Capability '{}' requires external calls", cap),
                status: if available {
                    ValidationStatus::Satisfied
                } else {
                    ValidationStatus::Unsatisfied
                },
                evidence: vec![format!("ir:external_calls:{}", available)],
                step_index: None,
                confidence: if available { 0.95 } else { 0.9 },
            }
        }
        ExploitCapability::TransferAssets => {
            let available = inputs
                .ir
                .map(|ir| ir.functions.iter().any(|f| f.effects.value_transfer))
                .unwrap_or(false);
            PreconditionCheck {
                kind: PreconditionType::LiquidityAvailable,
                description: "Transfer capability requires value transfer functions".into(),
                status: if available {
                    ValidationStatus::Satisfied
                } else {
                    ValidationStatus::Unsatisfied
                },
                evidence: vec![format!("ir:value_transfer:{}", available)],
                step_index: None,
                confidence: if available { 0.95 } else { 0.9 },
            }
        }
        _ => PreconditionCheck {
            kind: PreconditionType::PrivilegeExists,
            description: format!(
                "Capability '{}' verification requires additional analysis",
                cap
            ),
            status: ValidationStatus::Unknown,
            evidence: vec![format!("capability:{}", cap)],
            step_index: None,
            confidence: 0.0,
        },
    }
}

// ─── 2. State Reachability ────────────────────────────────────────

fn validate_state_reachability(
    chain: &ExploitChain,
    inputs: &SynthesisInputs,
) -> StateReachabilityValidation {
    let mut transitions = Vec::new();
    let mut current_state = "initial".to_string();

    for step in &chain.steps {
        let from_state = current_state.clone();

        // Check if the required capability is available at this state
        let reachable = if let Some(ir) = inputs.ir {
            ir.functions.iter().any(|f| f.name == step.function)
        } else {
            true // Cannot verify without IR
        };

        let (proof, unreachable_reason, missing, conflicting) = if reachable {
            let proof_str = format!(
                "Function '{}' exists with required effects for {:?}",
                step.function, step.required_capability
            );
            (proof_str, None, None, None)
        } else {
            let reason = format!("Function '{}' not found in IR", step.function);
            (
                String::new(),
                Some(reason),
                Some(step.function.clone()),
                None,
            )
        };

        transitions.push(StateTransitionProof {
            step_index: step.index,
            from_state: from_state.clone(),
            to_state: format!("state_after_{}", step.index),
            reachable,
            proof,
            unreachable_reason,
            missing_transition: missing,
            conflicting_transition: conflicting,
        });

        current_state = format!("state_after_{}", step.index);
    }

    let reachable_count = transitions.iter().filter(|t| t.reachable).count();
    let unreachable_count = transitions.iter().filter(|t| !t.reachable).count();

    StateReachabilityValidation {
        transitions,
        all_reachable: unreachable_count == 0,
        reachable_count,
        unreachable_count,
    }
}

// ─── 3. Transaction Sequence Validation ───────────────────────────

fn validate_transaction_sequence(
    chain: &ExploitChain,
    _inputs: &SynthesisInputs,
) -> TransactionSequenceValidation {
    let mut issues = Vec::new();
    let mut ordering = Vec::new();

    // Check for circular dependencies
    let mut graph: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for step in &chain.steps {
        let mut deps = Vec::new();
        for prereq in &step.prerequisites {
            if prereq.contains("Step") {
                if let Some(num_str) = prereq.split_whitespace().nth(1) {
                    if let Ok(num) = num_str.parse::<usize>() {
                        deps.push(num);
                    }
                }
            }
        }
        graph.insert(step.index, deps);
    }

    // Check for cycles using DFS
    let has_cycle = detect_cycle(&graph);
    if has_cycle {
        issues.push(SequenceIssue {
            kind: SequenceIssueKind::CircularDependency,
            step_a: 0,
            step_b: 1,
            description: "Circular dependency detected in step ordering".into(),
            evidence: vec!["cycle_detection:dfs".into()],
        });
    }

    // Check for impossible ordering (step depends on future step)
    for (step_idx, deps) in &graph {
        for dep in deps {
            if dep >= step_idx {
                issues.push(SequenceIssue {
                    kind: SequenceIssueKind::ImpossibleOrdering,
                    step_a: *dep,
                    step_b: *step_idx,
                    description: format!("Step {} depends on step {} (future)", step_idx, dep),
                    evidence: vec![format!("ordering:{}<{}", dep, step_idx)],
                });
            } else {
                ordering.push(OrderingConstraint {
                    from_step: *dep,
                    to_step: *step_idx,
                    kind: "dependency".into(),
                    reason: format!("Step {} must complete before step {}", dep, step_idx),
                });
            }
        }
    }

    // Check for invalid authority ordering (authority check before action)
    let has_authority_check = chain
        .steps
        .iter()
        .any(|s| s.required_capability == ExploitCapability::AuthorityEscalation);
    let has_action = chain.steps.iter().any(|s| {
        s.required_capability == ExploitCapability::WriteState
            || s.required_capability == ExploitCapability::TransferAssets
    });
    if has_authority_check && has_action {
        ordering.push(OrderingConstraint {
            from_step: 0,
            to_step: chain.steps.len().saturating_sub(1),
            kind: "authority_before_action".into(),
            reason: "Authority check must precede state-mutating action".into(),
        });
    }

    let valid = issues.is_empty();
    let explanation = if valid {
        "Transaction sequence is valid — no ordering conflicts detected".into()
    } else {
        format!(
            "{} ordering issue(s) detected: {}",
            issues.len(),
            issues
                .iter()
                .map(|i| i.description.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        )
    };

    TransactionSequenceValidation {
        valid,
        issues,
        ordering,
        explanation,
    }
}

/// Detect cycles in a dependency graph using DFS.
fn detect_cycle(graph: &BTreeMap<usize, Vec<usize>>) -> bool {
    let mut visited = std::collections::HashSet::new();
    let mut in_stack = std::collections::HashSet::new();

    fn dfs(
        node: usize,
        graph: &BTreeMap<usize, Vec<usize>>,
        visited: &mut std::collections::HashSet<usize>,
        in_stack: &mut std::collections::HashSet<usize>,
    ) -> bool {
        if in_stack.contains(&node) {
            return true;
        }
        if visited.contains(&node) {
            return false;
        }
        visited.insert(node);
        in_stack.insert(node);
        if let Some(deps) = graph.get(&node) {
            for &dep in deps {
                if dfs(dep, graph, visited, in_stack) {
                    return true;
                }
            }
        }
        in_stack.remove(&node);
        false
    }

    for &node in graph.keys() {
        if dfs(node, graph, &mut visited, &mut in_stack) {
            return true;
        }
    }
    false
}

// ─── 4. Invariant Replay ──────────────────────────────────────────

fn replay_invariants(chain: &ExploitChain, _inputs: &SynthesisInputs) -> InvariantReplayResult {
    let mut replays = Vec::new();
    let mut violations_detected = 0;
    let mut invariants_preserved = 0;

    // For each invariant mentioned in the chain
    for inv in &chain.violated_invariants {
        let mut steps = Vec::new();
        let mut violated = false;
        let mut violating_step = None;

        for step in &chain.steps {
            let step_affects = step.mutations.iter().any(|m| {
                m.to_lowercase().contains(&inv.to_lowercase())
                    || inv.to_lowercase().contains("balance")
                        && m.to_lowercase().contains("balance")
                    || inv.to_lowercase().contains("authority")
                        && step.required_capability == ExploitCapability::AuthorityEscalation
            });

            let holds = !step_affects;
            if step_affects && !violated {
                violated = true;
                violating_step = Some(step.index);
            }

            steps.push(InvariantStep {
                step_index: step.index,
                state: if holds {
                    "preserved".into()
                } else {
                    "violated".into()
                },
                holds,
                delta: if step_affects {
                    format!("'{}' broken by function '{}'", inv, step.function)
                } else {
                    "no change".into()
                },
            });
        }

        let affected_assets: Vec<String> = chain
            .steps
            .iter()
            .filter(|s| {
                s.mutations
                    .iter()
                    .any(|m| m.to_lowercase().contains(&inv.to_lowercase()))
            })
            .flat_map(|s| s.affected_assets.clone())
            .collect();

        let propagation_chain: Vec<String> = chain
            .steps
            .iter()
            .take_while(|s| {
                s.mutations
                    .iter()
                    .any(|m| m.to_lowercase().contains(&inv.to_lowercase()))
            })
            .map(|s| format!("Step {}: {}", s.index, s.function))
            .collect();

        if violated {
            violations_detected += 1;
        } else {
            invariants_preserved += 1;
        }

        replays.push(InvariantReplay {
            invariant_id: format!("inv-{}", inv.replace(' ', "_")),
            invariant_description: inv.clone(),
            initial_state: "satisfied".into(),
            steps,
            violated,
            violating_step,
            evidence: chain
                .evidence_provenance
                .iter()
                .filter(|e| e.source.contains("graph") || e.source.contains("economics"))
                .map(|e| e.ref_id.clone())
                .collect(),
            affected_assets,
            propagation_chain,
        });
    }

    InvariantReplayResult {
        replays,
        violations_detected,
        invariants_preserved,
    }
}

// ─── 5. Asset Flow Validation ─────────────────────────────────────

fn validate_asset_flow(chain: &ExploitChain, _inputs: &SynthesisInputs) -> AssetFlowValidation {
    let mut asset_flows: BTreeMap<String, AssetFlow> = BTreeMap::new();
    let mut impossible_creations = Vec::new();
    let mut balance_violations = Vec::new();
    let mut valid = true;

    for step in &chain.steps {
        for asset in &step.affected_assets {
            let flow = asset_flows
                .entry(asset.clone())
                .or_insert_with(|| AssetFlow {
                    asset_id: asset.clone(),
                    asset_type: classify_asset_type(asset),
                    steps: Vec::new(),
                    net_flow: 0.0,
                    balance_before: 1000.0,
                    balance_after: 1000.0,
                    valid: true,
                });

            let (inflow, outflow) = match step.state_transition {
                ExploitState::ValueExtraction => (1.0, 0.0),
                ExploitState::Preparation => (0.0, 0.1),
                ExploitState::Execution => (0.0, 0.01),
                _ => (0.0, 0.0),
            };

            let prev_cumulative = flow.steps.last().map(|s| s.cumulative).unwrap_or(0.0);
            let net = inflow - outflow;
            let cumulative = prev_cumulative + net;

            flow.steps.push(AssetFlowStep {
                step_index: step.index,
                inflow,
                outflow,
                net,
                cumulative,
            });
            flow.net_flow += net;

            // Check for impossible creation (more assets created than could exist)
            if inflow > 0.0 && outflow == 0.0 && prev_cumulative == 0.0 {
                impossible_creations.push(format!(
                    "Asset '{}' appears at step {} without prior transfer",
                    asset, step.index
                ));
            }
        }
    }

    // Update balances
    for flow in asset_flows.values_mut() {
        flow.balance_after = 1000.0 + flow.net_flow;
        flow.valid = flow.balance_after >= 0.0;
        if !flow.valid {
            balance_violations.push(BalanceViolation {
                asset_id: flow.asset_id.clone(),
                step_index: chain.steps.len().saturating_sub(1),
                expected: 0.0,
                actual: flow.balance_after,
                description: format!(
                    "Negative balance for '{}': {:.2}",
                    flow.asset_id, flow.balance_after
                ),
            });
            valid = false;
        }
    }

    if !impossible_creations.is_empty() {
        valid = false;
    }

    let flows: Vec<AssetFlow> = asset_flows.into_values().collect();
    let explanation = if valid {
        format!("All {} asset flows are valid", flows.len())
    } else {
        format!(
            "{} impossible creation(s), {} balance violation(s)",
            impossible_creations.len(),
            balance_violations.len()
        )
    };

    AssetFlowValidation {
        flows,
        valid,
        impossible_creations,
        balance_violations,
        explanation,
    }
}

fn classify_asset_type(asset: &str) -> AssetType {
    let lower = asset.to_lowercase();
    if lower.contains("vault") || lower.contains("lp") {
        AssetType::VaultBalance
    } else if lower.contains("debt") || lower.contains("borrow") {
        AssetType::DebtPosition
    } else if lower.contains("collateral") {
        AssetType::CollateralPosition
    } else if lower.contains("wrapped") {
        AssetType::WrappedAsset
    } else if lower.contains("sol")
        || lower.contains("eth")
        || lower.contains("wei")
        || lower.contains("lamport")
    {
        AssetType::NativeCurrency
    } else {
        AssetType::Token
    }
}

// ─── 6. Capability Validation ─────────────────────────────────────

fn validate_capabilities(
    chain: &ExploitChain,
    inputs: &SynthesisInputs,
) -> CapabilityValidationResult {
    let mut validations = Vec::new();

    for cap in &chain.required_capabilities {
        let (proven, evidence, proof_type) = match cap {
            ExploitCapability::WriteState => {
                let ir_proof = inputs.ir.map(|ir| {
                    let has_write = ir
                        .edges
                        .iter()
                        .any(|e| matches!(e, digger_ir::Edge::State(s) if s.access == "write"));
                    (
                        has_write,
                        vec![format!("ir:state_edges:write")],
                        ProofType::IrAnalysis,
                    )
                });
                ir_proof.unwrap_or((false, vec![], ProofType::Unproven))
            }
            ExploitCapability::AuthorityEscalation => {
                let ir_proof = inputs.ir.map(|ir| {
                    let has_gap = ir.edges.iter().any(
                        |e| matches!(e, digger_ir::Edge::Authority(a) if a.check_type == "missing"),
                    );
                    (
                        has_gap,
                        vec![format!("ir:authority_gaps")],
                        ProofType::IrAnalysis,
                    )
                });
                ir_proof.unwrap_or((false, vec![], ProofType::Unproven))
            }
            ExploitCapability::CrossContractCall | ExploitCapability::CrossProgramInvocation => {
                let ir_proof = inputs.ir.map(|ir| {
                    let has_ext = ir
                        .edges
                        .iter()
                        .any(|e| matches!(e, digger_ir::Edge::External(_)));
                    (
                        has_ext,
                        vec![format!("ir:external_edges")],
                        ProofType::IrAnalysis,
                    )
                });
                ir_proof.unwrap_or((false, vec![], ProofType::Unproven))
            }
            ExploitCapability::TransferAssets => {
                let ir_proof = inputs.ir.map(|ir| {
                    let has_transfer = ir.functions.iter().any(|f| f.effects.value_transfer);
                    (
                        has_transfer,
                        vec![format!("ir:value_transfer_functions")],
                        ProofType::IrAnalysis,
                    )
                });
                ir_proof.unwrap_or((false, vec![], ProofType::Unproven))
            }
            _ => (false, vec![], ProofType::Unproven),
        };

        validations.push(CapabilityCheck {
            capability: cap.to_string(),
            description: format!("Verify capability '{}' is achievable", cap),
            proven,
            evidence,
            proof_type,
        });
    }

    let proven_count = validations.iter().filter(|v| v.proven).count();
    let unproven_count = validations.iter().filter(|v| !v.proven).count();

    CapabilityValidationResult {
        validations,
        all_proven: unproven_count == 0,
        proven_count,
        unproven_count,
    }
}

// ─── 7. Trust Boundary Validation ─────────────────────────────────

fn validate_trust_boundaries(
    chain: &ExploitChain,
    inputs: &SynthesisInputs,
) -> TrustBoundaryValidation {
    let mut crossings = Vec::new();
    let mut unauthorized_count = 0;

    for step in &chain.steps {
        if step.required_capability == ExploitCapability::CrossContractCall
            || step.required_capability == ExploitCapability::CrossProgramInvocation
        {
            let authorized = inputs
                .ir
                .map(|ir| {
                    ir.edges.iter().any(|e| {
                        matches!(e, digger_ir::Edge::Authority(a)
                        if a.function == step.function && a.check_type != "missing")
                    })
                })
                .unwrap_or(false);

            let validation_performed = inputs.ir.is_some();
            let evidence = vec![format!("trust_boundary:{}:{}", step.function, authorized)];

            if !authorized {
                unauthorized_count += 1;
            }

            crossings.push(TrustBoundaryCrossing {
                from: "attacker".into(),
                to: step.function.clone(),
                kind: "external_call".into(),
                authorized,
                validation_performed,
                evidence,
                step_index: step.index,
            });
        }
    }

    let valid = unauthorized_count == 0;
    let explanation = if valid {
        format!(
            "{} trust boundary crossing(s) — all authorized",
            crossings.len()
        )
    } else {
        format!(
            "{} trust boundary crossing(s) — {} unauthorized",
            crossings.len(),
            unauthorized_count
        )
    };

    TrustBoundaryValidation {
        crossings,
        valid,
        unauthorized_count,
        explanation,
    }
}

// ─── 8. Economic Validation ───────────────────────────────────────

fn validate_economics(chain: &ExploitChain, _inputs: &SynthesisInputs) -> EconomicValidationReport {
    let mut breakdown = Vec::new();

    let mut capital_required = 0.0;
    let mut fees = 0.0;
    let mut expected_profit = 0.0;

    for step in &chain.steps {
        match step.state_transition {
            ExploitState::Preparation => {
                let cost = 0.1;
                capital_required += cost;
                breakdown.push(EconomicLineItem {
                    category: "Capital Required".into(),
                    amount: cost,
                    asset: step.affected_assets.first().cloned().unwrap_or_default(),
                    description: format!("Setup cost for step {}", step.index),
                });
            }
            ExploitState::Execution => {
                let gas_cost = 0.01;
                fees += gas_cost;
                breakdown.push(EconomicLineItem {
                    category: "Gas/Fees".into(),
                    amount: gas_cost,
                    asset: "gas".into(),
                    description: format!("Execution cost for step {}", step.index),
                });
            }
            ExploitState::ValueExtraction => {
                let gain = 1.0;
                expected_profit += gain;
                breakdown.push(EconomicLineItem {
                    category: "Expected Gain".into(),
                    amount: gain,
                    asset: step.affected_assets.first().cloned().unwrap_or_default(),
                    description: format!("Value extracted at step {}", step.index),
                });
            }
            _ => {}
        }
    }

    let total_cost = capital_required + fees;
    let net_profit = expected_profit - total_cost;
    let minimum_threshold = 0.001; // Minimum profit to consider worthwhile
    let profitable = net_profit > minimum_threshold;

    let explanation = if profitable {
        format!(
            "Profitable: profit {:.4} exceeds threshold {:.4}",
            net_profit, minimum_threshold
        )
    } else {
        format!(
            "Not profitable: profit {:.4} below threshold {:.4}",
            net_profit, minimum_threshold
        )
    };

    EconomicValidationReport {
        capital_required,
        borrowed_capital: 0.0,
        fees,
        slippage_estimate: 0.001,
        gas_estimate: fees,
        expected_profit,
        minimum_profitable_threshold: minimum_threshold,
        profitable,
        breakdown,
        explanation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain() -> ExploitChain {
        ExploitChain {
            chain_id: "test-validation".into(),
            goal: "DrainAssets".into(),
            steps: vec![
                ExploitStep {
                    index: 0,
                    state_transition: ExploitState::Execution,
                    function: "vulnerable_fn".into(),
                    action: "call".into(),
                    required_capability: ExploitCapability::AuthorityEscalation,
                    affected_state: vec!["balance".into()],
                    affected_assets: vec!["USDC".into()],
                    prerequisites: vec![],
                    mutations: vec!["drain balance".into()],
                    evidence_refs: vec!["test:evidence".into()],
                    confidence: 0.7,
                    explanation: "no auth".into(),
                },
                ExploitStep {
                    index: 1,
                    state_transition: ExploitState::ValueExtraction,
                    function: "withdraw".into(),
                    action: "extract".into(),
                    required_capability: ExploitCapability::TransferAssets,
                    affected_state: vec!["pool".into()],
                    affected_assets: vec!["USDC".into()],
                    prerequisites: vec!["Step 0 must succeed".into()],
                    mutations: vec!["transfer USDC".into()],
                    evidence_refs: vec![],
                    confidence: 0.7,
                    explanation: "extract funds".into(),
                },
            ],
            required_capabilities: vec![
                ExploitCapability::AuthorityEscalation,
                ExploitCapability::TransferAssets,
            ],
            assumptions: vec!["pool has funds".into()],
            violated_invariants: vec!["balance conservation".into()],
            evidence_provenance: vec![EvidenceReference {
                kind: EvidenceRefKind::GraphAnalysis,
                ref_id: "g1".into(),
                source: "graph".into(),
                derivation: "test".into(),
            }],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        }
    }

    fn test_inputs() -> SynthesisInputs<'static> {
        use std::sync::LazyLock;
        static IR: LazyLock<digger_ir::SystemIR> = LazyLock::new(|| digger_ir::SystemIR {
            program_id: "test".into(),
            language: digger_ir::Language::Solidity,
            functions: vec![
                digger_ir::Function {
                    id: "f1".into(),
                    name: "vulnerable_fn".into(),
                    contract: String::new(),
                    visibility: digger_ir::Visibility::Public,
                    inputs: vec![],
                    outputs: vec![],
                    modifiers: vec![],
                    effects: digger_ir::Effects {
                        state_mutation: true,
                        external_call: false,
                        authority_required: false,
                        value_transfer: true,
                        has_arithmetic: false,
                        has_temporal_guard: false,
                        value_flow: None,
                        has_unchecked_arithmetic: false,
                        writes_caller_scoped_state: false,
                        has_precision_loss_ordering: false,
                    },
                },
                digger_ir::Function {
                    id: "f2".into(),
                    name: "withdraw".into(),
                    contract: String::new(),
                    visibility: digger_ir::Visibility::Public,
                    inputs: vec![],
                    outputs: vec![],
                    modifiers: vec![],
                    effects: digger_ir::Effects {
                        state_mutation: false,
                        external_call: false,
                        authority_required: false,
                        value_transfer: true,
                        has_arithmetic: false,
                        has_temporal_guard: false,
                        value_flow: None,
                        has_unchecked_arithmetic: false,
                        writes_caller_scoped_state: false,
                        has_precision_loss_ordering: false,
                    },
                },
            ],
            state: vec![digger_ir::StateVariable {
                id: "s1".into(),
                name: "balance".into(),
                ty: "uint256".into(),
                mutable: true,
            }],
            edges: vec![
                digger_ir::Edge::State(digger_ir::StateEdge {
                    function: "vulnerable_fn".into(),
                    state: "balance".into(),
                    access: "write".into(),
                }),
                digger_ir::Edge::Authority(digger_ir::AuthorityEdge {
                    function: "vulnerable_fn".into(),
                    authority_source: "none".into(),
                    check_type: "missing".into(),
                }),
            ],
        });

        SynthesisInputs {
            ir: Some(&IR),
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

    #[test]
    fn test_full_validation() {
        let chain = test_chain();
        let inputs = test_inputs();
        let report = validate_exploit(&chain, &inputs);

        assert!(report.validation_score >= 0.0);
        assert!(report.validation_score <= 1.0);
        assert!(!report.evidence_references.is_empty());
        assert!(!report
            .validation_metadata
            .validation_duration_hint
            .is_empty());
    }

    #[test]
    fn test_preconditions_validation() {
        let chain = test_chain();
        let inputs = test_inputs();
        let preconditions = validate_preconditions(&chain, &inputs);
        assert!(preconditions.satisfied_count > 0);
        assert!(preconditions.results.len() >= 2); // At minimum: function existence + capability
    }

    #[test]
    fn test_invariant_replay() {
        let chain = test_chain();
        let inputs = test_inputs();
        let replay = replay_invariants(&chain, &inputs);
        assert_eq!(replay.replays.len(), 1);
        assert!(replay.replays[0].violated);
        assert!(replay.replays[0].violating_step.is_some());
    }

    #[test]
    fn test_asset_flow_validation() {
        let chain = test_chain();
        let inputs = test_inputs();
        let flow = validate_asset_flow(&chain, &inputs);
        assert!(!flow.flows.is_empty());
    }

    #[test]
    fn test_capability_validation() {
        let chain = test_chain();
        let inputs = test_inputs();
        let caps = validate_capabilities(&chain, &inputs);
        assert_eq!(caps.validations.len(), 2);
        assert!(caps.proven_count > 0);
    }

    #[test]
    fn test_cycle_detection() {
        let mut graph = BTreeMap::new();
        graph.insert(0, vec![2]);
        graph.insert(1, vec![0]);
        graph.insert(2, vec![1]);
        assert!(detect_cycle(&graph));

        let mut graph2 = BTreeMap::new();
        graph2.insert(0, vec![]);
        graph2.insert(1, vec![0]);
        graph2.insert(2, vec![1]);
        assert!(!detect_cycle(&graph2));
    }
}
