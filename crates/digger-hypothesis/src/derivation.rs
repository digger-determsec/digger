use crate::models::*;
use digger_graph::analysis::{
    AuthorityBoundaryGraph, CrossProgramGraph, ExecutionGraph, StateDependencyGraph,
    VulnerabilityPathAnalysis,
};
/// Hypothesis derivation engine.
///
/// Consumes existing graph outputs ONLY.
/// Does NOT modify graph generation.
/// Does NOT modify SystemIR.
/// Does NOT use AI, LLMs, probabilities, embeddings, or external services.
/// Is deterministic: same input → same output.
use digger_ir::{Edge, SystemIR};

/// Optional context for enhanced hypothesis derivation.
#[derive(Default)]
pub struct DerivationContext<'a> {
    /// Economic analysis results (optional).
    pub economic: Option<&'a digger_economics::EconomicReport>,
    /// Adversarial analysis results (optional).
    pub adversarial: Option<&'a digger_adversarial::CapabilityReport>,
    /// Historical finding store for corpus evidence attachment (optional).
    /// When provided, already-derived hypotheses receive structured corpus
    /// references as GraphFact entries. The corpus NEVER creates, gates,
    /// upgrades, or changes the detected set — it only decorates.
    pub knowledge: Option<&'a digger_knowledge_models::HistoricalFindingStore>,
    /// Corpus snapshot ID for provenance (e.g. content hash). Embedded in
    /// every corpus_match fact for traceability. None = no provenance tag.
    pub corpus_snapshot_id: Option<&'a str>,
    /// Corpus source label for provenance (e.g. "code4rena"). Embedded in
    /// every corpus_match fact. None = no source tag.
    pub corpus_source_id: Option<&'a str>,
}

/// Count total corpus_match facts across all hypotheses.
/// Read-only metric: no impact on detection.
pub fn count_corpus_matches(hypotheses: &[Hypothesis]) -> usize {
    hypotheses
        .iter()
        .flat_map(|h| &h.evidence)
        .flat_map(|e| &e.graph_facts)
        .filter(|f| f.fact_type == "corpus_match")
        .count()
}

/// Compute a deterministic content hash for a HistoricalFindingStore.
/// Uses FNV-1a (64-bit) which is portable across platforms and Rust versions,
/// unlike std DefaultHasher (SipHash) which is NOT stable across releases.
/// Hashes sorted (finding_id, vulnerability_class) pairs.
pub fn compute_corpus_hash(store: &digger_knowledge_models::HistoricalFindingStore) -> String {
    let mut pairs: Vec<(&str, String)> = store
        .findings
        .iter()
        .map(|f| (f.finding_id.as_str(), f.vulnerability_class.to_string()))
        .collect();
    pairs.sort();

    let mut hash: u64 = 14695981039346656037; // FNV offset basis
    for (fid, cls) in &pairs {
        for byte in fid.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(1099511628211); // FNV prime
        }
        for byte in cls.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(1099511628211);
        }
    }
    format!("{:016x}", hash)
}

/// Verify that a store's content hash matches the expected snapshot id.
/// Returns Ok(()) if they match, or Err with a clear message on mismatch.
/// When expected_snapshot is None, verification is skipped (always Ok).
pub fn verify_corpus_snapshot(
    store: &digger_knowledge_models::HistoricalFindingStore,
    expected_snapshot: Option<&str>,
) -> Result<(), String> {
    match expected_snapshot {
        None => Ok(()),
        Some(expected) => {
            let actual = compute_corpus_hash(store);
            if actual == expected {
                Ok(())
            } else {
                Err(format!(
                    "corpus snapshot mismatch: expected {expected}, got {actual}"
                ))
            }
        }
    }
}

/// Derive all hypotheses from SystemIR.
///
/// This is the ONLY entry point. It consumes existing graph outputs
/// and produces deterministic hypotheses with full evidence chains.
pub fn derive(ir: &SystemIR) -> HypothesisResult {
    derive_with_context(ir, &DerivationContext::default())
}

/// Derive hypotheses with optional economic and adversarial context.
pub fn derive_with_context(ir: &SystemIR, ctx: &DerivationContext) -> HypothesisResult {
    let exec = ExecutionGraph::build(ir);
    let state_dep = StateDependencyGraph::build(ir);
    let auth = AuthorityBoundaryGraph::build(ir);
    let cross = CrossProgramGraph::build(ir);
    let vuln = VulnerabilityPathAnalysis::derive(ir);

    let mut hypotheses = vec![];

    // 1. Reentrancy candidates
    hypotheses.extend(derive_reentrancy_hypotheses(
        ir, &exec, &state_dep, &cross, &auth, &vuln,
    ));

    // 2. Authority bypass candidates
    hypotheses.extend(derive_authority_bypass_hypotheses(
        ir, &auth, &state_dep, &cross, &vuln,
    ));

    // 3. CPI trust violation candidates
    hypotheses.extend(derive_cpi_trust_hypotheses(
        ir, &cross, &auth, &state_dep, &vuln,
    ));

    // 4. State corruption candidates
    hypotheses.extend(derive_state_corruption_hypotheses(
        ir, &state_dep, &auth, &vuln,
    ));

    // 5. Economic invariant violation candidates (from economics engine)
    if let Some(economic) = ctx.economic {
        hypotheses.extend(derive_economic_invariant_hypotheses(ir, economic));
    }

    // 6. Adversarial path candidates (from adversarial engine)
    if let Some(adversarial) = ctx.adversarial {
        hypotheses.extend(derive_adversarial_path_hypotheses(ir, adversarial));
    }

    // 7. Oracle manipulation candidates (storage-derived price/rate without external feed)
    hypotheses.extend(derive_oracle_manipulation_hypotheses(ir));

    // 8. Flash loan governance candidates (balance-read + value-transfer + no temporal guard)
    hypotheses.extend(derive_flash_loan_governance_hypotheses(ir));

    // 9. Solana account-constraint candidates (missing signer/owner/seeds)
    hypotheses.extend(derive_missing_account_constraint_hypotheses(ir));

    // 10. Unchecked arithmetic candidates (advisory: overflow in unchecked blocks)
    hypotheses.extend(derive_unchecked_arithmetic_hypotheses(ir));

    // 11. Precision-loss ordering candidates (advisory: div-before-mul feeds value transfer)
    hypotheses.extend(derive_precision_loss_hypotheses(ir));

    // Sort: severity tier first (Critical > High > Medium > Low > Info),
    // then by type priority within each tier (exploit-specific > structural),
    // then alphabetically by ID for deterministic output.
    fn severity_rank(s: &HypothesisSeverity) -> u8 {
        match s {
            HypothesisSeverity::Critical => 0,
            HypothesisSeverity::High => 1,
            HypothesisSeverity::Medium => 2,
            HypothesisSeverity::Low => 3,
            HypothesisSeverity::Info => 4,
        }
    }
    fn type_priority(t: &HypothesisType) -> u8 {
        match t {
            HypothesisType::OracleManipulationCandidate => 0,
            HypothesisType::FlashLoanGovernanceCandidate => 1,
            HypothesisType::ReentrancyCandidate => 2,
            HypothesisType::CPITrustViolationCandidate => 3,
            HypothesisType::StateCorruptionCandidate => 4,
            HypothesisType::EconomicInvariantViolationCandidate => 5,
            HypothesisType::AdversarialPathCandidate => 6,
            HypothesisType::AuthorityBypassCandidate => 7,
            HypothesisType::MissingAccountConstraintCandidate => 8,
            HypothesisType::UncheckedArithmeticCandidate => 9,
            HypothesisType::PrecisionLossCandidate => 10,
        }
    }
    hypotheses.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(type_priority(&a.hypothesis_type).cmp(&type_priority(&b.hypothesis_type)))
            .then(a.id.0.cmp(&b.id.0))
    });

    // Post-derivation corpus evidence attachment.
    // ATTACH ONLY: never create, gate, re-rank, or re-severity any hypothesis.
    if let Some(store) = ctx.knowledge {
        attach_corpus_evidence(
            &mut hypotheses,
            store,
            ctx.corpus_snapshot_id,
            ctx.corpus_source_id,
        );
    }

    let summary = build_summary(&hypotheses);

    HypothesisResult {
        program_id: ir.program_id.clone(),
        hypotheses,
        summary,
    }
}

/// Derive reentrancy hypotheses: external call + state mutation.
fn derive_reentrancy_hypotheses(
    ir: &SystemIR,
    _exec: &ExecutionGraph,
    state_dep: &StateDependencyGraph,
    cross: &CrossProgramGraph,
    auth: &AuthorityBoundaryGraph,
    vuln: &VulnerabilityPathAnalysis,
) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    for f in &ir.functions {
        let has_external = cross.external_calls.iter().any(|e| e.function == f.name);
        let writes = state_dep.states_written_by(&f.name);
        let has_authority = auth.is_enforced(&f.name);

        if has_external && !writes.is_empty() {
            let severity = if has_authority {
                HypothesisSeverity::Medium
            } else {
                HypothesisSeverity::Critical
            };

            // Find matching vulnerability paths
            let matching_paths: Vec<_> = vuln
                .paths
                .iter()
                .filter(|p| p.entry_function == f.name)
                .filter(|p| {
                    matches!(
                        p.path_type,
                        digger_graph::analysis::vuln_path::VulnerabilityPathType::Reentrancy
                    )
                })
                .collect();

            let evidence: Vec<HypothesisEvidence> = if matching_paths.is_empty() {
                // Generate evidence from graph facts even if no matching vuln path
                vec![HypothesisEvidence {
                    path_id: format!("PATH-REENTRANCY-{}", f.name),
                    evidence_chain_id: format!("FIND-REENTRANCY-{}", f.name),
                    involved_functions: vec![f.name.clone()],
                    graph_facts: vec![
                        GraphFact {
                            fact_type: "external_call".into(),
                            function: f.name.clone(),
                            detail: cross
                                .external_calls
                                .iter()
                                .find(|e| e.function == f.name)
                                .map(|e| e.target.clone())
                                .unwrap_or_default(),
                        },
                        GraphFact {
                            fact_type: "state_write".into(),
                            function: f.name.clone(),
                            detail: writes.join(", "),
                        },
                    ],
                }]
            } else {
                matching_paths
                    .iter()
                    .map(|_path| HypothesisEvidence {
                        path_id: format!("PATH-REENTRANCY-{}", f.name),
                        evidence_chain_id: format!("FIND-REENTRANCY-{}", f.name),
                        involved_functions: vec![f.name.clone()],
                        graph_facts: vec![
                            GraphFact {
                                fact_type: "external_call".into(),
                                function: f.name.clone(),
                                detail: cross
                                    .external_calls
                                    .iter()
                                    .find(|e| e.function == f.name)
                                    .map(|e| e.target.clone())
                                    .unwrap_or_default(),
                            },
                            GraphFact {
                                fact_type: "state_write".into(),
                                function: f.name.clone(),
                                detail: writes.join(", "),
                            },
                        ],
                    })
                    .collect()
            };

            let explanation = if has_authority {
                format!(
                    "Function '{}' makes external call and writes state variables [{}]. \
                     Authority check is present, reducing risk. \
                     External call before state update is a reentrancy pattern.",
                    f.name,
                    writes.join(", ")
                )
            } else {
                format!(
                    "Function '{}' makes external call and writes state variables [{}] \
                     without authority enforcement. \
                     External call before state update without access control is a critical reentrancy vector.",
                    f.name, writes.join(", ")
                )
            };

            hypotheses.push(Hypothesis {
                id: HypothesisId(format!("HYP-REENT-{}", f.name)),
                hypothesis_type: HypothesisType::ReentrancyCandidate,
                severity,
                description: format!("Reentrancy candidate in '{}'", f.name),
                primary_function: f.name.clone(),
                evidence,
                structural_explanation: explanation,
            });
        }
    }

    hypotheses
}

/// Derive authority bypass hypotheses: public + state mutation + no authority,
/// and also functions making external calls without authority.
fn derive_authority_bypass_hypotheses(
    ir: &SystemIR,
    auth: &AuthorityBoundaryGraph,
    _state_dep: &StateDependencyGraph,
    cross: &CrossProgramGraph,
    vuln: &VulnerabilityPathAnalysis,
) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];
    let mut seen_fns: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for unguarded in &auth.unguarded_mutations {
        if !unguarded.is_public {
            continue;
        }
        if !seen_fns.insert(unguarded.function.clone()) {
            continue;
        }

        // Skip constructors — deployment-only, cannot be an authority bypass.
        if is_constructor_name(&unguarded.function) {
            continue;
        }

        // Find matching vulnerability paths
        let matching_paths: Vec<_> = vuln
            .paths
            .iter()
            .filter(|p| p.entry_function == unguarded.function)
            .filter(|p| {
                matches!(p.path_type,
                digger_graph::analysis::vuln_path::VulnerabilityPathType::UnauthorizedModification
                | digger_graph::analysis::vuln_path::VulnerabilityPathType::MissingAuthority)
            })
            .collect();

        let evidence: Vec<HypothesisEvidence> = if matching_paths.is_empty() {
            vec![HypothesisEvidence {
                path_id: format!("PATH-AUTH-{}", unguarded.function),
                evidence_chain_id: format!("FIND-AUTH-{}", unguarded.function),
                involved_functions: vec![unguarded.function.clone()],
                graph_facts: vec![
                    GraphFact {
                        fact_type: "authority_gap".into(),
                        function: unguarded.function.clone(),
                        detail: "no authority check on public function".into(),
                    },
                    GraphFact {
                        fact_type: "state_write".into(),
                        function: unguarded.function.clone(),
                        detail: unguarded.state_vars.join(", "),
                    },
                ],
            }]
        } else {
            matching_paths
                .iter()
                .map(|_path| HypothesisEvidence {
                    path_id: format!("PATH-AUTH-{}", unguarded.function),
                    evidence_chain_id: format!("FIND-AUTH-{}", unguarded.function),
                    involved_functions: vec![unguarded.function.clone()],
                    graph_facts: vec![
                        GraphFact {
                            fact_type: "authority_gap".into(),
                            function: unguarded.function.clone(),
                            detail: "no authority check on public function".into(),
                        },
                        GraphFact {
                            fact_type: "state_write".into(),
                            function: unguarded.function.clone(),
                            detail: unguarded.state_vars.join(", "),
                        },
                    ],
                })
                .collect()
        };

        // Tiering: demote self-scoped functions to Medium.
        // A function is "self-scoped" (permissionless by design) if ALL its state
        // writes are to mapping-type variables (address-indexed, inherently scoped
        // to the caller). Privileged config/ownership mutations write to non-mapping
        // state and stay Critical. This separates "move own funds" from "change
        // protocol config" without hardcoding target names.
        let all_writes_are_mapping = unguarded.state_vars.iter().all(|var_name| {
            ir.state
                .iter()
                .any(|s| s.name == *var_name && s.ty.to_lowercase().contains("mapping"))
        });
        let severity = if all_writes_are_mapping && !unguarded.state_vars.is_empty() {
            HypothesisSeverity::Medium
        } else {
            HypothesisSeverity::Critical
        };

        hypotheses.push(Hypothesis {
            id: HypothesisId(format!("HYP-AUTH-{}", unguarded.function)),
            hypothesis_type: HypothesisType::AuthorityBypassCandidate,
            severity,
            description: format!("Authority bypass candidate in '{}'", unguarded.function),
            primary_function: unguarded.function.clone(),
            evidence,
            structural_explanation: format!(
                "Public function '{}' mutates state variables [{}] \
                 without any authority enforcement. \
                 Any caller can modify these state variables.",
                unguarded.function,
                unguarded.state_vars.join(", ")
            ),
        });
    }

    // Also consider functions making external calls without authority (C4.1).
    // These may not write state via Edge::State, so they don't appear in
    // unguarded_mutations, but they DO cross trust boundaries unsafely.
    for fn_name in &cross.untrusted_external {
        if !seen_fns.insert(fn_name.clone()) {
            continue;
        }
        // Check if this function is public
        let is_public = ir
            .functions
            .iter()
            .any(|f| f.name == *fn_name && f.visibility == digger_ir::Visibility::Public);
        if !is_public {
            continue;
        }

        let targets: Vec<String> = cross.targets_of(fn_name);
        let evidence = vec![HypothesisEvidence {
            path_id: format!("PATH-AUTH-EXT-{}", fn_name),
            evidence_chain_id: format!("FIND-AUTH-EXT-{}", fn_name),
            involved_functions: vec![fn_name.clone()],
            graph_facts: vec![GraphFact {
                fact_type: "authority_gap".into(),
                function: fn_name.clone(),
                detail: format!(
                    "external call to [{}] without authority check",
                    targets.join(", ")
                ),
            }],
        }];

        hypotheses.push(Hypothesis {
            id: HypothesisId(format!("HYP-AUTH-EXT-{}", fn_name)),
            hypothesis_type: HypothesisType::AuthorityBypassCandidate,
            severity: HypothesisSeverity::High,
            description: format!(
                "Authority bypass candidate in '{}' (untrusted external call)",
                fn_name
            ),
            primary_function: fn_name.clone(),
            evidence,
            structural_explanation: format!(
                "Function '{}' makes external call(s) to [{}] \
                 without any authority enforcement. \
                 An untrusted caller can invoke these external calls freely.",
                fn_name,
                targets.join(", ")
            ),
        });
    }

    // Third: missing-authority catch-all (C4.3).
    // PRINCIPLED SUPPRESSION (precision-pass-1):
    // Only flags public functions that actually mutate state. Bare getters,
    // view/pure functions, and constructors must not produce hypotheses here.
    // Uses structural state-write edges (not the imprecise text heuristic in
    // Effects.state_mutation which fires on bracket reads like data[key]).
    let enforced_set: std::collections::BTreeSet<String> = auth.enforced.iter().cloned().collect();
    let functions_with_state_writes: std::collections::BTreeSet<String> = ir
        .edges
        .iter()
        .filter_map(|e| {
            if let digger_ir::Edge::State(s) = e {
                if s.access == "write" {
                    Some(s.function.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    for f in &ir.functions {
        if f.visibility != digger_ir::Visibility::Public {
            continue;
        }
        if enforced_set.contains(&f.name) {
            continue; // has enforced authority — legacy would not flag this
        }
        if !seen_fns.insert(f.name.clone()) {
            continue; // already handled by earlier iteration
        }

        // Precision: skip constructors (they necessarily write state during init).
        if is_constructor_name(&f.name) {
            continue;
        }

        // Precision: skip functions with no state-mutation effect. Use structural
        // state-write edges (from state_access analyzer) when available — these
        // are accurate. Fall back to the text heuristic (Effects.state_mutation)
        // when no state edges exist (synthetic/test IR).
        let has_state_writes = if functions_with_state_writes.is_empty() {
            // No state edges in IR — fall back to text heuristic
            f.effects.state_mutation || f.effects.value_transfer
        } else {
            functions_with_state_writes.contains(&f.name) || f.effects.value_transfer
        };
        if !has_state_writes {
            continue;
        }

        hypotheses.push(Hypothesis {
            id: HypothesisId(format!("HYP-AUTH-MISS-{}", f.name)),
            hypothesis_type: HypothesisType::AuthorityBypassCandidate,
            severity: HypothesisSeverity::Medium,
            description: format!(
                "Authority bypass candidate in '{}' (missing authority check)",
                f.name
            ),
            primary_function: f.name.clone(),
            evidence: vec![HypothesisEvidence {
                path_id: format!("PATH-AUTH-MISS-{}", f.name),
                evidence_chain_id: format!("FIND-AUTH-MISS-{}", f.name),
                involved_functions: vec![f.name.clone()],
                graph_facts: vec![GraphFact {
                    fact_type: "authority_gap".into(),
                    function: f.name.clone(),
                    detail: "no enforced authority edge detected for public function".into(),
                }],
            }],
            structural_explanation: format!(
                "Public function '{}' executes without explicit authority verification. \
                 No enforced authority constraint was detected.",
                f.name
            ),
        });
    }

    hypotheses
}

/// Returns true if the function name matches a constructor pattern.
fn is_constructor_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "constructor" || lower.ends_with("constructor")
}

/// Derive CPI trust violation hypotheses: CPI + no authority.
fn derive_cpi_trust_hypotheses(
    _ir: &SystemIR,
    cross: &CrossProgramGraph,
    auth: &AuthorityBoundaryGraph,
    state_dep: &StateDependencyGraph,
    vuln: &VulnerabilityPathAnalysis,
) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    for cpi_call in &cross.cpi_calls {
        let fn_name = &cpi_call.function;
        let is_enforced = auth.is_enforced(fn_name);
        let writes = state_dep.states_written_by(fn_name);

        if !is_enforced {
            let matching_paths: Vec<_> =
                vuln.paths
                    .iter()
                    .filter(|p| p.entry_function == *fn_name)
                    .filter(|p| {
                        matches!(p.path_type,
                    digger_graph::analysis::vuln_path::VulnerabilityPathType::CpiTrustViolation)
                    })
                    .collect();

            let build_cpi_evidence = || -> HypothesisEvidence {
                let mut graph_facts = vec![
                    GraphFact {
                        fact_type: "cpi_call".into(),
                        function: fn_name.clone(),
                        detail: cpi_call.target.clone(),
                    },
                    GraphFact {
                        fact_type: "authority_gap".into(),
                        function: fn_name.clone(),
                        detail: "CPI without authority check".into(),
                    },
                ];
                if !writes.is_empty() {
                    graph_facts.push(GraphFact {
                        fact_type: "state_write".into(),
                        function: fn_name.clone(),
                        detail: writes.join(", "),
                    });
                }
                HypothesisEvidence {
                    path_id: format!("PATH-CPI-{}", fn_name),
                    evidence_chain_id: format!("FIND-CPI-{}", fn_name),
                    involved_functions: vec![fn_name.clone()],
                    graph_facts,
                }
            };

            let evidence: Vec<HypothesisEvidence> = if matching_paths.is_empty() {
                vec![build_cpi_evidence()]
            } else {
                matching_paths
                    .iter()
                    .map(|_| build_cpi_evidence())
                    .collect()
            };

            let explanation = if writes.is_empty() {
                format!(
                    "Function '{}' makes CPI call to '{}' without authority enforcement. \
                     Trust boundary crossed without access control.",
                    fn_name, cpi_call.target
                )
            } else {
                format!(
                    "Function '{}' makes CPI call to '{}' and writes state [{}] \
                     without authority enforcement. \
                     Trust boundary crossed without access control.",
                    fn_name,
                    cpi_call.target,
                    writes.join(", ")
                )
            };

            hypotheses.push(Hypothesis {
                id: HypothesisId(format!("HYP-CPI-{}", fn_name)),
                hypothesis_type: HypothesisType::CPITrustViolationCandidate,
                severity: HypothesisSeverity::High,
                description: format!("CPI trust violation candidate in '{}'", fn_name),
                primary_function: fn_name.clone(),
                evidence,
                structural_explanation: explanation,
            });
        }
    }

    hypotheses
}

/// Derive state corruption hypotheses: multiple writers, no coordination.
fn derive_state_corruption_hypotheses(
    _ir: &SystemIR,
    state_dep: &StateDependencyGraph,
    auth: &AuthorityBoundaryGraph,
    vuln: &VulnerabilityPathAnalysis,
) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    // Find state variables written by multiple functions
    for state_var in &state_dep.shared_mutations {
        let writers = state_dep
            .writers
            .get(state_var)
            .cloned()
            .unwrap_or_default();
        let unguarded_writers: Vec<_> = writers
            .iter()
            .filter(|w| !auth.is_enforced(w))
            .cloned()
            .collect();

        if !unguarded_writers.is_empty() {
            let matching_paths: Vec<_> = vuln
                .paths
                .iter()
                .filter(|p| unguarded_writers.contains(&p.entry_function))
                .collect();

            let build_corrupt_evidence = || -> HypothesisEvidence {
                let graph_facts: Vec<GraphFact> = unguarded_writers
                    .iter()
                    .map(|w| GraphFact {
                        fact_type: "state_write".into(),
                        function: w.clone(),
                        detail: state_var.clone(),
                    })
                    .collect();
                HypothesisEvidence {
                    path_id: format!("PATH-CORRUPT-{}", state_var),
                    evidence_chain_id: format!("FIND-CORRUPT-{}", state_var),
                    involved_functions: unguarded_writers.clone(),
                    graph_facts,
                }
            };

            let evidence: Vec<HypothesisEvidence> = if matching_paths.is_empty() {
                vec![build_corrupt_evidence()]
            } else {
                matching_paths
                    .iter()
                    .map(|_| build_corrupt_evidence())
                    .collect()
            };

            hypotheses.push(Hypothesis {
                id: HypothesisId(format!("HYP-CORRUPT-{}", state_var)),
                hypothesis_type: HypothesisType::StateCorruptionCandidate,
                severity: HypothesisSeverity::High,
                description: format!("State corruption candidate for '{}'", state_var),
                primary_function: unguarded_writers.first().cloned().unwrap_or_default(),
                evidence,
                structural_explanation: format!(
                    "State variable '{}' is written by multiple functions [{}] \
                     without coordinated authority enforcement. \
                     Unguarded writers: [{}]. \
                     Concurrent access without synchronization is a corruption vector.",
                    state_var,
                    writers.join(", "),
                    unguarded_writers.join(", ")
                ),
            });
        }
    }

    hypotheses
}

/// Derive oracle manipulation hypotheses: value transfer reads from writable
/// storage without external feed validation.
fn derive_oracle_manipulation_hypotheses(ir: &SystemIR) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    // 1. Build the set of writable state variables (any variable with a write edge).
    let writable: std::collections::BTreeSet<String> = ir
        .edges
        .iter()
        .filter_map(|e| match e {
            Edge::State(s) if s.access == "write" => Some(s.state.clone()),
            _ => None,
        })
        .collect();

    if writable.is_empty() {
        return hypotheses;
    }

    // 2. For each function: value_transfer && !external_call && has_arithmetic
    //    && reads a writable var that the function does NOT itself write.
    //    When value_flow is available, use structured signals for precision.
    for f in &ir.functions {
        if !f.effects.value_transfer {
            continue;
        }
        if f.effects.external_call {
            continue;
        }
        // Arithmetic gate: prefer structured value_flow, fall back to boolean.
        // Tightened: require that at least one WRITABLE state variable appears
        // inside an arithmetic subtree (state_reads_in_arithmetic), not just that
        // arithmetic exists in the function. This cuts FPs where arithmetic is
        // only on constants/parameters.
        let has_arithmetic_signal = if let Some(ref vf) = f.effects.value_flow {
            // Require: arithmetic feeds value transfer AND at least one writable
            // state var is inside the arithmetic subtree.
            vf.arithmetic_feeds_value_transfer
                && vf
                    .state_reads_in_arithmetic
                    .iter()
                    .any(|var| writable.contains(var))
        } else {
            f.effects.has_arithmetic
        };
        if !has_arithmetic_signal {
            continue;
        }

        // Find writable state variables this function reads.
        let read_writable: Vec<String> = if let Some(ref vf) = f.effects.value_flow {
            // Use structured value_flow: state_reads ∩ writable set, excluding self-written
            vf.state_reads
                .iter()
                .filter(|var| writable.contains(*var) && !vf.state_writes.contains(*var))
                .cloned()
                .collect()
        } else {
            ir.edges
                .iter()
                .filter_map(|e| match e {
                    Edge::State(s) if s.function == f.name && s.access == "read" => {
                        if writable.contains(&s.state) {
                            Some(s.state.clone())
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .collect()
        };

        if read_writable.is_empty() {
            continue;
        }

        // Structural gate: exclude state variables that this function also writes.
        // Oracle pattern: function reads rate (written by governance, not by itself) → fires.
        // Token pattern: function reads/writes allowances → doesn't fire.
        let self_written: std::collections::BTreeSet<String> = ir
            .edges
            .iter()
            .filter_map(|e| match e {
                Edge::State(s) if s.function == f.name && s.access == "write" => {
                    Some(s.state.clone())
                }
                _ => None,
            })
            .collect();

        let externally_written_writable: Vec<String> = read_writable
            .iter()
            .filter(|v| !self_written.contains(*v))
            .cloned()
            .collect();

        if externally_written_writable.is_empty() {
            continue;
        }

        let evidence = vec![HypothesisEvidence {
            path_id: format!("PATH-ORACLE-{}", f.name),
            evidence_chain_id: format!("FIND-ORACLE-{}", f.name),
            involved_functions: vec![f.name.clone()],
            graph_facts: vec![
                GraphFact {
                    fact_type: "state_read".into(),
                    function: f.name.clone(),
                    detail: externally_written_writable.join(", "),
                },
                GraphFact {
                    fact_type: "value_transfer".into(),
                    function: f.name.clone(),
                    detail: "function transfers value without external feed".into(),
                },
                GraphFact {
                    fact_type: "no_external_call".into(),
                    function: f.name.clone(),
                    detail: "no external oracle/feed dependency detected".into(),
                },
            ],
        }];

        hypotheses.push(Hypothesis {
            id: HypothesisId(format!("HYP-ORACLE-{}", f.name)),
            hypothesis_type: HypothesisType::OracleManipulationCandidate,
            severity: HypothesisSeverity::High,
            description: format!("Oracle manipulation candidate in '{}'", f.name),
            primary_function: f.name.clone(),
            evidence,
            structural_explanation: format!(
                "Function '{}' reads writable state variables [{}] and transfers value, \
                 but makes no external calls to validated feeds. \
                 Value computation depends on internally mutable state \
                 rather than an external oracle — potential oracle manipulation vector.",
                f.name,
                externally_written_writable.join(", ")
            ),
        });
    }

    hypotheses
}

/// Derive unchecked-arithmetic advisory candidates.
///
/// Fires ONLY when:
/// 1. effects.has_unchecked_arithmetic == true (AST-derived flag from solidity_ast)
/// 2. The function has a value-relevant effect (state_mutation OR value_transfer)
///
/// Severity: LOW advisory — never Critical/High. This is a precision/safety
/// signal, not an exploit confirmation. The advisory sits BELOW the access-control,
/// reentrancy, oracle, and CPI tiers in the ranking.
fn derive_unchecked_arithmetic_hypotheses(ir: &SystemIR) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    for f in &ir.functions {
        if !f.effects.has_unchecked_arithmetic {
            continue;
        }
        // Require value-relevant effect: state mutation or value transfer
        if !f.effects.state_mutation && !f.effects.value_transfer {
            continue;
        }
        // NO other authority/signer check gating — this is advisory, not exploit-grade.
        // Skip functions that are already gated (the advisory is only useful on
        // functions that have OTHER issues or could benefit from overflow awareness).

        let id_str = format!("HYP-UNCHECK-{}-{}", f.contract, f.name);
        let id = HypothesisId(id_str.clone());

        // Check if this hypothesis already exists (dedup)
        if hypotheses.iter().any(|h: &Hypothesis| h.id.0 == id_str) {
            continue;
        }

        let mut evidence_chain = vec![];
        evidence_chain.push(HypothesisEvidence {
            path_id: format!("PATH-UNCHECK-{}-{}", f.contract, f.name),
            evidence_chain_id: format!("FIND-UNCHECK-{}-{}", f.contract, f.name),
            involved_functions: vec![f.name.clone()],
            graph_facts: vec![GraphFact {
                fact_type: "unchecked_arithmetic".into(),
                function: f.name.clone(),
                detail: format!(
                    "Function '{}' contains arithmetic inside an unchecked block",
                    f.name
                ),
            }],
        });

        hypotheses.push(Hypothesis {
            id,
            hypothesis_type: HypothesisType::UncheckedArithmeticCandidate,
            severity: HypothesisSeverity::Low,
            description: format!(
                "Arithmetic inside unchecked block in '{}' — overflow/precision loss may silently alter value computation",
                f.name
            ),
            primary_function: f.name.clone(),
            evidence: evidence_chain,
            structural_explanation: format!(
                "Function '{}' contains arithmetic inside a Solidity unchecked block where overflow is not checked.",
                f.name
            ),
        });
    }

    hypotheses
}

/// Derive precision-loss ordering advisory candidates.
///
/// Fires ONLY when:
/// 1. effects.has_precision_loss_ordering == true (div-before-mul in a single expression)
/// 2. effects.value_transfer == true (the precision loss feeds a value/amount path)
///
/// Severity: MEDIUM advisory — not Critical/High. Flags a real structural pattern
/// commonly seen in rounding/oracle vulnerabilities.
fn derive_precision_loss_hypotheses(ir: &SystemIR) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    for f in &ir.functions {
        if !f.effects.has_precision_loss_ordering {
            continue;
        }
        if !f.effects.state_mutation && !f.effects.value_transfer {
            continue;
        }

        let id_str = format!("HYP-PRECLOSS-{}-{}", f.contract, f.name);
        let id = HypothesisId(id_str.clone());

        if hypotheses.iter().any(|h: &Hypothesis| h.id.0 == id_str) {
            continue;
        }

        hypotheses.push(Hypothesis {
            id,
            hypothesis_type: HypothesisType::PrecisionLossCandidate,
            severity: HypothesisSeverity::Medium,
            description: format!(
                "Division-before-multiplication in '{}' feeds a value transfer — \
                 truncated division may silently reduce the computed amount",
                f.name
            ),
            primary_function: f.name.clone(),
            evidence: vec![HypothesisEvidence {
                path_id: format!("PATH-PRECLOSS-{}-{}", f.contract, f.name),
                evidence_chain_id: format!("FIND-PRECLOSS-{}-{}", f.contract, f.name),
                involved_functions: vec![f.name.clone()],
                graph_facts: vec![GraphFact {
                    fact_type: "precision_loss_ordering".into(),
                    function: f.name.clone(),
                    detail: format!(
                        "Function '{}' contains division feeding into multiplication",
                        f.name
                    ),
                }],
            }],
            structural_explanation: format!(
                "Function '{}' has a/b*c ordering where truncated division feeds multiplication.",
                f.name
            ),
        });
    }

    hypotheses
}

/// Derive flash loan governance hypotheses.
///
/// Fires when ALL conditions hold:
/// - Function has `value_transfer == true` (moves tokens)
/// - Function has `state_mutation == true` (mutates state)
/// - Function has `has_temporal_guard == false` (no block.number/timestamp/guard)
/// - Function has NO enforced authority check
/// - Function reads at least one state variable that is also written by OTHER functions
///   (shared mutable state — the "inflatable" balance/deposit/share variable)
fn derive_flash_loan_governance_hypotheses(ir: &SystemIR) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    // Build the set of writable state variables.
    let writable: std::collections::BTreeSet<String> = ir
        .edges
        .iter()
        .filter_map(|e| match e {
            Edge::State(s) if s.access == "write" => Some(s.state.clone()),
            _ => None,
        })
        .collect();

    if writable.is_empty() {
        return hypotheses;
    }

    for f in &ir.functions {
        // Gate 1: value_transfer == true
        if !f.effects.value_transfer {
            continue;
        }
        // Gate 2: state_mutation == true
        if !f.effects.state_mutation {
            continue;
        }
        // Gate 3: has_temporal_guard == false
        if f.effects.has_temporal_guard {
            continue;
        }
        // Gate 3b: has_arithmetic == true (reward computation involves math
        // with the balance — pure transfers like transferFrom don't do this)
        if !f.effects.has_arithmetic {
            continue;
        }
        // Gate 3c: no external calls (internal distribution, not cross-contract)
        if f.effects.external_call {
            continue;
        }
        // Gate 4: no enforced authority check
        let has_enforced_authority = ir.edges.iter().any(|e| match e {
            Edge::Authority(a) => a.function == f.name && a.check_type == "enforced",
            _ => false,
        });
        if has_enforced_authority {
            continue;
        }

        // Gate 5: reads at least one state variable that is also written by OTHER functions
        let read_writable: Vec<String> = ir
            .edges
            .iter()
            .filter_map(|e| match e {
                Edge::State(s) if s.function == f.name && s.access == "read" => {
                    if writable.contains(&s.state) {
                        Some(s.state.clone())
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();

        if read_writable.is_empty() {
            continue;
        }

        // Structural gate: exclude state variables that this function also writes.
        let self_written: std::collections::BTreeSet<String> = ir
            .edges
            .iter()
            .filter_map(|e| match e {
                Edge::State(s) if s.function == f.name && s.access == "write" => {
                    Some(s.state.clone())
                }
                _ => None,
            })
            .collect();

        let externally_written: Vec<String> = read_writable
            .iter()
            .filter(|v| !self_written.contains(*v))
            .cloned()
            .collect();

        if externally_written.is_empty() {
            continue;
        }

        let evidence = vec![HypothesisEvidence {
            path_id: format!("PATH-FLGOV-{}", f.name),
            evidence_chain_id: format!("FIND-FLGOV-{}", f.name),
            involved_functions: vec![f.name.clone()],
            graph_facts: vec![
                GraphFact {
                    fact_type: "state_read".into(),
                    function: f.name.clone(),
                    detail: externally_written.join(", "),
                },
                GraphFact {
                    fact_type: "value_transfer".into(),
                    function: f.name.clone(),
                    detail: "function transfers value based on shared state".into(),
                },
                GraphFact {
                    fact_type: "no_temporal_guard".into(),
                    function: f.name.clone(),
                    detail: "no block.number/timestamp/guard pattern detected".into(),
                },
            ],
        }];

        hypotheses.push(Hypothesis {
            id: HypothesisId(format!("HYP-FLGOV-{}", f.name)),
            hypothesis_type: HypothesisType::FlashLoanGovernanceCandidate,
            severity: HypothesisSeverity::High,
            description: format!("Flash loan governance candidate in '{}'", f.name),
            primary_function: f.name.clone(),
            evidence,
            structural_explanation: format!(
                "Function '{}' reads shared mutable state variables [{}], \
                 transfers value, and mutates state without temporal guard or \
                 authority enforcement. Balance/deposit state can be inflated via \
                 flash loan to manipulate value distribution.",
                f.name,
                externally_written.join(", ")
            ),
        });
    }

    hypotheses
}

/// Derive Solana account-constraint hypotheses from missing/implicit AuthorityEdges.
///
/// The graph builder emits AuthorityEdge with check_type "missing" for
/// accounts in #[derive(Accounts)] structs that lack authority constraints.
/// This detector fires ONLY on those edges — it does NOT use a
/// public+state_mutation catch-all.
///
/// A corrected contract (constraints present) will NOT emit "missing" edges
/// from the builder, so this detector naturally stays silent on fixed code.
fn derive_missing_account_constraint_hypotheses(ir: &SystemIR) -> Vec<Hypothesis> {
    if ir.language != digger_ir::Language::Anchor {
        return vec![];
    }

    let mut hypotheses = vec![];
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for edge in &ir.edges {
        if let Edge::Authority(a) = edge {
            if a.check_type != "missing" && a.check_type != "implicit" {
                continue;
            }

            // Key on (function, authority_source) to deduplicate
            let key = format!("{}:{}", a.function, a.authority_source);
            if !seen.insert(key) {
                continue;
            }

            // Severity: has_one class = Critical, signer class = High, owner class = High
            let severity = if a.authority_source.contains(":has_one") {
                HypothesisSeverity::Critical
            } else {
                HypothesisSeverity::High
            };

            hypotheses.push(Hypothesis {
                id: HypothesisId(format!("HYP-ACCT-{}-{}", a.function, a.authority_source)),
                hypothesis_type: HypothesisType::MissingAccountConstraintCandidate,
                severity,
                description: format!(
                    "Missing constraint on '{}' in '{}' ({})",
                    a.authority_source, a.function, a.check_type
                ),
                primary_function: a.function.clone(),
                evidence: vec![HypothesisEvidence {
                    path_id: format!("PATH-ACCT-{}-{}", a.function, a.authority_source),
                    evidence_chain_id: format!("FIND-ACCT-{}-{}", a.function, a.authority_source),
                    involved_functions: vec![a.function.clone()],
                    graph_facts: vec![GraphFact {
                        fact_type: "missing_constraint".into(),
                        function: a.function.clone(),
                        detail: format!(
                            "account '{}' lacks constraint enforcement ({})",
                            a.authority_source, a.check_type
                        ),
                    }],
                }],
                structural_explanation: format!(
                    "Account '{}' in instruction '{}' is missing required \
                     constraint enforcement ({}) — no signer, has_one, owner, \
                     or seeds verification detected.",
                    a.authority_source, a.function, a.check_type
                ),
            });
        }
    }

    hypotheses
}

/// Derive economic invariant violation hypotheses from economic analysis.
///
/// Maps conservation, collateral, debt, and dependency violations to hypotheses.
fn derive_economic_invariant_hypotheses(
    _ir: &SystemIR,
    economic: &digger_economics::EconomicReport,
) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    for invariant in &economic.invariants {
        if !invariant.is_satisfied {
            // Find functions that preserve this invariant
            let involved_functions: Vec<String> = invariant.functions.to_vec();

            let evidence: Vec<HypothesisEvidence> = vec![HypothesisEvidence {
                path_id: format!("PATH-ECON-{}", invariant.invariant_id),
                evidence_chain_id: format!("FIND-ECON-{}", invariant.invariant_id),
                involved_functions: involved_functions.clone(),
                graph_facts: invariant
                    .evidence
                    .iter()
                    .map(|e| GraphFact {
                        fact_type: "economic_invariant".into(),
                        function: involved_functions.first().cloned().unwrap_or_default(),
                        detail: e.clone(),
                    })
                    .collect(),
            }];

            let severity = match invariant.kind {
                digger_economics::InvariantKind::Conservation => HypothesisSeverity::Critical,
                digger_economics::InvariantKind::Solvency => HypothesisSeverity::Critical,
                digger_economics::InvariantKind::Collateralization => HypothesisSeverity::High,
                digger_economics::InvariantKind::Accounting => HypothesisSeverity::High,
            };

            hypotheses.push(Hypothesis {
                id: HypothesisId(format!("HYP-ECON-{}", invariant.invariant_id)),
                hypothesis_type: HypothesisType::EconomicInvariantViolationCandidate,
                severity,
                description: format!("Economic invariant violation: {}", invariant.kind),
                primary_function: involved_functions.first().cloned().unwrap_or_default(),
                evidence,
                structural_explanation: format!(
                    "Protocol invariant '{}' involving state variables [{}] is violated. \
                     Functions [{}] must preserve this invariant. \
                     Violation consequence: {}",
                    invariant.kind,
                    invariant.state_vars.join(", "),
                    involved_functions.join(", "),
                    match invariant.kind {
                        digger_economics::InvariantKind::Conservation =>
                            "fund theft, infinite minting",
                        digger_economics::InvariantKind::Solvency =>
                            "bad debt, protocol insolvency",
                        digger_economics::InvariantKind::Collateralization =>
                            "under-collateralized positions",
                        digger_economics::InvariantKind::Accounting => "incorrect accounting state",
                    }
                ),
            });
        }
    }

    hypotheses
}

/// Derive adversarial path hypotheses from adversarial analysis.
///
/// Maps feasible attack goals to hypotheses.
fn derive_adversarial_path_hypotheses(
    _ir: &SystemIR,
    adversarial: &digger_adversarial::CapabilityReport,
) -> Vec<Hypothesis> {
    let mut hypotheses = vec![];

    for hypothesis in &adversarial.hypotheses {
        if !hypothesis.is_feasible {
            continue;
        }

        let primary_function = hypothesis
            .paths
            .first()
            .and_then(|p| p.steps.first())
            .map(|s| s.function.clone())
            .unwrap_or_default();

        let evidence: Vec<HypothesisEvidence> = vec![HypothesisEvidence {
            path_id: format!("PATH-ADV-{:?}", hypothesis.goal),
            evidence_chain_id: format!("FIND-ADV-{:?}", hypothesis.goal),
            involved_functions: vec![primary_function.clone()],
            graph_facts: hypothesis
                .evidence_graph
                .nodes
                .iter()
                .map(|n| GraphFact {
                    fact_type: "adversarial_evidence".into(),
                    function: primary_function.clone(),
                    detail: n.description.clone(),
                })
                .collect(),
        }];

        let severity = if hypothesis.confidence > 0.8 {
            HypothesisSeverity::Critical
        } else if hypothesis.confidence > 0.6 {
            HypothesisSeverity::High
        } else {
            HypothesisSeverity::Medium
        };

        hypotheses.push(Hypothesis {
            id: HypothesisId(format!("HYP-ADV-{:?}", hypothesis.goal)),
            hypothesis_type: HypothesisType::AdversarialPathCandidate,
            severity,
            description: format!(
                "Adversarial path for goal {:?} is feasible",
                hypothesis.goal
            ),
            primary_function,
            evidence,
            structural_explanation: format!(
                "Adversarial modeling confirms that goal {:?} is achievable \
                 with the detected capabilities. Confidence: {:.2}. \
                 Attack paths: {}",
                hypothesis.goal,
                hypothesis.confidence,
                hypothesis.paths.len()
            ),
        });
    }

    hypotheses
}

/// Build summary statistics.
fn build_summary(hypotheses: &[Hypothesis]) -> HypothesisSummary {
    let reentrancy_count = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::ReentrancyCandidate)
        .count();
    let authority_bypass_count = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
        .count();
    let cpi_trust_count = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::CPITrustViolationCandidate)
        .count();
    let state_corruption_count = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::StateCorruptionCandidate)
        .count();
    let economic_invariant_violation_count = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::EconomicInvariantViolationCandidate)
        .count();
    let adversarial_path_count = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::AdversarialPathCandidate)
        .count();
    let oracle_manipulation_count = hypotheses
        .iter()
        .filter(|h| h.hypothesis_type == HypothesisType::OracleManipulationCandidate)
        .count();

    let critical_count = hypotheses
        .iter()
        .filter(|h| h.severity == HypothesisSeverity::Critical)
        .count();
    let high_count = hypotheses
        .iter()
        .filter(|h| h.severity == HypothesisSeverity::High)
        .count();
    let medium_count = hypotheses
        .iter()
        .filter(|h| h.severity == HypothesisSeverity::Medium)
        .count();
    let low_count = hypotheses
        .iter()
        .filter(|h| h.severity == HypothesisSeverity::Low)
        .count();
    let info_count = hypotheses
        .iter()
        .filter(|h| h.severity == HypothesisSeverity::Info)
        .count();

    HypothesisSummary {
        total: hypotheses.len(),
        reentrancy_count,
        authority_bypass_count,
        cpi_trust_count,
        state_corruption_count,
        economic_invariant_violation_count,
        adversarial_path_count,
        oracle_manipulation_count,
        flash_loan_governance_count: hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .count(),
        missing_account_constraint_count: hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::MissingAccountConstraintCandidate)
            .count(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
    }
}

/// Map a HypothesisType to the corpus VulnerabilityClass display strings
/// it structurally corresponds to. Returns a Vec of canonical class strings
/// that the by_class index can key on. No prose, no NL matching.
pub fn hypothesis_type_to_corpus_classes(ht: &HypothesisType) -> Vec<&'static str> {
    match ht {
        HypothesisType::ReentrancyCandidate => {
            vec![
                "reentrancy",
                "cross_function_reentrancy",
                "cross_contract_reentrancy",
            ]
        }
        HypothesisType::AuthorityBypassCandidate
        | HypothesisType::MissingAccountConstraintCandidate => {
            vec![
                "missing_access_control",
                "privilege_escalation",
                "unprotected_initialization",
            ]
        }
        HypothesisType::CPITrustViolationCandidate => {
            vec![
                "cross_contract_reentrancy",
                "cross_protocol_dependency",
                "composability_risk",
            ]
        }
        HypothesisType::StateCorruptionCandidate => {
            vec!["state_corruption", "storage_collision"]
        }
        HypothesisType::EconomicInvariantViolationCandidate => {
            vec!["invariant_violation", "precision_loss", "rounding_error"]
        }
        HypothesisType::AdversarialPathCandidate => {
            vec!["business_logic_flaw", "missing_validation"]
        }
        HypothesisType::OracleManipulationCandidate => {
            vec!["oracle_manipulation", "price_manipulation"]
        }
        HypothesisType::FlashLoanGovernanceCandidate => {
            vec!["flash_loan_attack", "governance_attack"]
        }
        HypothesisType::UncheckedArithmeticCandidate => {
            vec!["integer_overflow", "rounding_error", "precision_loss"]
        }
        HypothesisType::PrecisionLossCandidate => {
            vec!["precision_loss", "rounding_error", "incorrect_calculation"]
        }
    }
}

/// Map a HypothesisType to corpus AttackTechnique display strings.
pub fn hypothesis_type_to_corpus_techniques(ht: &HypothesisType) -> Vec<&'static str> {
    match ht {
        HypothesisType::ReentrancyCandidate => {
            vec!["reentrancy_exploit", "state_manipulation_cross_function"]
        }
        HypothesisType::AuthorityBypassCandidate
        | HypothesisType::MissingAccountConstraintCandidate => {
            vec!["access_control_bypass"]
        }
        HypothesisType::CPITrustViolationCandidate => {
            vec!["delegatecall_exploitation", "unchecked_external_call"]
        }
        HypothesisType::StateCorruptionCandidate => {
            vec![
                "state_manipulation_cross_function",
                "storage_collision_exploit",
            ]
        }
        HypothesisType::EconomicInvariantViolationCandidate => {
            vec!["precision_loss_exploitation"]
        }
        HypothesisType::AdversarialPathCandidate => {
            vec!["access_control_bypass", "unchecked_external_call"]
        }
        HypothesisType::OracleManipulationCandidate => {
            vec!["price_oracle_manipulation"]
        }
        HypothesisType::FlashLoanGovernanceCandidate => {
            vec!["flash_loan_borrow"]
        }
        HypothesisType::UncheckedArithmeticCandidate => {
            vec!["precision_loss_exploitation"]
        }
        HypothesisType::PrecisionLossCandidate => {
            vec!["precision_loss_exploitation"]
        }
    }
}

/// Attach structured corpus evidence to already-derived hypotheses.
///
/// SAFETY INVARIANT: This function MUST NOT add, remove, re-gate, re-rank,
/// or re-severity any hypothesis. It ONLY appends GraphFact entries with
/// `fact_type = "corpus_match"` to existing hypotheses' evidence vectors.
/// The detected set is UNCHANGED.
///
/// Matching is STRUCTURED-ONLY: keys off VulnerabilityClass / AttackTechnique
/// display strings (closed enums) via the by_class / by_technique BTreeMap
/// indexes. No natural-language, no prose, no substring matching.
fn attach_corpus_evidence(
    hypotheses: &mut [Hypothesis],
    store: &digger_knowledge_models::HistoricalFindingStore,
    snapshot_id: Option<&str>,
    source_id: Option<&str>,
) {
    if store.is_empty() {
        return;
    }

    // Build a lookup: finding_id -> protocol_domain (for enrichment metadata)
    let domain_lookup: std::collections::BTreeMap<String, String> = store
        .findings
        .iter()
        .map(|f| (f.finding_id.clone(), f.protocol_domain.to_string()))
        .collect();

    let snap = snapshot_id.unwrap_or("none");
    let src = source_id.unwrap_or("unknown");

    for h in hypotheses.iter_mut() {
        let mut matched_refs: Vec<(String, String, String)> = Vec::new();
        // (finding_id, dimension_key, matched_value)

        // Dimension 1: by_class (VulnerabilityClass)
        let classes = hypothesis_type_to_corpus_classes(&h.hypothesis_type);
        for class_str in &classes {
            if let Some(finding_ids) = store.by_class.get(*class_str) {
                for fid in finding_ids {
                    matched_refs.push((fid.clone(), "class".to_string(), class_str.to_string()));
                }
            }
        }

        // Dimension 2: by_technique (AttackTechnique)
        let techniques = hypothesis_type_to_corpus_techniques(&h.hypothesis_type);
        for tech_str in &techniques {
            if let Some(finding_ids) = store.by_technique.get(*tech_str) {
                for fid in finding_ids {
                    if !matched_refs
                        .iter()
                        .any(|(existing_fid, _, _)| existing_fid == fid)
                    {
                        matched_refs.push((
                            fid.clone(),
                            "technique".to_string(),
                            tech_str.to_string(),
                        ));
                    }
                }
            }
        }

        // Stable sort for determinism.
        matched_refs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        if matched_refs.is_empty() {
            continue;
        }

        // Group ALL corpus matches into ONE HypothesisEvidence entry.
        let graph_facts: Vec<GraphFact> = matched_refs
            .into_iter()
            .take(5)
            .map(|(finding_id, dimension, value)| {
                let domain = domain_lookup
                    .get(&finding_id)
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                GraphFact {
                    fact_type: "corpus_match".to_string(),
                    function: finding_id,
                    detail: format!("{dimension}:{value}:{domain}:{snap}:{src}"),
                }
            })
            .collect();

        h.evidence.push(HypothesisEvidence {
            path_id: String::new(),
            evidence_chain_id: String::new(),
            involved_functions: vec![],
            graph_facts,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_graph::build_system_ir;
    use digger_ir::CallKind;
    use digger_parser::model::*;

    /// IR with a public function that has NO authority check.
    fn ir_public_no_authority() -> SystemIR {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "setOwner".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "owner = newOwner".into(),
                ..Default::default()
            }],
            state: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    /// IR with a public function that HAS an enforced authority check.
    fn ir_public_with_authority() -> SystemIR {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "setOwner".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "require(msg.sender == owner); owner = newOwner".into(),
                ..Default::default()
            }],
            state: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    /// IR with a private function — should NOT fire.
    fn ir_private_no_authority() -> SystemIR {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "setOwner".into(),
                visibility: "private".into(),
                inputs: vec![],
                body: "owner = newOwner".into(),
                ..Default::default()
            }],
            state: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    #[test]
    fn public_function_missing_authority_emits_hypothesis() {
        let ir = ir_public_no_authority();
        let result = derive(&ir);
        let auth_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
            .collect();
        assert_eq!(auth_hyps.len(), 1, "should emit one authority bypass");
        assert_eq!(auth_hyps[0].primary_function, "setOwner");
        assert_eq!(auth_hyps[0].severity, HypothesisSeverity::Medium);
    }

    #[test]
    fn public_function_with_enforced_authority_does_not_fire() {
        let ir = ir_public_with_authority();
        let result = derive(&ir);
        let auth_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
            .collect();
        assert!(
            auth_hyps.is_empty(),
            "should NOT emit authority bypass for guarded function, got: {:?}",
            auth_hyps
        );
    }

    #[test]
    fn private_function_missing_authority_does_not_fire() {
        let ir = ir_private_no_authority();
        let result = derive(&ir);
        let auth_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::AuthorityBypassCandidate)
            .collect();
        assert!(
            auth_hyps.is_empty(),
            "should NOT emit authority bypass for private function"
        );
    }

    #[test]
    fn determinism_of_derivation() {
        let ir = ir_public_no_authority();
        let r1 = format!("{:#?}", derive(&ir));
        let r2 = format!("{:#?}", derive(&ir));
        assert_eq!(r1, r2, "derive must be deterministic");
    }

    // ── Oracle manipulation tests ─────────────────────────────────────

    /// POSITIVE: convert reads rate (writable by setRate), has value_transfer,
    /// no external call → MUST produce OracleManipulationCandidate.
    fn ir_oracle_positive() -> SystemIR {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "setRate".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "rate = newRate".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "convert".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "amount = input * rate; transfer(msg.sender, amount)".into(),
                    ..Default::default()
                },
            ],
            state: vec![RawState {
                name: "rate".into(),
                ty: "uint256".into(),
                ..Default::default()
            }],
            calls: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    /// NEGATIVE: external feed — should NOT fire (external_call = true).
    fn ir_oracle_negative_external_feed() -> SystemIR {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "getPrice".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "price = oracle.getPrice(); transfer(msg.sender, amount)".into(),
                ..Default::default()
            }],
            state: vec![],
            calls: vec![RawCall {
                from: "getPrice".into(),
                to: "oracle".into(),
                kind: CallKind::External,
            }],
            ..Default::default()
        };
        build_system_ir(program)
    }

    /// NEGATIVE: config counter — should NOT fire (no value_transfer).
    fn ir_oracle_negative_config_counter() -> SystemIR {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "increment".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "counter += 1".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "counter".into(),
                ty: "uint256".into(),
                ..Default::default()
            }],
            calls: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    #[test]
    fn oracle_manipulation_positive_fires() {
        let ir = ir_oracle_positive();
        let result = derive(&ir);
        let oracle_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::OracleManipulationCandidate)
            .collect();
        assert_eq!(
            oracle_hyps.len(),
            1,
            "should emit exactly one OracleManipulationCandidate, got: {:?}",
            oracle_hyps
        );
        assert_eq!(oracle_hyps[0].primary_function, "convert");
        assert_eq!(oracle_hyps[0].severity, HypothesisSeverity::High);
    }

    #[test]
    fn oracle_manipulation_negative_external_feed() {
        let ir = ir_oracle_negative_external_feed();
        let result = derive(&ir);
        let oracle_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::OracleManipulationCandidate)
            .collect();
        assert!(
            oracle_hyps.is_empty(),
            "should NOT emit OracleManipulationCandidate for external feed, got: {:?}",
            oracle_hyps
        );
    }

    #[test]
    fn oracle_manipulation_negative_config_counter() {
        let ir = ir_oracle_negative_config_counter();
        let result = derive(&ir);
        let oracle_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::OracleManipulationCandidate)
            .collect();
        assert!(
            oracle_hyps.is_empty(),
            "should NOT emit OracleManipulationCandidate for config counter, got: {:?}",
            oracle_hyps
        );
    }

    /// NEGATIVE: function reads AND writes the same writable state (token pattern).
    /// Should NOT fire because the state it reads is also written by itself.
    fn ir_oracle_negative_self_contained_state() -> SystemIR {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "transferFrom".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "allowances[from][msg.sender] -= amount; balances[to] += amount".into(),
                ..Default::default()
            }],
            state: vec![
                RawState {
                    name: "allowances".into(),
                    ty: "mapping".into(),
                    ..Default::default()
                },
                RawState {
                    name: "balances".into(),
                    ty: "mapping".into(),
                    ..Default::default()
                },
            ],
            calls: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    #[test]
    fn oracle_manipulation_negative_self_contained_state() {
        let ir = ir_oracle_negative_self_contained_state();
        let result = derive(&ir);
        let oracle_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::OracleManipulationCandidate)
            .collect();
        assert!(
            oracle_hyps.is_empty(),
            "should NOT emit OracleManipulationCandidate when function reads and writes same state, got: {:?}",
            oracle_hyps
        );
    }

    /// Cross-contract anti-regression: ContractA.deposit (no arithmetic, no .mul)
    /// must NOT inherit has_arithmetic from ContractB.priceCalc (which has .mul/.div)
    /// even though both exist in the same concatenated source. The contract-scoped
    /// call graph prevents false cross-contract Call edges.
    #[test]
    fn oracle_no_cross_contract_arithmetic_leak() {
        use digger_parser::model::{RawFunction, RawProgram, RawState};

        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "deposit".into(),
                    contract: "Vault".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "balances[msg.sender] += amount".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "priceCalc".into(),
                    contract: "Oracle".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "result = price.mul(amount).div(1000)".into(),
                    ..Default::default()
                },
            ],
            state: vec![
                RawState {
                    name: "balances".into(),
                    ty: "mapping".into(),
                    ..Default::default()
                },
                RawState {
                    name: "price".into(),
                    ty: "uint256".into(),
                    ..Default::default()
                },
            ],
            calls: vec![],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = derive(&ir);

        // deposit should NOT have has_arithmetic — it's in Vault, not Oracle
        let deposit_fn = ir.functions.iter().find(|f| f.name == "deposit").unwrap();
        assert!(
            !deposit_fn.effects.has_arithmetic,
            "deposit in Vault must NOT inherit has_arithmetic from Oracle.priceCalc"
        );

        // deposit should NOT get an oracle hypothesis
        let oracle_for_deposit: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| {
                h.hypothesis_type == HypothesisType::OracleManipulationCandidate
                    && h.primary_function == "deposit"
            })
            .collect();
        assert!(
            oracle_for_deposit.is_empty(),
            "deposit must NOT get oracle hypothesis from cross-contract arithmetic leak"
        );
    }

    // ── Flash loan governance tests ─────────────────────────────────

    /// POSITIVE: function reads balance state, computes reward via arithmetic,
    /// has value_transfer + state_mutation, no temporal guard, no authority.
    fn ir_flashloan_positive() -> SystemIR {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "sweepAwards".into(),
                    contract: "PrizePool".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "accrued = balances[msg.sender] * prizeRate / SCALE; transfer(msg.sender, accrued)"
                        .into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "deposit".into(),
                    contract: "PrizePool".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "balances[msg.sender] += msg.value".into(),
                    ..Default::default()
                },
            ],
            state: vec![RawState {
                name: "balances".into(),
                ty: "mapping".into(),
                ..Default::default()
            }],
            calls: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    #[test]
    fn flash_loan_governance_positive_fires() {
        let ir = ir_flashloan_positive();
        let result = derive(&ir);
        let flgov_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .collect();
        assert_eq!(
            flgov_hyps.len(),
            1,
            "should emit exactly one FlashLoanGovernanceCandidate, got: {:?}",
            flgov_hyps
        );
        assert_eq!(flgov_hyps[0].primary_function, "sweepAwards");
        assert_eq!(flgov_hyps[0].severity, HypothesisSeverity::High);
    }

    /// NEGATIVE CONTROL 1: temporal-guarded governance fn (block.number check).
    /// Should NOT fire because has_temporal_guard == true.
    fn ir_flashloan_negative_guarded() -> SystemIR {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "distributePrizes".into(),
                    contract: "PrizePool".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "require(block.number > lastDistribution); lastDistribution = block.number; transfer(msg.sender, accrued)"
                        .into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "deposit".into(),
                    contract: "PrizePool".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "balances[msg.sender] += msg.value".into(),
                    ..Default::default()
                },
            ],
            state: vec![RawState {
                name: "balances".into(),
                ty: "mapping".into(),
                ..Default::default()
            }],
            calls: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    #[test]
    fn flash_loan_governance_negative_guarded() {
        let ir = ir_flashloan_negative_guarded();
        let result = derive(&ir);
        let flgov_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .collect();
        assert!(
            flgov_hyps.is_empty(),
            "should NOT emit FlashLoanGovernanceCandidate for temporal-guarded function, got: {:?}",
            flgov_hyps
        );
    }

    /// NEGATIVE CONTROL 2: balance read with no value/reward decision.
    /// Should NOT fire because value_transfer == false.
    fn ir_flashloan_negative_no_decision() -> SystemIR {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "getBalance".into(),
                contract: "Vault".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "return balances[msg.sender]".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "balances".into(),
                ty: "mapping".into(),
                ..Default::default()
            }],
            calls: vec![],
            ..Default::default()
        };
        build_system_ir(program)
    }

    #[test]
    fn flash_loan_governance_negative_no_decision() {
        let ir = ir_flashloan_negative_no_decision();
        let result = derive(&ir);
        let flgov_hyps: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .collect();
        assert!(
            flgov_hyps.is_empty(),
            "should NOT emit FlashLoanGovernanceCandidate when no value/reward decision, got: {:?}",
            flgov_hyps
        );
    }

    /// CROSS-CONTRACT ANTI-REGRESSION: ContractA.deposit (no flashloan)
    /// must NOT get FlashLoanGovernanceCandidate from ContractB.priceCalc.
    #[test]
    fn flash_loan_no_cross_contract_leak() {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "deposit".into(),
                    contract: "Vault".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "balances[msg.sender] += amount".into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "priceCalc".into(),
                    contract: "Oracle".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "result = price.mul(amount).div(1000)".into(),
                    ..Default::default()
                },
            ],
            state: vec![
                RawState {
                    name: "balances".into(),
                    ty: "mapping".into(),
                    ..Default::default()
                },
                RawState {
                    name: "price".into(),
                    ty: "uint256".into(),
                    ..Default::default()
                },
            ],
            calls: vec![],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = derive(&ir);

        let flgov_for_deposit: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| {
                h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate
                    && h.primary_function == "deposit"
            })
            .collect();
        assert!(
            flgov_for_deposit.is_empty(),
            "deposit must NOT get FlashLoanGovernanceCandidate from cross-contract leak"
        );
    }

    /// flash_loan_governance_count must match actual count in summary.
    #[test]
    fn flash_loan_summary_count_matches() {
        let ir = ir_flashloan_positive();
        let result = derive(&ir);
        let actual = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .count();
        assert_eq!(result.summary.flash_loan_governance_count, actual);
    }

    /// NEGATIVE: simple transfer with arithmetic but no shared balance read.
    /// The amount is a fixed constant, not derived from inflatable state.
    /// Proves the detector isn't just "has_arithmetic + value_transfer = alert."
    #[test]
    fn flash_loan_negative_no_shared_balance() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "distributeFixed".into(),
                contract: "Rewards".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "amount = 1000 * 10 ** 18; transfer(msg.sender, amount)".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "treasury".into(),
                ty: "uint256".into(),
                ..Default::default()
            }],
            calls: vec![],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = derive(&ir);
        let flgov: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .collect();
        assert!(
            flgov.is_empty(),
            "distributeFixed must NOT fire — amount is constant, not from shared balance. Got: {:?}",
            flgov
        );
    }

    /// NEGATIVE: reward fn WITH snapshot guard (withdrawal delay).
    /// The has_temporal_guard flag should suppress it even though it
    /// reads shared balance and has arithmetic + value_transfer.
    #[test]
    fn flash_loan_negative_snapshot_guarded() {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "claimReward".into(),
                    contract: "Staking".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "require(block.timestamp >= unlockTime[msg.sender]); amount = staked[msg.sender] * rewardRate / SCALE; transfer(msg.sender, amount)"
                        .into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "stake".into(),
                    contract: "Staking".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "staked[msg.sender] += msg.value; unlockTime[msg.sender] = block.timestamp + 7 days"
                        .into(),
                    ..Default::default()
                },
            ],
            state: vec![
                RawState {
                    name: "staked".into(),
                    ty: "mapping".into(),
                    ..Default::default()
                },
                RawState {
                    name: "unlockTime".into(),
                    ty: "mapping".into(),
                    ..Default::default()
                },
            ],
            calls: vec![],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = derive(&ir);
        let flgov: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .collect();
        assert!(
            flgov.is_empty(),
            "claimReward must NOT fire — has temporal guard (unlockTime + block.timestamp). Got: {:?}",
            flgov
        );
    }

    // ── Flash-loan recall boundary tests ────────────────────────────

    /// POSITIVE: reward fn using SafeMath library calls (.mul/.div) instead of
    /// inline operators. The text fallback catches .mul()/.div() — this should fire.
    /// This is the likely pattern for real DeFi reward contracts.
    #[test]
    fn flash_loan_safemath_library_fires() {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "claimReward".into(),
                    contract: "Staking".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "accrued = staked[msg.sender].mul(rewardRate).div(SCALE); transfer(msg.sender, accrued)"
                        .into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "stake".into(),
                    contract: "Staking".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "staked[msg.sender] += msg.value".into(),
                    ..Default::default()
                },
            ],
            state: vec![RawState {
                name: "staked".into(),
                ty: "mapping".into(),
                ..Default::default()
            }],
            calls: vec![],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = derive(&ir);
        let flgov: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .collect();
        assert_eq!(
            flgov.len(),
            1,
            "SafeMath .mul()/.div() reward fn should fire. Got: {:?}",
            flgov
        );
    }

    /// KNOWN LIMITATION: reward fn that routes payout through external .call().
    /// The flash-loan detector requires !external_call, so this does NOT fire.
    /// This is a genuine recall boundary: the detector fires only on INTERNAL
    /// transfers, not external-call payouts. Closing this gap requires
    /// value-from-balance data-flow analysis beyond the current IR.
    #[test]
    fn flash_loan_external_call_payout_does_not_fire() {
        let program = RawProgram {
            functions: vec![
                RawFunction {
                    name: "claimReward".into(),
                    contract: "Staking".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "accrued = staked[msg.sender] * rewardRate; (bool ok,) = msg.sender.call{value: accrued}(\"\")"
                        .into(),
                    ..Default::default()
                },
                RawFunction {
                    name: "stake".into(),
                    contract: "Staking".into(),
                    visibility: "public".into(),
                    inputs: vec![],
                    body: "staked[msg.sender] += msg.value".into(),
                    ..Default::default()
                },
            ],
            state: vec![RawState {
                name: "staked".into(),
                ty: "mapping".into(),
                ..Default::default()
            }],
            calls: vec![RawCall {
                from: "claimReward".into(),
                to: "external".into(),
                kind: digger_ir::CallKind::External,
            }],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = derive(&ir);
        let flgov: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| h.hypothesis_type == HypothesisType::FlashLoanGovernanceCandidate)
            .collect();
        assert!(
            flgov.is_empty(),
            "External-call payout MUST NOT fire — known recall boundary. Got: {:?}",
            flgov
        );
    }

    // ── Authority tiering regression tests ──────────────────────────

    /// POLY-SHAPED: config setter writes a non-mapping (struct/bytes) state var.
    /// MUST stay Critical — this is the pattern Poly's putCurEpochConnectPubBytes
    /// exploits. If this demotes to Medium, a real missing-auth bug would be buried.
    #[test]
    fn tiering_non_mapping_state_stays_critical() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "setConfig".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "config = newConfig".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "config".into(),
                ty: "bytes".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = derive(&ir);
        let auth: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| {
                h.hypothesis_type == HypothesisType::AuthorityBypassCandidate
                    && h.primary_function == "setConfig"
            })
            .collect();
        assert_eq!(
            auth.len(),
            1,
            "setConfig should emit one authority hypothesis"
        );
        assert_eq!(
            auth[0].severity,
            HypothesisSeverity::Critical,
            "Config setter writing non-mapping state MUST stay Critical"
        );
    }

    /// Self-scoped function writing ONLY to mapping state demotes to Medium.
    /// This is the permissionless-by-design pattern (deposit/transfer to self).
    #[test]
    fn tiering_mapping_only_state_demotes_to_medium() {
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "deposit".into(),
                visibility: "public".into(),
                inputs: vec![],
                body: "balances[msg.sender] += amount".into(),
                ..Default::default()
            }],
            state: vec![RawState {
                name: "balances".into(),
                ty: "mapping(address => uint256)".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let ir = build_system_ir(program);
        let result = derive(&ir);
        let auth: Vec<_> = result
            .hypotheses
            .iter()
            .filter(|h| {
                h.hypothesis_type == HypothesisType::AuthorityBypassCandidate
                    && h.primary_function == "deposit"
            })
            .collect();
        assert_eq!(
            auth.len(),
            1,
            "deposit should emit one authority hypothesis"
        );
        assert_eq!(
            auth[0].severity,
            HypothesisSeverity::Medium,
            "Self-scoped mapping-only function should demote to Medium"
        );
    }
}
