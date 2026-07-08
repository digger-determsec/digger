//! Knowledge-informed suspicion channel — UNPROVEN advisory, weaker than a Hypothesis.
//!
//! ## Reconciliation of what emits each hypothesis type:
//!
//! `derive_oracle_manipulation_hypotheses` (derivation.rs:729) emits
//! OracleManipulationCandidate when ALL hold:
//!   - value_transfer == true
//!   - external_call == false
//!   - arithmetic feeds value transfer (structured: arithmetic_feeds_value_transfer
//!     && state_reads_in_arithmetic intersection writable is non-empty; fallback: has_arithmetic)
//!   - reads a writable state var NOT self-written
//!
//! `derive_flash_loan_governance_hypotheses` (derivation.rs:1007) emits
//! FlashLoanGovernanceCandidate when ALL hold:
//!   - value_transfer == true
//!   - state_mutation == true
//!   - has_temporal_guard == false
//!   - has_arithmetic == true
//!   - external_call == false
//!   - no enforced authority check
//!   - reads a writable state var written by OTHER functions
//!
//! ## Corpus domain scoping gap
//!
//! LIMITATION: SystemIR does not carry protocol_domain. The corpus prior is
//! scoped ONLY by by_class key (structural class match), NOT by the target's
//! protocol domain. A vault suspicion draws on all "oracle_manipulation"
//! findings regardless of whether the corpus finding was from a vault, a DEX,
//! or a bridge. This reduces analogical discrimination but does NOT create
//! false positives — the structural precondition must always hold first.
//! Future improvement: thread protocol_domain through SystemIR or accept it
//! as an optional DerivationContext parameter.
//!
//! Both detectors require `external_call == false`. The suspicion channel fills
//! the structural gap: functions that match the oracle/flash-loan PRECONDITION
//! but whose detection was already satisfied by the real hypothesis. A suspicion
//! fires ONLY for a (function, class) pair that has NO corresponding hypothesis,
//! meaning the real detector abstained or the function doesn't fully qualify.
//!
//! ## Invariants
//!
//! - Suspicions live in a SEPARATE SuspicionResult.
//! - They are NEVER added to HypothesisResult.hypotheses or HypothesisSummary.
//! - The derived hypothesis/finding set (ids, count, types, severity, is_finding)
//!   is BYTE-IDENTICAL with or without corpus.
//! - `is_finding` is ALWAYS false on every suspicion.

use digger_ir::SystemIR;
use serde::{Deserialize, Serialize};

/// Maps to the existing HypothesisType for the analogized vulnerability class.
pub use crate::models::HypothesisType as SuspicionClass;

/// Structured corpus prior — what the corpus knows about this class.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorpusPrior {
    pub matched_key: String,
    pub finding_count: usize,
    pub snapshot_id: String,
    pub source_id: String,
}

/// An unproven suspicion — knowledge-informed, structurally gated, never a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Suspicion {
    pub id: String,
    pub class: SuspicionClass,
    pub primary_function: String,
    pub structural_reason: String,
    pub corpus_prior: CorpusPrior,
    /// ALWAYS false.
    pub is_finding: bool,
}

/// Result of the suspicion derivation pass — SEPARATE from HypothesisResult.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SuspicionResult {
    pub program_id: String,
    pub suspicions: Vec<Suspicion>,
}

impl SuspicionResult {
    pub fn empty(program_id: &str) -> Self {
        Self {
            program_id: program_id.to_string(),
            suspicions: vec![],
        }
    }
}

/// Derive unproven suspicions from SystemIR + corpus knowledge.
///
/// `hypotheses` is the already-derived HypothesisResult. Suspicions MUST NOT
/// fire for any (function, class) that already has a real hypothesis.
pub fn derive_suspicions(
    ir: &SystemIR,
    hypotheses: &crate::models::HypothesisResult,
    store: Option<&digger_knowledge_models::HistoricalFindingStore>,
    snapshot_id: Option<&str>,
    source_id: Option<&str>,
) -> SuspicionResult {
    let mut result = SuspicionResult::empty(&ir.program_id);

    let store = match store {
        Some(s) if !s.is_empty() => s,
        _ => return result,
    };

    let snap = snapshot_id.unwrap_or("none");
    let src = source_id.unwrap_or("unknown");

    // Build dedup set: (function_name, type_name_str) already present
    let existing: std::collections::HashSet<(String, String)> = hypotheses
        .hypotheses
        .iter()
        .map(|h| (h.primary_function.clone(), h.hypothesis_type.to_string()))
        .collect();

    // Build writable state set
    let writable: std::collections::BTreeSet<String> = ir
        .edges
        .iter()
        .filter_map(|e| match e {
            digger_ir::Edge::State(s) if s.access == "write" => Some(s.state.clone()),
            _ => None,
        })
        .collect();

    // Build enforced-authority set
    let enforced_authority: std::collections::BTreeSet<String> = ir
        .edges
        .iter()
        .filter_map(|e| match e {
            digger_ir::Edge::Authority(a) if a.check_type == "enforced" => Some(a.function.clone()),
            _ => None,
        })
        .collect();

    for f in &ir.functions {
        let fn_name = f.name.as_str();

        // ─── CLASS A: oracle-price-from-internal-state near-miss ───
        // The real oracle detector fires when: value_transfer + !external_call +
        // arithmetic_feeds_value_transfer + reads writable-not-self-written.
        // This suspicion fires when the SAME structural precondition holds but
        // the real detector did NOT emit a hypothesis for this function.
        // This is the "near-miss" the detector missed.
        if f.effects.value_transfer && f.effects.has_arithmetic {
            let reads_writable_in_arith = if let Some(ref vf) = f.effects.value_flow {
                vf.arithmetic_feeds_value_transfer
                    && vf
                        .state_reads_in_arithmetic
                        .iter()
                        .any(|var| writable.contains(var))
            } else {
                false
            };

            if reads_writable_in_arith {
                // Check: reads a writable var NOT self-written
                let self_written: std::collections::BTreeSet<String> = ir
                    .edges
                    .iter()
                    .filter_map(|e| match e {
                        digger_ir::Edge::State(s)
                            if s.function == fn_name && s.access == "write" =>
                        {
                            Some(s.state.clone())
                        }
                        _ => None,
                    })
                    .collect();

                let reads_external_writable = if let Some(ref vf) = f.effects.value_flow {
                    vf.state_reads
                        .iter()
                        .any(|var| writable.contains(var) && !self_written.contains(var))
                } else {
                    false
                };

                if reads_external_writable {
                    // Dedup: skip if real oracle hypothesis already fired
                    if !existing.contains(&(
                        f.name.clone(),
                        SuspicionClass::OracleManipulationCandidate.to_string(),
                    )) {
                        // Corpus prior: require oracle_manipulation or price_manipulation
                        let corpus_key = ["oracle_manipulation", "price_manipulation"]
                            .iter()
                            .find(|k| store.by_class.contains_key(**k));

                        if let Some(key) = corpus_key {
                            let count = store.by_class[*key].len();
                            result.suspicions.push(Suspicion {
                                id: format!("SUSP-ORACLE-{}", f.name),
                                class: SuspicionClass::OracleManipulationCandidate,
                                primary_function: f.name.clone(),
                                structural_reason: "internal state read through arithmetic into transfer, no real oracle hypothesis fired".to_string(),
                                corpus_prior: CorpusPrior {
                                    matched_key: key.to_string(),
                                    finding_count: count,
                                    snapshot_id: snap.to_string(),
                                    source_id: src.to_string(),
                                },
                                is_finding: false,
                            });
                        }
                    }
                }
            }
        }

        // ─── CLASS B: flash-loan-governance (Pass-5 deferral) ───
        // The real flash-loan detector fires when: value_transfer + state_mutation +
        // !has_temporal_guard + has_arithmetic + !external_call + no authority +
        // reads writable written by others.
        // This suspicion fires on the WIDER signal the Pass-5 deferral identified:
        // balance-derived reward + no temporal guard (the distinguishing indicator).
        // external_call is NOT a gate — flash-loan manipulation is same-tx.
        if f.effects.value_transfer && f.effects.has_arithmetic && !f.effects.has_temporal_guard {
            let reads_balance = f
                .effects
                .value_flow
                .as_ref()
                .map(|vf| vf.reads_balance_through_arithmetic && vf.arithmetic_feeds_value_transfer)
                .unwrap_or(false);

            if reads_balance {
                // No enforced authority
                if !enforced_authority.contains(&f.name) {
                    // Dedup: skip if real flash-loan hypothesis already fired
                    if !existing.contains(&(
                        f.name.clone(),
                        SuspicionClass::FlashLoanGovernanceCandidate.to_string(),
                    )) {
                        let corpus_key = ["flash_loan_attack", "governance_attack"]
                            .iter()
                            .find(|k| store.by_class.contains_key(**k));

                        if let Some(key) = corpus_key {
                            let count = store.by_class[*key].len();
                            result.suspicions.push(Suspicion {
                                id: format!("SUSP-FLOAN-{}", f.name),
                                class: SuspicionClass::FlashLoanGovernanceCandidate,
                                primary_function: f.name.clone(),
                                structural_reason: "balance-derived reward through arithmetic into transfer, no temporal guard, no real flash-loan hypothesis fired".to_string(),
                                corpus_prior: CorpusPrior {
                                    matched_key: key.to_string(),
                                    finding_count: count,
                                    snapshot_id: snap.to_string(),
                                    source_id: src.to_string(),
                                },
                                is_finding: false,
                            });
                        }
                    }
                }
            }
        }
    }

    result.suspicions.sort_by(|a, b| a.id.cmp(&b.id));
    result
}
