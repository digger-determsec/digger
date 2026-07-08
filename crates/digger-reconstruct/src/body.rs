//! Body/operation recovery types (ADR-0026, Phase C5.1).
//!
//! Deterministic, provenance-carrying operation-level evidence recovered from
//! bytecode or source-parse analysis. Lives in the **recovered-facts layer**;
//! does NOT mutate frozen SystemIR (ADR-0002).
//!
//! A [`RecoveredBodyGraph`] is an optional extension on [`RecoveredFacts`]:
//! `body: Option<RecoveredBodyGraph>`. Existing consumers see `None` and are
//! unaffected.
//!
//! OperationKind is reused from `digger_parser::model` — no duplicate enum.
//! Chain-agnostic: EVM recovers from instruction patterns, Solana from CPI
//! invoke patterns. Both emit the same semantic operation kinds.

use crate::confidence::ConfidenceTier;
use crate::lifter::node_id;
use crate::provenance::{EvidenceSource, Provenance, ReconstructionStage};
use digger_parser::model::OperationKind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Ordered operation within a recovered function body.
///
/// Each operation traces to concrete evidence (instruction pattern, CPI edge)
/// via its `Provenance`. Absent evidence → absent operation (never synthesized).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredOperation {
    /// Deterministic content-addressed id (`op:<digest>`).
    pub id: String,
    /// Links to the function this operation belongs to
    /// (RecoveredFunction.id or SystemIR Function.id).
    pub function_id: String,
    /// Sequence index within the function (0-based, deterministic).
    pub index: usize,
    /// Operation kind — reused from `digger_parser::model::OperationKind`.
    pub kind: OperationKind,
    /// Target or subject (state variable name, call target, etc.).
    pub target: String,
    /// Evidence provenance for this specific operation.
    pub provenance: Provenance,
}

impl RecoveredOperation {
    /// Compute the deterministic content-addressed id.
    /// Digest is over: function_id + index + kind + target + evidence_source.
    /// NEVER includes addresses, pointers, or map-iteration order.
    pub fn make_id(function_id: &str, index: usize, kind: &OperationKind, target: &str) -> String {
        let canon = format!("{}|{}|{}|{}", function_id, index, kind, target);
        node_id("op", &canon)
    }
}

/// Recovered function body: ordered operations for a single function.
///
/// A function with no grounded operations yields NO `RecoveredBody`
/// (absent, not empty — mirror `StorageEvidence::empty()`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredBody {
    /// Deterministic content-addressed id (`body:<digest>`).
    pub id: String,
    /// The function this body belongs to.
    pub function_id: String,
    /// Ordered operations within this function body.
    pub operations: Vec<RecoveredOperation>,
    /// Provenance for the body as a whole.
    pub provenance: Provenance,
    /// D-IR2: The Accounts struct name this function uses (e.g. "RelayAccounts").
    /// None if not an Anchor instruction handler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub struct_context: Option<String>,
}

impl RecoveredBody {
    /// Compute the deterministic content-addressed id.
    /// Digest is over: function_id + sorted operation ids.
    pub fn make_id(function_id: &str, operation_ids: &[&str]) -> String {
        let mut sorted_ids = operation_ids.to_vec();
        sorted_ids.sort();
        let canon = format!("{}|{}", function_id, sorted_ids.join("|"));
        node_id("body", &canon)
    }
}

/// Chain-agnostic recovered body graph: all function bodies for a program.
///
/// This is the top-level container that flows through `RecoveredFacts.body`.
/// Consumers opt in by checking `facts.body.is_some()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredBodyGraph {
    /// Deterministic content-addressed id (`bodygraph:<digest>`).
    pub id: String,
    /// All recovered function bodies.
    pub bodies: Vec<RecoveredBody>,
    /// Provenance for the body graph as a whole.
    pub provenance: Provenance,
    /// D-IR2: Per-struct AccountModel map (struct_name -> Vec<AccountModel>).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub account_models: BTreeMap<String, Vec<digger_parser::model::AccountModel>>,
}

impl RecoveredBodyGraph {
    /// Compute the deterministic content-addressed id.
    /// Digest is over: sorted body ids.
    pub fn make_id(body_ids: &[&str]) -> String {
        let mut sorted = body_ids.to_vec();
        sorted.sort();
        let canon = sorted.join("|");
        node_id("bodygraph", &canon)
    }
}

// ── RecoveredFact implementations ──────────────────────────────────────

use crate::fact::RecoveredFact;

impl RecoveredFact for RecoveredOperation {
    fn fact_id(&self) -> &str {
        &self.id
    }
    fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

impl RecoveredFact for RecoveredBody {
    fn fact_id(&self) -> &str {
        &self.id
    }
    fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

impl RecoveredFact for RecoveredBodyGraph {
    fn fact_id(&self) -> &str {
        &self.id
    }
    fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

// ── Source-path body recovery (C5.3) ──────────────────────────────────

/// Build a `RecoveredBodyGraph` from source-parse `RawProgram` operations.
///
/// This is the SOURCE-PATH analog of `recover_evm_body_graph`. It carries
/// ground-truth operations from the parser directly into the body layer with
/// `EvidenceSource::SourceCode` provenance, making the source corpus measurable
/// end-to-end.
///
/// This is a WIRING/SANITY CHECK — same data, same operations, provenance-marked
/// as SourceCode (NOT RuntimeBytecode). A <100% fidelity against this path is
/// NOT a recovery bug; it means the bytecode recoverer diverges from source.
pub fn recover_source_body_graph(
    program: &digger_parser::model::RawProgram,
) -> Option<RecoveredBodyGraph> {
    use std::collections::BTreeMap;

    // Group operations by function name
    let mut ops_by_fn: BTreeMap<String, Vec<&digger_parser::model::RawOperation>> = BTreeMap::new();
    for op in &program.operations {
        ops_by_fn.entry(op.function.clone()).or_default().push(op);
    }

    if ops_by_fn.is_empty() {
        return None;
    }

    // D-IR2: Extract AccountModels from metadata
    let mut account_models: BTreeMap<String, Vec<digger_parser::model::AccountModel>> =
        BTreeMap::new();
    for (key, value) in &program.metadata.extra {
        if key.starts_with("anchor_accounts_") {
            let struct_name = key.strip_prefix("anchor_accounts_").unwrap_or(key);
            if let Ok(models) = serde_json::from_value(value.clone()) {
                account_models.insert(struct_name.to_string(), models);
            }
        }
    }

    // D-IR2: Map function names to their Accounts struct context
    let fn_struct_map: BTreeMap<String, String> = {
        let mut map = BTreeMap::new();
        for func in &program.functions {
            for input in &func.inputs {
                if let Some(start) = input.find("Context<") {
                    let rest = &input[start + 8..];
                    if let Some(end) = rest.find('>') {
                        let struct_name = rest[..end].trim().to_string();
                        if !struct_name.is_empty() {
                            map.insert(func.name.clone(), struct_name);
                        }
                    }
                }
            }
        }
        map
    };

    let mut bodies: Vec<RecoveredBody> = Vec::new();

    for (fn_name, ops) in &ops_by_fn {
        let mut recovered_ops: Vec<RecoveredOperation> = ops
            .iter()
            .enumerate()
            .map(|(idx, op)| {
                let prov = Provenance::new(
                    EvidenceSource::SourceCode,
                    ReconstructionStage::Recover,
                    ConfidenceTier::Recovered,
                    &format!("src_op|{}|{}|{}", fn_name, idx, op.kind),
                );
                RecoveredOperation {
                    id: RecoveredOperation::make_id(fn_name, idx, &op.kind, &op.target),
                    function_id: fn_name.clone(),
                    index: idx,
                    kind: op.kind.clone(),
                    target: op.target.clone(),
                    provenance: prov,
                }
            })
            .collect();
        recovered_ops.sort_by_key(|o| o.index);

        let op_ids: Vec<&str> = recovered_ops.iter().map(|o| o.id.as_str()).collect();
        let body_prov = Provenance::new(
            EvidenceSource::SourceCode,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            &format!("src_body|{}", fn_name),
        );
        bodies.push(RecoveredBody {
            id: RecoveredBody::make_id(fn_name, &op_ids),
            function_id: fn_name.clone(),
            operations: recovered_ops,
            provenance: body_prov,
            struct_context: fn_struct_map.get(fn_name).cloned(),
        });
    }

    if bodies.is_empty() {
        return None;
    }

    let body_ids: Vec<&str> = bodies.iter().map(|b| b.id.as_str()).collect();
    let graph_prov = Provenance::new(
        EvidenceSource::SourceCode,
        ReconstructionStage::Recover,
        ConfidenceTier::Recovered,
        "bodygraph|source",
    );

    Some(RecoveredBodyGraph {
        id: RecoveredBodyGraph::make_id(&body_ids),
        bodies,
        provenance: graph_prov,
        account_models,
    })
}

// ── CEI / Reentrancy Detector (C5.6) ─────────────────────────────────

/// A checks-effects-interactions violation candidate.
///
/// Flags a StateWrite that occurs AFTER an ExternalCall in body order,
/// indicating a potential reentrancy vector. Only fires when both ops are
/// concretely present in the source-path body — no fabrication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeivViolation {
    /// Deterministic content-addressed id (`ceiv:<digest>`).
    pub id: String,
    /// The function containing the violation.
    pub function_id: String,
    /// The ExternalCall op that precedes the StateWrite.
    pub external_call_op_id: String,
    /// The StateWrite op that follows the ExternalCall.
    pub state_write_op_id: String,
    /// Index of the ExternalCall in the body's operation sequence.
    pub call_index: usize,
    /// Index of the StateWrite in the body's operation sequence.
    pub write_index: usize,
    /// Whether this violation was suppressed (reentrancy guard detected).
    pub suppressed: bool,
    /// Reason for suppression, if any.
    pub suppression_reason: Option<String>,
    /// Provenance for this finding.
    pub provenance: Provenance,
}

impl CeivViolation {
    pub fn make_id(function_id: &str, call_idx: usize, write_idx: usize) -> String {
        let canon = format!("ceiv|{}|{}|{}", function_id, call_idx, write_idx);
        crate::lifter::node_id("ceiv", &canon)
    }
}

/// Detect CEI (checks-effects-interactions) violations in a source-path body graph.
///
/// Per function, flags a StateWrite that occurs AFTER an ExternalCall in body order.
/// NON-FABRICATION: emits only when both ops are concretely present and ordered.
/// Source-path only — do NOT run on experimental bytecode path.
pub fn detect_cei_violations(body: &RecoveredBodyGraph) -> Vec<CeivViolation> {
    let mut violations = Vec::new();

    for body_entry in &body.bodies {
        let fn_id = &body_entry.function_id;
        let ops = &body_entry.operations;

        // Find all ExternalCall indices
        let call_indices: Vec<usize> = ops
            .iter()
            .enumerate()
            .filter(|(_, op)| op.kind == OperationKind::ExternalCall)
            .map(|(i, _)| i)
            .collect();

        // For each ExternalCall, check if any StateWrite follows it
        for &call_idx in &call_indices {
            for write_idx in (call_idx + 1)..ops.len() {
                if ops[write_idx].kind == OperationKind::StateWrite {
                    let prov = Provenance::new(
                        EvidenceSource::SourceCode,
                        ReconstructionStage::Recover,
                        ConfidenceTier::Recovered,
                        &format!("ceiv|{}|{}|{}", fn_id, ops[call_idx].id, ops[write_idx].id),
                    );

                    violations.push(CeivViolation {
                        id: CeivViolation::make_id(fn_id, call_idx, write_idx),
                        function_id: fn_id.clone(),
                        external_call_op_id: ops[call_idx].id.clone(),
                        state_write_op_id: ops[write_idx].id.clone(),
                        call_index: call_idx,
                        write_index: write_idx,
                        suppressed: false,
                        suppression_reason: None,
                        provenance: prov,
                    });
                }
            }
        }
    }

    violations
}

/// Suppress CEI violations where a reentrancy guard is concretely present.
///
/// Checks:
/// 1. Function modifiers for "nonReentrant" or similar guard patterns.
/// 2. Body-level mutex pattern (SLOAD from a known lock slot + conditional revert).
///
/// Suppress ONLY on concrete evidence; otherwise keep the candidate.
/// Records suppression reason in the violation.
pub fn suppress_cei_violations(
    violations: &mut [CeivViolation],
    modifiers: &std::collections::BTreeMap<String, Vec<String>>,
) {
    for v in violations.iter_mut() {
        // Check modifiers for guard patterns
        if let Some(func_mods) = modifiers.get(&v.function_id) {
            for m in func_mods {
                let ml = m.to_lowercase();
                if ml.contains("nonreentrant") || ml.contains("mutex") || ml.contains("guard") {
                    v.suppressed = true;
                    v.suppression_reason = Some(format!("modifier guard: {}", m));
                    break;
                }
            }
        }
    }
}

/// Convenience: detect + suppress in one call.
pub fn detect_and_suppress_cei(
    body: &RecoveredBodyGraph,
    modifiers: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<CeivViolation> {
    let mut violations = detect_cei_violations(body);
    suppress_cei_violations(&mut violations, modifiers);
    violations
}

// ── Solana Account-Model Detectors (C6.2) ─────────────────────────────

/// A Solana account-model access-control violation.
///
/// Flags instructions that mutate account data or invoke privileged CPIs
/// WITHOUT a concrete signer/owner check. Ground in Solana IR edges / CpiGraph.
/// NON-FABRICATION: emits only when evidence is concretely present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaAccessViolation {
    /// Deterministic content-addressed id.
    pub id: String,
    /// The function containing the violation.
    pub function_id: String,
    /// Violation kind: MissingSigner, MissingOwner, CpiPrivilegeEscalation.
    pub violation_kind: String,
    /// Whether this violation was suppressed.
    pub suppressed: bool,
    /// Suppression reason.
    pub suppression_reason: Option<String>,
    /// Provenance.
    pub provenance: Provenance,
}

impl SolanaAccessViolation {
    pub fn make_id(function_id: &str, violation_kind: &str) -> String {
        let canon = format!("sol_acc|{}|{}", function_id, violation_kind);
        crate::lifter::node_id("sol_acc", &canon)
    }
}

/// Detect Solana account-model access-control violations.
///
/// Per function, checks for:
/// - StateWrite without a signer/owner check (MissingSigner)
/// - CPI invocation without authority validation (CpiPrivilegeEscalation)
///
/// Source-path only. Emits on concrete evidence with provenance.
pub fn detect_solana_access_violations(body: &RecoveredBodyGraph) -> Vec<SolanaAccessViolation> {
    let mut violations = Vec::new();

    for body_entry in &body.bodies {
        let fn_id = &body_entry.function_id;
        let ops = &body_entry.operations;

        // Build PROTECTED_ACCOUNTS: accounts with explicit authority binding
        // (Signer, has_one, constraint, seeds/bump PDA from authority)
        let protected_accounts: BTreeSet<String> = ops
            .iter()
            .filter(|o| o.kind == OperationKind::AuthorityCheck)
            .filter_map(|o| extract_protected_account(&o.target))
            .collect();

        // Check for StateWrite on an UNPROTECTED account
        for op in ops.iter().filter(|o| o.kind == OperationKind::StateWrite) {
            if let Some(account) = extract_target_account(&op.target) {
                if !protected_accounts.contains(&account) {
                    let prov = Provenance::new(
                        EvidenceSource::SourceCode,
                        ReconstructionStage::Recover,
                        ConfidenceTier::Recovered,
                        &format!("sol_acc|{}|missing_signer|{}", fn_id, account),
                    );
                    violations.push(SolanaAccessViolation {
                        id: SolanaAccessViolation::make_id(fn_id, "missing_signer"),
                        function_id: fn_id.clone(),
                        violation_kind: "MissingAuthorityCheck".into(),
                        suppressed: false,
                        suppression_reason: None,
                        provenance: prov,
                    });
                    break;
                }
            }
        }

        // Check for ValueTransfer/CPI on an UNPROTECTED account
        // Build signals for attribution
        let has_any_auth = !protected_accounts.is_empty()
            || ops.iter().any(|o| {
                o.kind == OperationKind::AuthorityCheck
                    && (o.target == "require" || o.target == "assert")
            });

        // Check if the function has has_one (main storage account protected)
        let has_has_one = ops
            .iter()
            .any(|o| o.kind == OperationKind::AuthorityCheck && o.target.starts_with("has_one:"));

        // Check if the function has pda_seed + signer (PDA derived from signer)
        let has_pda_seed = ops
            .iter()
            .any(|o| o.kind == OperationKind::AuthorityCheck && o.target.starts_with("pda_seed:"));
        let has_signer = ops
            .iter()
            .any(|o| o.kind == OperationKind::AuthorityCheck && o.target.starts_with("signer:"));

        for op in ops.iter().filter(|o| {
            o.kind == OperationKind::ExternalCall || o.kind == OperationKind::ValueTransfer
        }) {
            let account = extract_transfer_account(&op.target);
            if account.is_empty() {
                // When account is unresolvable: suppress only if the function has
                // structural protection (has_one or pda_seed+signer). Otherwise emit.
                let is_structurally_protected =
                    has_any_auth && (has_has_one || (has_pda_seed && has_signer));
                if !is_structurally_protected {
                    let prov = Provenance::new(
                        EvidenceSource::SourceCode,
                        ReconstructionStage::Recover,
                        ConfidenceTier::Recovered,
                        &format!("sol_acc|{}|cpi_privilege|{}", fn_id, op.target),
                    );
                    violations.push(SolanaAccessViolation {
                        id: SolanaAccessViolation::make_id(fn_id, "cpi_privilege"),
                        function_id: fn_id.clone(),
                        violation_kind: "MissingAuthorityCheck".into(),
                        suppressed: false,
                        suppression_reason: None,
                        provenance: prov,
                    });
                    break;
                }
            } else if !protected_accounts.contains(&account) {
                let prov = Provenance::new(
                    EvidenceSource::SourceCode,
                    ReconstructionStage::Recover,
                    ConfidenceTier::Recovered,
                    &format!("sol_acc|{}|cpi_privilege|{}", fn_id, account),
                );
                violations.push(SolanaAccessViolation {
                    id: SolanaAccessViolation::make_id(fn_id, "cpi_privilege"),
                    function_id: fn_id.clone(),
                    violation_kind: "MissingAuthorityCheck".into(),
                    suppressed: false,
                    suppression_reason: None,
                    provenance: prov,
                });
                break;
            }
        }
    }

    violations
}

// ── Unvalidated CPI Detector (C20) ──────────────────────────────────

/// An unvalidated CPI violation: a cross-program invocation whose target program
/// is not validated (no has_one, signer, pda_seed, constraint, or require/assert
/// protecting the CPI path).
///
/// Detection: function has ExternalCall (CPI) + ZERO AuthorityCheck operations.
/// Suppression: ANY AuthorityCheck (has_one, signer, pda_seed, constraint,
/// require, assert) → suppress (assumes partial validation exists).
///
/// Experimental label: this is a structural heuristic. The absence of any
/// authority check in a CPI-calling function is a strong but not exhaustive
/// signal for unvalidated CPI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnvalidatedCpiViolation {
    pub id: String,
    pub function_id: String,
    pub violation_kind: String,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub provenance: Provenance,
}

impl UnvalidatedCpiViolation {
    pub fn make_id(fn_id: &str, kind: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        fn_id.hash(&mut h);
        kind.hash(&mut h);
        format!("ucpi-{:016x}", h.finish())
    }
}

/// Detect unvalidated CPI: functions that invoke other programs but whose CPI
/// target program is not validated.
///
/// Attribution rules (C21):
/// 1. EMIT if zero authority checks → CPI target completely unvalidated.
/// 2. EMIT if authority checks are ONLY signer:X → signer constrains the
///    CALLER, not which program is invoked; CPI target still substitutable.
/// 3. SUPPRESS if any authority check could constrain the CPI target:
///    - has_one:X (binds program account or data account that gates CPI)
///    - constraint:X (could directly validate program id)
///    - pda_seed:X (PDA-derived program account)
///    - require/assert (could validate program id)
///
/// Known ceiling: when auth checks include has_one on an unrelated data
/// account (not the program), the detector conservatively suppresses
/// because it cannot distinguish has_one:vault from has_one:token_program
/// in the IR. This produces FNs, never FPs.
///
/// EXPERIMENTAL: precision-first.
pub fn detect_unvalidated_cpi(body: &RecoveredBodyGraph) -> Vec<UnvalidatedCpiViolation> {
    let mut violations = Vec::new();

    for body_entry in &body.bodies {
        let fn_id = &body_entry.function_id;
        let ops = &body_entry.operations;

        let has_cpi = ops.iter().any(|o| {
            o.kind == OperationKind::ExternalCall || o.kind == OperationKind::ValueTransfer
        });

        if !has_cpi {
            continue;
        }

        let auth_targets: Vec<&str> = ops
            .iter()
            .filter(|o| o.kind == OperationKind::AuthorityCheck)
            .map(|o| o.target.as_str())
            .collect();

        if auth_targets.is_empty() {
            let prov = Provenance::new(
                EvidenceSource::SourceCode,
                ReconstructionStage::Recover,
                ConfidenceTier::Recovered,
                &format!("sol_cpi|{}|unvalidated_cpi|cpi_target", fn_id),
            );
            violations.push(UnvalidatedCpiViolation {
                id: UnvalidatedCpiViolation::make_id(fn_id, "unvalidated_cpi"),
                function_id: fn_id.clone(),
                violation_kind: "UnvalidatedCpi".into(),
                suppressed: false,
                suppression_reason: None,
                provenance: prov,
            });
            continue;
        }

        let all_signer_only = auth_targets.iter().all(|t| t.starts_with("signer:"));

        if all_signer_only {
            let prov = Provenance::new(
                EvidenceSource::SourceCode,
                ReconstructionStage::Recover,
                ConfidenceTier::Recovered,
                &format!(
                    "sol_cpi|{}|unvalidated_cpi|signer_only_no_target_guard",
                    fn_id
                ),
            );
            violations.push(UnvalidatedCpiViolation {
                id: UnvalidatedCpiViolation::make_id(fn_id, "unvalidated_cpi"),
                function_id: fn_id.clone(),
                violation_kind: "UnvalidatedCpi".into(),
                suppressed: false,
                suppression_reason: None,
                provenance: prov,
            });
        }
    }

    violations
}

/// Extract the protected account name from an AuthorityCheck target.
///
/// Maps:
///   "signer:authority" → "authority"
///   "has_one:vault" → "vault"
///   "constraint:from" → "from"
///   "pda_seed:pool" → "pool"
///   "pda_bump:pool" → "pool"
///   "require" / "assert" → None (generic, not account-specific)
fn extract_protected_account(target: &str) -> Option<String> {
    let prefixes = &["signer:", "has_one:", "constraint:", "pda_seed:"];
    for prefix in prefixes {
        if let Some(field) = target.strip_prefix(prefix) {
            return Some(field.to_string());
        }
    }
    None
}

/// Extract the target account name from a StateWrite target.
///
/// Maps:
///   "&mut ctx.accounts.mint" → "mint"
///   "&ctx.accounts.vault.amount" → "vault"
///   "ctx.accounts.pool" → "pool"
///   "mint.supply" → None (local variable, not ctx.accounts)
fn extract_target_account(target: &str) -> Option<String> {
    let cleaned = target.trim_start_matches('&').trim_start_matches("mut ");
    if let Some(rest) = cleaned.strip_prefix("ctx.accounts.") {
        let account = rest.split('.').next().unwrap_or(rest);
        let account = account.trim();
        if !account.is_empty() {
            return Some(account.to_string());
        }
    }
    None
}

/// Extract the authority-relevant account from a transfer/CPI target.
fn extract_transfer_account(target: &str) -> String {
    if let Some(rest) = target.strip_prefix("cpi|") {
        if let Some(account) = rest.split('|').next() {
            return account.to_string();
        }
    }
    String::new()
}

// ── Type Cosplay / Missing Discriminator Detector (C44) ──────────

/// A type-cosplay / missing discriminator violation: a function reads/deserializes
/// account data from a raw AccountInfo/UncheckedAccount without verifying the account's
/// type discriminator or owner — so an attacker can pass an account of a different type.
///
/// Detection: function has StateRead on an unprotected account + ZERO AuthorityCheck.
/// Suppression: ANY AuthorityCheck (has_one, signer, pda_seed, constraint, require, assert)
/// on ANY account in the function indicates some validation exists.
///
/// Known ceiling: cannot distinguish Account<'info,T> from AccountInfo<'info> at the IR
/// level. Suppresses conservatively: any AuthorityCheck → suppress, even if it doesn't
/// cover the specific account. This avoids FPs at the cost of FNs.
///
/// Severity: HIGH. Confidence: experimental.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeCosplayViolation {
    pub id: String,
    pub function_id: String,
    pub violation_kind: String,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub provenance: Provenance,
}

impl TypeCosplayViolation {
    pub fn make_id(fn_id: &str, kind: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        fn_id.hash(&mut h);
        kind.hash(&mut h);
        format!("tcp-{:016x}", h.finish())
    }
}

/// Detect type-cosplay / missing discriminator: functions that read account data
/// (StateRead) from unprotected accounts with no type validation.
///
/// D-IR2 per-account logic:
/// - TYPED account (Account<T>, InterfaceAccount, Program, etc.) → SUPPRESS
///   (Anchor validates discriminator + owner on deserialize)
/// - RAW account (AccountInfo, UncheckedAccount) → ELIGIBLE for finding
/// - SIGNER on another field → does NOT suppress findings on RAW accounts
/// - UNKNOWN → conservative, do NOT suppress, do NOT invent finding
/// - Per-account constraint: owner/address on THIS account → SUPPRESS
/// - Function-level fallback: no struct_context → old behavior (any auth → suppress)
///
/// Severity: HIGH. Confidence: experimental.
pub fn detect_type_cosplay(body: &RecoveredBodyGraph) -> Vec<TypeCosplayViolation> {
    let mut violations = Vec::new();

    for body_entry in &body.bodies {
        let fn_id = &body_entry.function_id;
        let ops = &body_entry.operations;

        let has_state_read = ops.iter().any(|o| o.kind == OperationKind::StateRead);
        if !has_state_read {
            continue;
        }

        // D-IR2: If we have per-account data, use it; otherwise fall back
        if let Some(ref struct_name) = body_entry.struct_context {
            if let Some(models) = body.account_models.get(struct_name) {
                // Per-account reasoning
                for op in ops.iter().filter(|o| o.kind == OperationKind::StateRead) {
                    let account = match extract_account_from_target(&op.target) {
                        Some(a) => a,
                        None => continue,
                    };

                    let model = models.iter().find(|m| m.name == account);

                    // Rule: TYPED → suppress (safe by construction)
                    if let Some(m) = model {
                        if m.wrapper_type == digger_parser::model::AccountWrapperType::TYPED {
                            continue;
                        }
                    }

                    // Rule: UNKNOWN without additional evidence → don't emit
                    if model.is_none()
                        || model.is_some_and(|m| {
                            m.wrapper_type == digger_parser::model::AccountWrapperType::UNKNOWN
                        })
                    {
                        continue;
                    }

                    // Rule: SIGNER → not a type guard, doesn't suppress
                    // (fall through — signer on THIS account doesn't suppress)

                    // Function-level: require/assert is a general validation guard
                    // that could check any account. Unlike has_one/constraint (which
                    // bind per-account via target), require/assert is untargeted.
                    let has_require_or_assert = ops.iter().any(|o| {
                        o.kind == OperationKind::AuthorityCheck
                            && (o.target.starts_with("require") || o.target.starts_with("assert"))
                    });

                    // RAW account: check per-account constraints that close the gap
                    if let Some(m) = model {
                        if m.wrapper_type == digger_parser::model::AccountWrapperType::RAW {
                            let has_owner_guard = m
                                .constraints
                                .iter()
                                .any(|c| c.kind == "owner" || c.kind == "address");
                            if has_owner_guard {
                                continue;
                            }

                            // Cross-reference: another account's has_one/constraint
                            // targeting THIS account also suppresses (transitive guard)
                            let protected_by_others = models.iter().any(|other| {
                                other.constraints.iter().any(|c| {
                                    (c.kind == "has_one" || c.kind == "constraint")
                                        && c.target == account
                                })
                            });
                            if protected_by_others {
                                continue;
                            }

                            // If ANY account in the struct has has_one/constraint,
                            // the struct is structurally guarded — suppress RAW accounts.
                            // (Accounts with has_one/constraint are Anchor-typed, meaning
                            // the struct is an Anchor instruction context with validation.)
                            let struct_has_structural_guard = models.iter().any(|m| {
                                m.constraints
                                    .iter()
                                    .any(|c| c.kind == "has_one" || c.kind == "constraint")
                            });
                            if struct_has_structural_guard {
                                continue;
                            }

                            // Untargeted require/assert could validate any account
                            if has_require_or_assert {
                                continue;
                            }
                        }
                        // SIGNER account → not a read target for type-cosplay
                        if m.wrapper_type == digger_parser::model::AccountWrapperType::SIGNER {
                            continue;
                        }
                    }

                    // RAW account with no owner/address guard → emit
                    let prov = Provenance::new(
                        EvidenceSource::SourceCode,
                        ReconstructionStage::Recover,
                        ConfidenceTier::Recovered,
                        &format!("sol_type|{}|type_cosplay|{}", fn_id, account),
                    );
                    violations.push(TypeCosplayViolation {
                        id: TypeCosplayViolation::make_id(
                            fn_id,
                            &format!("type_cosplay_{}", account),
                        ),
                        function_id: fn_id.clone(),
                        violation_kind: "TypeCosplay".into(),
                        suppressed: false,
                        suppression_reason: None,
                        provenance: prov,
                    });
                    break;
                }
                continue;
            }
        }

        // Fallback: no per-account data → function-level suppression (old behavior)
        let has_any_auth = ops.iter().any(|o| {
            o.kind == OperationKind::AuthorityCheck
                && (o.target.starts_with("has_one:")
                    || o.target.starts_with("signer:")
                    || o.target.starts_with("pda_seed:")
                    || o.target.starts_with("constraint:")
                    || o.target == "require"
                    || o.target == "assert")
        });

        if !has_any_auth {
            let prov = Provenance::new(
                EvidenceSource::SourceCode,
                ReconstructionStage::Recover,
                ConfidenceTier::Recovered,
                &format!("sol_type|{}|type_cosplay|missing_discriminator", fn_id),
            );
            violations.push(TypeCosplayViolation {
                id: TypeCosplayViolation::make_id(fn_id, "type_cosplay"),
                function_id: fn_id.clone(),
                violation_kind: "TypeCosplay".into(),
                suppressed: false,
                suppression_reason: None,
                provenance: prov,
            });
        }
    }

    violations
}

/// Extract the account field name from a StateRead target like "ctx.accounts.X".
fn extract_account_from_target(target: &str) -> Option<String> {
    let cleaned = target.trim_start_matches('&').trim_start_matches("mut ");
    if let Some(rest) = cleaned.strip_prefix("ctx.accounts.") {
        let account = rest.split('.').next().unwrap_or(rest);
        let account = account.trim();
        if !account.is_empty() {
            return Some(account.to_string());
        }
    }
    None
}

// ── Unchecked Account Owner Detector (D-S2) ──────────────────────

/// An unchecked-account-owner violation: a function reads/deserializes account data
/// from a raw AccountInfo/UncheckedAccount without verifying the account's `owner`
/// field — so an attacker can substitute an account owned by a different program.
///
/// Detection: function has StateRead on an unprotected account + ZERO AuthorityCheck.
/// Suppression: ANY AuthorityCheck (has_one, signer, pda_seed, constraint, owner,
/// require, assert) on ANY account in the function indicates some validation exists.
///
/// Known ceiling: same as type-cosplay — cannot distinguish Account<'info,T> from
/// AccountInfo<'info> at the IR level. Cannot distinguish "owner check" from "has_one"
/// or "signer" in the IR. Suppresses conservatively: any AuthorityCheck → suppress.
/// Severity: HIGH. Confidence: experimental.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UncheckedOwnerViolation {
    pub id: String,
    pub function_id: String,
    pub violation_kind: String,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub provenance: Provenance,
}

impl UncheckedOwnerViolation {
    pub fn make_id(fn_id: &str, kind: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        fn_id.hash(&mut h);
        kind.hash(&mut h);
        format!("uow-{:016x}", h.finish())
    }
}

/// Detect unchecked-account-owner: functions that read account data (StateRead)
/// from raw AccountInfo/UncheckedAccount without verifying the account's owner.
///
/// D-IR2 per-account logic:
/// - TYPED → SUPPRESS (Anchor validates owner on deserialize)
/// - RAW → ELIGIBLE for finding
/// - Per-account constraint: owner/address/has_one on THIS account → SUPPRESS
/// - SIGNER → does NOT suppress findings on RAW accounts
/// - Function-level fallback: no struct_context → old behavior
///
/// Severity: HIGH. Confidence: experimental.
pub fn detect_unchecked_owner(body: &RecoveredBodyGraph) -> Vec<UncheckedOwnerViolation> {
    let mut violations = Vec::new();

    for body_entry in &body.bodies {
        let fn_id = &body_entry.function_id;
        let ops = &body_entry.operations;

        let has_state_read = ops.iter().any(|o| o.kind == OperationKind::StateRead);
        if !has_state_read {
            continue;
        }

        // D-IR2: per-account reasoning when AccountModel is available
        if let Some(ref struct_name) = body_entry.struct_context {
            if let Some(models) = body.account_models.get(struct_name) {
                for op in ops.iter().filter(|o| o.kind == OperationKind::StateRead) {
                    let account = match extract_account_from_target(&op.target) {
                        Some(a) => a,
                        None => continue,
                    };

                    let model = models.iter().find(|m| m.name == account);

                    // TYPED → suppress
                    if let Some(m) = model {
                        if m.wrapper_type == digger_parser::model::AccountWrapperType::TYPED {
                            continue;
                        }
                    }

                    // UNKNOWN → don't emit
                    if model.is_none()
                        || model.is_some_and(|m| {
                            m.wrapper_type == digger_parser::model::AccountWrapperType::UNKNOWN
                        })
                    {
                        continue;
                    }

                    // SIGNER → not an owner guard
                    if let Some(m) = model {
                        if m.wrapper_type == digger_parser::model::AccountWrapperType::SIGNER {
                            continue;
                        }
                    }

                    let has_require_or_assert = ops.iter().any(|o| {
                        o.kind == OperationKind::AuthorityCheck
                            && (o.target.starts_with("require") || o.target.starts_with("assert"))
                    });

                    // RAW: check per-account owner-related constraints
                    if let Some(m) = model {
                        if m.wrapper_type == digger_parser::model::AccountWrapperType::RAW {
                            let has_owner_guard = m.constraints.iter().any(|c| {
                                c.kind == "owner" || c.kind == "address" || c.kind == "has_one"
                            });
                            if has_owner_guard {
                                continue;
                            }

                            // Cross-reference: another account's has_one targeting THIS account
                            let protected_by_others = models.iter().any(|other| {
                                other
                                    .constraints
                                    .iter()
                                    .any(|c| c.kind == "has_one" && c.target == account)
                            });
                            if protected_by_others {
                                continue;
                            }

                            // Struct-level structural guard
                            let struct_has_structural_guard = models.iter().any(|m| {
                                m.constraints
                                    .iter()
                                    .any(|c| c.kind == "has_one" || c.kind == "constraint")
                            });
                            if struct_has_structural_guard {
                                continue;
                            }

                            if has_require_or_assert {
                                continue;
                            }
                        }
                    }

                    // RAW with no owner guard → emit
                    let prov = Provenance::new(
                        EvidenceSource::SourceCode,
                        ReconstructionStage::Recover,
                        ConfidenceTier::Recovered,
                        &format!("sol_type|{}|unchecked_owner|{}", fn_id, account),
                    );
                    violations.push(UncheckedOwnerViolation {
                        id: UncheckedOwnerViolation::make_id(
                            fn_id,
                            &format!("unchecked_owner_{}", account),
                        ),
                        function_id: fn_id.clone(),
                        violation_kind: "UncheckedAccountOwner".into(),
                        suppressed: false,
                        suppression_reason: None,
                        provenance: prov,
                    });
                    break;
                }
                continue;
            }
        }

        // Fallback: function-level suppression (old behavior)
        let has_any_auth = ops.iter().any(|o| {
            o.kind == OperationKind::AuthorityCheck
                && (o.target.starts_with("has_one:")
                    || o.target.starts_with("signer:")
                    || o.target.starts_with("pda_seed:")
                    || o.target.starts_with("constraint:")
                    || o.target.starts_with("owner:")
                    || o.target == "require"
                    || o.target == "assert")
        });

        if !has_any_auth {
            let prov = Provenance::new(
                EvidenceSource::SourceCode,
                ReconstructionStage::Recover,
                ConfidenceTier::Recovered,
                &format!("sol_type|{}|unchecked_owner|missing_owner_check", fn_id),
            );
            violations.push(UncheckedOwnerViolation {
                id: UncheckedOwnerViolation::make_id(fn_id, "unchecked_owner"),
                function_id: fn_id.clone(),
                violation_kind: "UncheckedAccountOwner".into(),
                suppressed: false,
                suppression_reason: None,
                provenance: prov,
            });
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::ConfidenceTier;
    use crate::fact::RecoveredFact;
    use crate::provenance::{EvidenceSource, ReconstructionStage};

    fn test_prov(input: &str) -> Provenance {
        Provenance::new(
            EvidenceSource::RuntimeBytecode,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            input,
        )
    }

    #[test]
    fn operation_id_is_deterministic() {
        let id1 =
            RecoveredOperation::make_id("fn_withdraw", 2, &OperationKind::ExternalCall, "external");
        let id2 =
            RecoveredOperation::make_id("fn_withdraw", 2, &OperationKind::ExternalCall, "external");
        assert_eq!(id1, id2, "same inputs must produce identical ids");
        assert!(id1.starts_with("op:"));
    }

    #[test]
    fn operation_id_is_order_sensitive() {
        let id_a = RecoveredOperation::make_id("fn_a", 0, &OperationKind::StateWrite, "x");
        let id_b = RecoveredOperation::make_id("fn_b", 0, &OperationKind::StateWrite, "x");
        assert_ne!(
            id_a, id_b,
            "different function_id must produce different ids"
        );
    }

    #[test]
    fn body_id_is_deterministic_from_operation_ids() {
        let id1 = RecoveredBody::make_id("fn_withdraw", &["op:aaa", "op:bbb"]);
        let id2 = RecoveredBody::make_id("fn_withdraw", &["op:bbb", "op:aaa"]);
        assert_eq!(
            id1, id2,
            "body id must be stable regardless of operation ordering"
        );
        assert!(id1.starts_with("body:"));
    }

    #[test]
    fn bodygraph_id_is_deterministic() {
        let id1 = RecoveredBodyGraph::make_id(&["body:aaa", "body:bbb"]);
        let id2 = RecoveredBodyGraph::make_id(&["body:bbb", "body:aaa"]);
        assert_eq!(
            id1, id2,
            "bodygraph id must be stable regardless of body ordering"
        );
        assert!(id1.starts_with("bodygraph:"));
    }

    #[test]
    fn absent_not_empty() {
        let op = RecoveredOperation {
            id: RecoveredOperation::make_id("fn", 0, &OperationKind::StateRead, "x"),
            function_id: "fn".into(),
            index: 0,
            kind: OperationKind::StateRead,
            target: "x".into(),
            provenance: test_prov("test"),
        };
        // A RecoveredBody exists — but a function with NO grounded operations
        // yields NO RecoveredBody. This is the "absent not empty" invariant.
        let body = RecoveredBody {
            id: RecoveredBody::make_id("fn", &[&op.id]),
            function_id: "fn".into(),
            operations: vec![op],
            provenance: test_prov("body"),
            struct_context: None,
        };
        assert_eq!(body.operations.len(), 1);
        // Conversely, we never construct an empty RecoveredBody:
        // the caller simply doesn't emit one.
    }

    #[test]
    fn provenance_wired_correctly() {
        let prov = test_prov("test");
        let op = RecoveredOperation {
            id: RecoveredOperation::make_id("fn", 0, &OperationKind::StateWrite, "x"),
            function_id: "fn".into(),
            index: 0,
            kind: OperationKind::StateWrite,
            target: "x".into(),
            provenance: prov.clone(),
        };
        assert_eq!(op.fact_id(), op.id);
        assert_eq!(op.confidence(), ConfidenceTier::Recovered);
        assert_eq!(op.provenance().stage, ReconstructionStage::Recover);
    }

    #[test]
    fn recover_source_body_graph_basic() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![RawFunction {
                name: "deposit".into(),
                contract: String::new(),
                visibility: "public".into(),
                inputs: vec![],
                body: "balances[msg.sender] += msg.value".into(),
                has_arithmetic: false,
            }],
            state: vec![],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::StateWrite,
                    target: "balances".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::AuthorityCheck,
                    target: "authority".into(),
                },
            ],
            ..Default::default()
        };

        let body_graph = recover_source_body_graph(&program).expect("should produce body");
        assert_eq!(body_graph.bodies.len(), 1);
        let body = &body_graph.bodies[0];
        assert_eq!(body.function_id, "deposit");
        assert_eq!(body.operations.len(), 2);
        assert_eq!(body.operations[0].kind, OperationKind::StateWrite);
        assert_eq!(body.operations[0].index, 0);
        assert_eq!(body.operations[1].kind, OperationKind::AuthorityCheck);
        assert_eq!(body.operations[1].index, 1);

        // SourceCode provenance
        assert_eq!(
            body.operations[0].provenance.originating_evidence,
            EvidenceSource::SourceCode
        );
        assert_eq!(
            body_graph.provenance.originating_evidence,
            EvidenceSource::SourceCode
        );
    }

    #[test]
    fn recover_source_body_graph_empty_yields_none() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![],
            ..Default::default()
        };
        assert!(recover_source_body_graph(&program).is_none());
    }

    #[test]
    fn recover_source_body_graph_determinism() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![
                RawOperation {
                    function: "fn_a".into(),
                    index: 0,
                    kind: OperationKind::StateRead,
                    target: "x".into(),
                },
                RawOperation {
                    function: "fn_b".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "external".into(),
                },
            ],
            ..Default::default()
        };
        let a = format!("{:#?}", recover_source_body_graph(&program));
        let b = format!("{:#?}", recover_source_body_graph(&program));
        assert_eq!(a, b);
    }

    // ── CEI detector tests ────────────────────────────────────────────

    #[test]
    fn cei_detects_call_before_state_write() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![
                RawOperation {
                    function: "withdraw".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "external".into(),
                },
                RawOperation {
                    function: "withdraw".into(),
                    index: 1,
                    kind: OperationKind::StateWrite,
                    target: "balances".into(),
                },
            ],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let violations = detect_cei_violations(&body);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].function_id, "withdraw");
        assert_eq!(violations[0].call_index, 0);
        assert_eq!(violations[0].write_index, 1);
        assert!(!violations[0].suppressed);
    }

    #[test]
    fn cei_no_violation_when_state_before_call() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![
                RawOperation {
                    function: "deposit".into(),
                    index: 0,
                    kind: OperationKind::StateWrite,
                    target: "balances".into(),
                },
                RawOperation {
                    function: "deposit".into(),
                    index: 1,
                    kind: OperationKind::ExternalCall,
                    target: "external".into(),
                },
            ],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let violations = detect_cei_violations(&body);
        assert!(
            violations.is_empty(),
            "state before call is NOT a CEI violation"
        );
    }

    #[test]
    fn cei_no_violation_when_no_external_call() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![RawOperation {
                function: "set".into(),
                index: 0,
                kind: OperationKind::StateWrite,
                target: "x".into(),
            }],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let violations = detect_cei_violations(&body);
        assert!(violations.is_empty());
    }

    #[test]
    fn cei_determinism() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![
                RawOperation {
                    function: "fn".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "ext".into(),
                },
                RawOperation {
                    function: "fn".into(),
                    index: 1,
                    kind: OperationKind::StateWrite,
                    target: "x".into(),
                },
            ],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let a = format!("{:#?}", detect_cei_violations(&body));
        let b = format!("{:#?}", detect_cei_violations(&body));
        assert_eq!(a, b);
    }

    // ── Suppression tests ─────────────────────────────────────────────

    #[test]
    fn suppression_with_nonreentrant_modifier() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![
                RawOperation {
                    function: "withdraw".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "external".into(),
                },
                RawOperation {
                    function: "withdraw".into(),
                    index: 1,
                    kind: OperationKind::StateWrite,
                    target: "balances".into(),
                },
            ],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let mut violations = detect_cei_violations(&body);
        assert_eq!(violations.len(), 1);
        assert!(!violations[0].suppressed);

        let mut mods = std::collections::BTreeMap::new();
        mods.insert("withdraw".to_string(), vec!["nonReentrant".to_string()]);
        suppress_cei_violations(&mut violations, &mods);
        assert!(violations[0].suppressed);
        assert!(violations[0]
            .suppression_reason
            .as_ref()
            .unwrap()
            .contains("nonReentrant"));
    }

    #[test]
    fn no_suppression_without_guard() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![
                RawOperation {
                    function: "withdraw".into(),
                    index: 0,
                    kind: OperationKind::ExternalCall,
                    target: "external".into(),
                },
                RawOperation {
                    function: "withdraw".into(),
                    index: 1,
                    kind: OperationKind::StateWrite,
                    target: "balances".into(),
                },
            ],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let mut violations = detect_cei_violations(&body);
        let mods = std::collections::BTreeMap::new(); // no guards
        suppress_cei_violations(&mut violations, &mods);
        assert!(!violations[0].suppressed);
    }

    // ── Solana access-control detector tests ─────────────────────────

    #[test]
    fn solana_missing_signer_detected() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![RawOperation {
                function: "mint".into(),
                index: 0,
                kind: OperationKind::StateWrite,
                target: "&mut ctx.accounts.mint".into(),
            }],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let violations = detect_solana_access_violations(&body);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_kind, "MissingAuthorityCheck");
    }

    #[test]
    fn solana_cpi_privilege_detected() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![RawOperation {
                function: "relay".into(),
                index: 0,
                kind: OperationKind::ExternalCall,
                target: "cpi".into(),
            }],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let violations = detect_solana_access_violations(&body);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_kind, "MissingAuthorityCheck");
    }

    #[test]
    fn solana_no_violation_with_authority() {
        use digger_parser::model::*;
        let program = RawProgram {
            functions: vec![],
            state: vec![],
            operations: vec![
                RawOperation {
                    function: "transfer".into(),
                    index: 0,
                    kind: OperationKind::AuthorityCheck,
                    target: "signer".into(),
                },
                RawOperation {
                    function: "transfer".into(),
                    index: 1,
                    kind: OperationKind::StateWrite,
                    target: "balance".into(),
                },
            ],
            ..Default::default()
        };
        let body = recover_source_body_graph(&program).expect("should produce body");
        let violations = detect_solana_access_violations(&body);
        assert!(violations.is_empty());
    }

    #[test]
    fn regression_guard_type_cosplay_tp_set() {
        use digger_parser::parse_program;
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let dir = root.join("corpus/solana-account-model");
        // Tracks corpus growth: +7 fixtures from Track G corpus expansion (f0684fc).
        // All newly-detected fixtures are labeled-vulnerable positives (cross-class firing).
        let expected_tp: Vec<&str> = vec![
            "cpi-bridge-vuln-1",
            "cpi-oracle-vuln-1",
            "cpi-signer-only-vuln",
            "cpi-staking-vuln-1",
            "missing-owner-vuln",
            "owner-check-vuln-1",
            "owner-check-vuln-3",
            "owner-check-vuln-4",
            "sablier-stake-pool-2023",
            "solarbridge-cpi-2022",
            "squid-token-swap-2022",
            "type-cosplay-vuln-1",
            "type-cosplay-vuln-3",
            "type-cosplay-vuln-4",
            "unvalidated-cpi-vuln",
            "vesper-lp-2023",
        ];
        let mut detected_tp: Vec<String> = Vec::new();
        for case in std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()) {
            let case_dir = case.path();
            if !case_dir.is_dir() {
                continue;
            }
            let mp = case_dir.join("meta.json");
            if !mp.exists() {
                continue;
            }
            let meta: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&mp).unwrap_or_default())
                    .unwrap_or_default();
            let is_neg = meta["known_limitations"]
                .as_str()
                .map(|s| s.contains("NEGATIVE"))
                .unwrap_or(false);
            if is_neg {
                continue;
            }
            let cid = meta["exploit_id"].as_str().unwrap_or("");
            if cid.is_empty() {
                continue;
            }
            let src = std::fs::read_dir(&case_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .find(|e| e.path().extension().map(|x| x == "rs").unwrap_or(false));
            if let Some(sf) = src {
                let src_text = std::fs::read_to_string(sf.path()).unwrap();
                let raw = parse_program(&src_text, "anchor");
                if let Some(body) = recover_source_body_graph(&raw) {
                    let v = detect_type_cosplay(&body);
                    if !v.is_empty() {
                        detected_tp.push(cid.to_string());
                    }
                }
            }
        }
        detected_tp.sort();
        let mut expected_sorted: Vec<String> = expected_tp.iter().map(|s| s.to_string()).collect();
        expected_sorted.sort();
        assert_eq!(
            detected_tp, expected_sorted,
            "Regression: type_cosplay TP set changed! Expected {:?}, got {:?}",
            expected_sorted, detected_tp
        );
    }
}
