//! Function mapping — maps Gen 5 capabilities to SystemIR Functions.
//!
//! B3 scope: synthesizes one `Function` per resolved `Capability`.
//!
//! # D1 Contract (Safety-Critical)
//!
//! - `name`: `"__gen5::<kind>"` — reserved collision-proof label.
//! - `effects`: truthful booleans per CapabilityKind → Effects table.
//! - `modifiers`: ALWAYS EMPTY for synthetic functions. Guard presence lives
//!   ONLY in `effects.authority_required`.
//! - `visibility`: `Public` — all capabilities are externally invokable.
//! - `inputs`/`outputs`: empty (no signature recovered).
//!
//! # Guard Predicate (authority_required) — SAFETY-CRITICAL
//!
//! `authority_required = true` ONLY when there is AFFIRMATIVE recovered evidence
//! of a controlling authority: a `Permission` with `holder.is_some()`.
//!
/// `derive_permissions` emits a Permission for EVERY privileged capability
/// unconditionally — Permission existence records the ACTION, not the
/// AUTHORITY. `Permission.holder.is_some()` is the only per-capability
/// authority evidence. For Upgrade, holder is set when an UpgradeAuthority
/// actor was recovered. For Mint/Burn/Pause/Treasury/Governance, holder is
/// hardcoded None (no authority recovered) → authority_required = false.
///
/// This surfaces missing access control as risk, not suppresses it.
use digger_ir::{Effects, Function, Visibility};
use digger_protocol_model::capability_graph::{Capability, CapabilityKind};
use digger_protocol_model::permissions::Permission;

/// Mapping table: CapabilityKind → base Effects booleans.
///
/// `authority_required` is NOT set here — it is driven by the guard predicate.
fn effects_for_kind(kind: CapabilityKind) -> Effects {
    match kind {
        CapabilityKind::Upgrade => Effects {
            state_mutation: true,
            external_call: false,
            authority_required: false, // set by guard predicate
            value_transfer: false,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::Mint => Effects {
            state_mutation: true,
            external_call: false,
            authority_required: false, // set by guard predicate
            value_transfer: true,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::Burn => Effects {
            state_mutation: true,
            external_call: false,
            authority_required: false, // set by guard predicate
            value_transfer: true,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::Pause => Effects {
            state_mutation: true,
            external_call: false,
            authority_required: false, // set by guard predicate
            value_transfer: false,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::OracleDependency => Effects {
            state_mutation: false,
            external_call: true,
            authority_required: false, // permissionless
            value_transfer: false,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::BridgeDependency => Effects {
            state_mutation: false,
            external_call: true,
            authority_required: false, // set by guard predicate
            value_transfer: false,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::FlashLoan => Effects {
            state_mutation: false,
            external_call: true,
            authority_required: false, // permissionless
            value_transfer: true,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::Delegatecall => Effects {
            state_mutation: true,
            external_call: true,
            authority_required: false, // set by guard predicate
            value_transfer: false,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::Treasury => Effects {
            state_mutation: true,
            external_call: false,
            authority_required: false, // set by guard predicate
            value_transfer: true,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
        CapabilityKind::Governance => Effects {
            state_mutation: true,
            external_call: false,
            authority_required: false, // set by guard predicate
            value_transfer: false,
            has_arithmetic: false,
            has_temporal_guard: false,
            value_flow: None,
            has_unchecked_arithmetic: false,
            writes_caller_scoped_state: false,
            has_precision_loss_ordering: false,
        },
    }
}

/// Guard predicate (SAFETY-CRITICAL): is there AFFIRMATIVE recovered evidence
/// of a controlling authority for this capability?
///
/// # Evidence Rule
///
/// `authority_required = true` ONLY when the capability's Permission has
/// `holder.is_some()` — meaning the controlling authority's address was
/// actually recovered from deployment evidence.
///
/// ## Why Permission existence is NOT sufficient
///
/// `derive_permissions` emits a Permission for EVERY privileged capability
/// unconditionally (permissions.rs:75-101). The module doc states: "permissions
/// are facts about WHAT privileged actions exist, never judgments about whether
/// they are safe." Permission existence records the ACTION, not the AUTHORITY.
///
/// ## What actually constitutes authority evidence
///
/// The ONLY per-capability authority evidence in the ProtocolModel is
/// `Permission.holder`:
/// - `holder = Some(addr)`: the controlling authority's address was recovered.
///   This is affirmative evidence of a guard.
/// - `holder = None`: no authority address was recovered. For Upgrade, this
///   means no UpgradeAuthority actor was found. For Mint/Burn/Pause/Treasury/
///   Governance, `holder` is HARDCODED to None by `derive_permissions`
///   (permissions.rs:90-94) — the model does NOT recover their authorities.
///
/// ## TrustBoundary/TrustGraph cannot help
///
/// `TrustBoundary { kind, inside_id, outside_id }` and `TrustEdge` are generic
/// zone-crossing edges (protocol core → actor/external system). They do NOT
/// associate a controlling actor with a specific capability. No per-capability
/// authority evidence exists for non-Upgrade actions.
///
/// ## Rules
///
/// 1. `Permission.holder.is_some()` → `authority_required = true` (real authority
///    evidence).
/// 2. `Permission.holder.is_none()` → `authority_required = false` (no authority
///    evidence; surface the risk).
/// 3. No matching Permission → `authority_required = false` (permissionless caps).
///
/// ## Model limitation
///
/// Currently ONLY Upgrade can be proven guarded (when an UpgradeAuthority actor
/// was recovered). Mint/Burn/Pause/Treasury/Governance carry no recovered
/// controlling-authority data (holder is hardcoded None), so they conservatively
/// surface as UNGUARDED until the model is enhanced to recover their authorities.
/// This is a model-layer limitation, not a bridge limitation.
///
/// This predicate is deterministic and pure over the ProtocolModel.
fn has_authority_evidence(capability: &Capability, permissions: &[Permission]) -> bool {
    permissions
        .iter()
        .any(|p| p.capability_fact_id == capability.id && p.holder.is_some())
}

/// Synthesize a single `Function` from a resolved `Capability`.
///
/// D1 contract:
/// - `id`: the capability's own id (cap:<digest>) — unique, deterministic
/// - `name`: `"__gen5::<kind>"` or `"__gen5::<kind>::<digest8>"` on collision
/// - `visibility`: `Public` — all capabilities are externally invokable
/// - `inputs`/`outputs`: empty (no signature recovered)
/// - `modifiers`: ALWAYS EMPTY — guard presence lives ONLY in effects
/// - `effects`: from mapping table + authority evidence predicate
pub fn synthesize_function(capability: &Capability, permissions: &[Permission]) -> Function {
    let mut effects = effects_for_kind(capability.kind);

    // Authority evidence predicate: set authority_required based on recovered evidence.
    effects.authority_required = has_authority_evidence(capability, permissions);

    Function {
        id: capability.id.clone(),
        name: unique_function_name(capability),
        contract: String::new(),
        visibility: Visibility::Public,
        inputs: vec![],
        outputs: vec![],
        modifiers: vec![],
        effects,
    }
}

/// Synthesize Functions for all resolved capabilities.
///
/// Handles name uniqueness: when multiple capabilities share a kind, each gets
/// a deterministic disambiguator (short cap digest). Output is sorted by
/// function id for deterministic ordering.
pub fn synthesize_functions(
    capabilities: &[Capability],
    permissions: &[Permission],
) -> Vec<Function> {
    // Count occurrences per kind to detect collisions.
    let mut kind_counts: std::collections::BTreeMap<CapabilityKind, u32> =
        std::collections::BTreeMap::new();
    for c in capabilities {
        *kind_counts.entry(c.kind).or_insert(0) += 1;
    }

    let mut functions: Vec<Function> = capabilities
        .iter()
        .map(|c| {
            let mut f = synthesize_function(c, permissions);
            // Disambiguate if multiple caps share the same kind.
            if kind_counts[&c.kind] > 1 {
                let digest8 = &c.id[..c.id.len().min(16)]; // first 16 chars of cap:<digest>
                f.name = format!("__gen5::{}::{}", c.kind.label(), digest8);
            }
            f
        })
        .collect();
    crate::ordering::canonical_function_order(&mut functions);
    functions
}

/// Generate a unique function name for a capability.
///
/// When there's exactly one capability of this kind, the name is
/// `"__gen5::<kind>"`. When there are multiple, `synthesize_functions`
/// handles disambiguation. This function produces the base name.
fn unique_function_name(capability: &Capability) -> String {
    format!("__gen5::{}", capability.kind.label())
}
