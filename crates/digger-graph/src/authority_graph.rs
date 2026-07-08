use crate::analysis::authority_analyzer;
/// Authority Graph — generates Authority edges for SystemIR.
///
/// Phase 7.1: Uses AST-aware authority analysis instead of substring matching.
/// Distinguishes genuine authorization checks from generic invariant checks.
///
/// Output: Vec<Edge::Authority> — compatible with frozen SystemIR.
use digger_ir::*;
use digger_parser::model::*;

/// Build authority edges from RawProgram.
///
/// Uses the new authority analyzer to distinguish genuine authorization
/// checks from generic invariant checks. Only genuine authority checks
/// produce "enforced" edges. Invariant checks produce "invariant" edges.
///
/// For Anchor programs (with metadata), "missing" edges come exclusively
/// from the builder's constraint check — the body analyzer can't see
/// #[derive(Accounts)] constraints. For non-Anchor programs, the body
/// analyzer emits "missing" for functions without recognized auth patterns.
pub fn build(program: &RawProgram) -> Vec<Edge> {
    let graph = authority_analyzer::analyze_authority(program);

    // For Anchor programs: the builder's extract_anchor_constraints handles
    // "missing" edges correctly. Suppress body-analyzer "missing" to avoid
    // false positives (body analyzer can't see Anchor constraints).
    let has_anchor_metadata = program
        .metadata
        .extra
        .keys()
        .any(|k| k.starts_with("anchor_struct_") || k.starts_with("anchor_accounts_"));

    graph
        .relations
        .iter()
        .filter_map(|rel| {
            let check_type = if rel.enforced && !rel.is_invariant {
                "enforced".to_string()
            } else if rel.is_invariant {
                "invariant".to_string()
            } else if has_anchor_metadata {
                // Anchor: body analyzer can't see constraints — builder handles "missing"
                return None;
            } else {
                "missing".to_string()
            };

            let authority_source = rel.source.to_string();

            Some(Edge::Authority(AuthorityEdge {
                function: rel.function.clone(),
                authority_source,
                check_type,
            }))
        })
        .collect()
}
