//! Deterministic ordering — ensures SystemIR output vectors are sorted by
//! content key (function name, state name, edge kind+from+to).
//!
//! D2 contract: ordering is by structural content key, NOT investigation priority.
//!
//! This module is the SINGLE canonical-ordering authority. All other modules
//! must delegate to these functions — never sort inline.

use digger_ir::{Edge, Function};

/// Deterministic sort key for edges.
///
/// Key = (edge_kind_tag, primary_field, secondary_field).
/// Ordering by tag first (Authority=0, External=1, Call=2, State=3),
/// then by primary field (function/from name), then secondary (check_type/target/to/state).
pub fn edge_sort_key(edge: &Edge) -> (u8, String, String) {
    match edge {
        Edge::Authority(a) => (0, a.function.clone(), a.check_type.clone()),
        Edge::External(e) => (1, e.function.clone(), e.target.clone()),
        Edge::Call(c) => (2, c.from.clone(), c.to.clone()),
        Edge::State(s) => (3, s.function.clone(), s.state.clone()),
    }
}

/// Sort functions by id ascending — the canonical order for SystemIR output.
pub fn canonical_function_order(functions: &mut [Function]) {
    functions.sort_by(|a, b| a.id.cmp(&b.id));
}

/// Sort edges by the canonical edge_sort_key — the canonical order for SystemIR output.
pub fn canonical_edge_order(edges: &mut [Edge]) {
    edges.sort_by_key(edge_sort_key);
}
