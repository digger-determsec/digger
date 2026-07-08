//! Deterministic unit tests for Gen 5 shared helpers.

use super::*;

#[test]
fn canon_is_deterministic() {
    assert_eq!(canon(&["a", "b", "c"]), "a|b|c");
    assert_eq!(canon(&[]), "");
}

#[test]
fn join_ids_is_deterministic_and_sorted() {
    let ids = vec!["c".into(), "a".into(), "b".into()];
    assert_eq!(join_ids(&ids), "a,b,c");
    let ids = vec!["a".into(), "a".into(), "b".into()];
    assert_eq!(join_ids(&ids), "a,b");
}

#[test]
fn normalize_ids_is_deterministic() {
    let mut ids = vec!["c".into(), "a".into(), "b".into()];
    normalize_ids(&mut ids);
    assert_eq!(ids, vec!["a", "b", "c"]);
}

#[test]
fn sorted_unique_is_deterministic() {
    let v = sorted_unique(vec!["c".into(), "a".into(), "b".into(), "a".into()]);
    assert_eq!(v, vec!["a", "b", "c"]);
}

#[test]
fn derive_provenance_is_deterministic() {
    let p1 = derive_provenance("input1", "basis1");
    let p2 = derive_provenance("input1", "basis1");
    assert_eq!(p1.id, p2.id);
    assert_eq!(
        p1.confidence,
        ::digger_reconstruct::confidence::ConfidenceTier::Inferred
    );
    assert_eq!(
        p1.originating_evidence,
        ::digger_reconstruct::provenance::EvidenceSource::Inferred
    );
    assert_eq!(
        p1.stage,
        ::digger_reconstruct::provenance::ReconstructionStage::Enrich
    );
}

#[test]
fn derive_provenance_basis_changes_id() {
    let p1 = derive_provenance("input", "basis1");
    let p2 = derive_provenance("input", "basis2");
    assert_ne!(p1.id, p2.id);
}

#[test]
fn node_id_is_reexported() {
    let id = node_id("test", "abc123");
    assert!(id.starts_with("test:"));
}

#[test]
fn digest_str_is_reexported() {
    let d = digest_str("hello");
    assert_eq!(d.len(), 16);
}

// ── canon() focused tests ──

#[test]
fn canon_same_input_same_output() {
    let input = &["x", "y", "z"];
    assert_eq!(canon(input), canon(input));
}

#[test]
fn canon_different_inputs_differ() {
    assert_ne!(canon(&["a", "b"]), canon(&["b", "a"]));
}

#[test]
fn canon_single_element() {
    assert_eq!(canon(&["only"]), "only");
}

#[test]
fn canon_special_characters() {
    assert_eq!(canon(&["a|b", "c|d"]), "a|b|c|d");
}

// ── join_ids() focused tests ──

#[test]
fn join_ids_empty() {
    assert_eq!(join_ids(&[]), "");
}

#[test]
fn join_ids_single() {
    assert_eq!(join_ids(&["one".into()]), "one");
}

#[test]
fn join_ids_already_sorted() {
    assert_eq!(join_ids(&["a".into(), "b".into(), "c".into()]), "a,b,c");
}

#[test]
fn join_ids_empty_strings() {
    assert_eq!(join_ids(&["".into(), "".into()]), "");
}

// ── normalize_ids() focused tests ──

#[test]
fn normalize_ids_empty() {
    let mut ids: Vec<String> = vec![];
    normalize_ids(&mut ids);
    assert!(ids.is_empty());
}

#[test]
fn normalize_ids_single() {
    let mut ids = vec!["only".into()];
    normalize_ids(&mut ids);
    assert_eq!(ids, vec!["only"]);
}

#[test]
fn normalize_ids_all_duplicates() {
    let mut ids = vec!["x".into(), "x".into(), "x".into()];
    normalize_ids(&mut ids);
    assert_eq!(ids, vec!["x"]);
}

#[test]
fn normalize_ids_already_sorted() {
    let mut ids = vec!["a".into(), "b".into(), "c".into()];
    normalize_ids(&mut ids);
    assert_eq!(ids, vec!["a", "b", "c"]);
}

// ── sorted_unique() focused tests ──

#[test]
fn sorted_unique_empty() {
    assert!(sorted_unique(vec![]).is_empty());
}

#[test]
fn sorted_unique_single() {
    assert_eq!(sorted_unique(vec!["only".into()]), vec!["only"]);
}

#[test]
fn sorted_unique_all_duplicates() {
    assert_eq!(sorted_unique(vec!["x".into(), "x".into()]), vec!["x"]);
}

#[test]
fn sorted_unique_mixed_with_empty() {
    assert_eq!(
        sorted_unique(vec!["b".into(), "".into(), "a".into(), "".into()]),
        vec!["", "a", "b"]
    );
}

// ── derive_provenance() focused tests ──

#[test]
fn derive_provenance_different_inputs_differ() {
    let p1 = derive_provenance("input-a", "basis");
    let p2 = derive_provenance("input-b", "basis");
    assert_ne!(p1.id, p2.id);
}

#[test]
fn derive_provenance_basis_field() {
    let p = derive_provenance("inp", "fact-id-1");
    assert_eq!(p.basis.as_deref(), Some("fact-id-1"));
}

#[test]
fn derive_provenance_same_input_same_id() {
    let p1 = derive_provenance("dup", "dup");
    let p2 = derive_provenance("dup", "dup");
    assert_eq!(p1.id, p2.id);
    assert_eq!(p1.basis, p2.basis);
}
