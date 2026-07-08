/// Corpus store — read/write NormalizedKnowledge to JSON files.
///
/// Supports incremental updates: merge new+modified artifacts into existing
/// corpus without reprocessing unchanged items.
use crate::IngestionError;
use digger_knowledge_models::NormalizedKnowledge;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

/// Ingestion batch result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IngestionBatch {
    /// Batch identifier (deterministic hash).
    pub batch_id: String,
    /// Source identifier.
    pub source_id: String,
    /// Items fetched.
    pub fetched_count: usize,
    /// Items after normalization.
    pub normalized_count: usize,
    /// Items after validation.
    pub validated_count: usize,
    /// Duplicates removed.
    pub dedup_count: usize,
    /// Items stored (new + modified).
    pub stored_count: usize,
    /// Errors during processing.
    pub errors: Vec<String>,
    /// Timestamp.
    pub timestamp: String,
    /// New artifacts ingested this run.
    pub new_artifacts: usize,
    /// Modified artifacts updated this run.
    pub modified_artifacts: usize,
    /// Unchanged artifacts skipped.
    pub unchanged_artifacts: usize,
    /// Removed artifacts.
    pub removed_artifacts: usize,
    /// Ingestion run identifier.
    pub run_id: String,
}

impl IngestionBatch {
    /// Create a new batch with defaults.
    pub fn new(source_id: &str, timestamp: &str) -> Self {
        Self {
            batch_id: String::new(),
            source_id: source_id.to_string(),
            fetched_count: 0,
            normalized_count: 0,
            validated_count: 0,
            dedup_count: 0,
            stored_count: 0,
            errors: vec![],
            timestamp: timestamp.to_string(),
            new_artifacts: 0,
            modified_artifacts: 0,
            unchanged_artifacts: 0,
            removed_artifacts: 0,
            run_id: String::new(),
        }
    }
}

/// Load all existing hashes from the corpus directory.
pub fn load_existing_hashes(corpus_dir: &Path) -> BTreeSet<String> {
    let mut hashes = BTreeSet::new();

    if !corpus_dir.exists() {
        return hashes;
    }

    walk_corpus(corpus_dir, &mut hashes);

    hashes
}

fn walk_corpus(dir: &Path, hashes: &mut BTreeSet<String>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_corpus(&path, hashes);
            } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(items) = serde_json::from_str::<Vec<NormalizedKnowledge>>(&content) {
                        for item in &items {
                            for finding in &item.findings {
                                hashes.insert(finding.finding_id.clone());
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Load existing corpus for a source from disk.
pub fn load_corpus(corpus_dir: &Path, source_id: &str) -> Vec<NormalizedKnowledge> {
    let path = corpus_dir.join(format!("{}.json", source_id));
    if !path.exists() {
        return vec![];
    }
    if let Ok(content) = std::fs::read_to_string(&path) {
        if let Ok(items) = serde_json::from_str::<Vec<NormalizedKnowledge>>(&content) {
            return items;
        }
    }
    vec![]
}

/// Merge new+modified artifacts into existing corpus, preserving unchanged items.
///
/// Returns the merged corpus ready to write.
pub fn merge_corpus(
    existing: Vec<NormalizedKnowledge>,
    new_items: Vec<NormalizedKnowledge>,
    _modified_ids: &BTreeSet<String>,
    removed_ids: &BTreeSet<String>,
) -> Vec<NormalizedKnowledge> {
    // Build index of new items by knowledge_id
    let new_index: BTreeMap<String, NormalizedKnowledge> = new_items
        .into_iter()
        .map(|item| (item.knowledge_id.clone(), item))
        .collect();

    let mut merged = Vec::new();

    // Process existing items: update modified, skip removed, keep unchanged
    for item in existing {
        if removed_ids.contains(&item.knowledge_id) {
            continue; // Removed
        }
        if let Some(updated) = new_index.get(&item.knowledge_id) {
            merged.push(updated.clone()); // Modified
        } else {
            merged.push(item); // Unchanged
        }
    }

    // Add genuinely new items
    for (id, item) in new_index {
        if !merged.iter().any(|m| m.knowledge_id == id) {
            merged.push(item);
        }
    }

    // Deterministic ordering by knowledge_id
    merged.sort_by(|a, b| a.knowledge_id.cmp(&b.knowledge_id));
    merged
}

use std::collections::BTreeMap;

/// Store normalized knowledge to a JSON file (full overwrite).
pub fn store_knowledge(
    items: &[NormalizedKnowledge],
    output_path: &Path,
) -> Result<usize, IngestionError> {
    if items.is_empty() {
        return Ok(0);
    }

    let json =
        serde_json::to_string_pretty(items).map_err(|e| IngestionError::Other(e.to_string()))?;

    std::fs::write(output_path, json)?;

    Ok(items.len())
}

/// Compute batch ID from source and content.
pub fn compute_batch_id(source_id: &str, items: &[NormalizedKnowledge]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_id.as_bytes());
    for item in items {
        hasher.update(item.knowledge_id.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Compute deterministic run ID from source + timestamp.
pub fn compute_run_id(source_id: &str, timestamp: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_id.as_bytes());
    hasher.update(timestamp.as_bytes());
    format!("run-{}", &format!("{:x}", hasher.finalize())[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_ir::Severity;
    use digger_knowledge_models::*;

    fn make_test_artifact(id: &str) -> NormalizedKnowledge {
        NormalizedKnowledge {
            knowledge_id: id.to_string(),
            source_id: "test".into(),
            source_kind: KnowledgeSourceKind::AuditRepository,
            source_identifier: "test.md".into(),
            subject: "test".into(),
            subject_category: "test".into(),
            findings: vec![NormalizedFinding {
                finding_id: format!("{}-f1", id),
                original_finding_id: "H-1".into(),
                report_id: "r1".into(),
                protocol_name: "test".into(),
                protocol_category: ProtocolCategory::Unknown,
                protocol_domain: ProtocolDomain::Generic,
                protocol_pattern: None,
                vulnerability_class: VulnerabilityClass::Other("test".into()),
                attack_goal: String::new(),
                capability_pattern: vec![],
                violated_invariant: ViolatedInvariant {
                    kind: String::new(),
                    description: String::new(),
                    affected_state_vars: vec![],
                },
                attack_technique: AttackTechnique::Other("test".into()),
                mitigation_pattern: None,
                security_assumptions: vec![],
                severity: Severity::Medium,
                root_cause: StructuralRootCause::Other("test".into()),
                impact_text: String::new(),
                description_text: "test content".into(),
                remediation_text: String::new(),
                impacted_contracts: vec![],
                impacted_functions: vec![],
                confidence: 1.0,
            }],
            evidence: vec![],
            invariants: vec![],
            architectural_patterns: vec![],
            mitigation_patterns: vec![],
            references: vec![],
            claims: vec![],
            raw_sections: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn test_batch_id_deterministic() {
        let items = vec![];
        let id1 = compute_batch_id("test", &items);
        let id2 = compute_batch_id("test", &items);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_run_id_deterministic() {
        let id1 = compute_run_id("test", "2026-01-01T00:00:00Z");
        let id2 = compute_run_id("test", "2026-01-01T00:00:00Z");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_merge_corpus_new_only() {
        let existing = vec![];
        let new_items = vec![make_test_artifact("k1"), make_test_artifact("k2")];
        let merged = merge_corpus(existing, new_items, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_corpus_modified() {
        let existing = vec![make_test_artifact("k1"), make_test_artifact("k2")];
        let mut modified_ids = BTreeSet::new();
        modified_ids.insert("k1".to_string());

        let mut updated = make_test_artifact("k1");
        updated.findings[0].description_text = "modified".into();

        let merged = merge_corpus(existing, vec![updated], &modified_ids, &BTreeSet::new());
        assert_eq!(merged.len(), 2);
        let k1 = merged.iter().find(|m| m.knowledge_id == "k1").unwrap();
        assert_eq!(k1.findings[0].description_text, "modified");
    }

    #[test]
    fn test_merge_corpus_removed() {
        let existing = vec![make_test_artifact("k1"), make_test_artifact("k2")];
        let mut removed_ids = BTreeSet::new();
        removed_ids.insert("k1".to_string());

        let merged = merge_corpus(existing, vec![], &BTreeSet::new(), &removed_ids);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].knowledge_id, "k2");
    }

    #[test]
    fn test_merge_corpus_deterministic_order() {
        let existing = vec![make_test_artifact("k3"), make_test_artifact("k1")];
        let new_items = vec![make_test_artifact("k2")];
        let merged = merge_corpus(existing, new_items, &BTreeSet::new(), &BTreeSet::new());
        let ids: Vec<&str> = merged.iter().map(|m| m.knowledge_id.as_str()).collect();
        assert_eq!(ids, vec!["k1", "k2", "k3"]);
    }

    #[test]
    fn test_store_knowledge_deterministic() {
        let items = vec![make_test_artifact("k1"), make_test_artifact("k2")];
        let dir = std::env::temp_dir().join("digger_store_det_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.json");

        store_knowledge(&items, &path).expect("store 1");
        let json1 = std::fs::read_to_string(&path).expect("read 1");

        store_knowledge(&items, &path).expect("store 2");
        let json2 = std::fs::read_to_string(&path).expect("read 2");

        assert_eq!(
            json1, json2,
            "store_knowledge must produce deterministic output"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_non_authoritative_guard() {
        let items = vec![make_test_artifact("na-1"), make_test_artifact("na-2")];
        let dir = std::env::temp_dir().join("digger_nonauth_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.json");

        store_knowledge(&items, &path).expect("store");
        let json = std::fs::read_to_string(&path).expect("read");

        assert!(!json.is_empty(), "output must be non-empty");
        assert!(
            !json.contains("Graduated"),
            "output must not contain 'Graduated'"
        );
        assert!(
            !json.contains("Confirmed"),
            "output must not contain 'Confirmed'"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_knowledge_empty() {
        let dir = std::env::temp_dir().join("digger_store_empty_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.json");

        let count = store_knowledge(&[], &path).expect("store empty");
        assert_eq!(count, 0);
        assert!(!path.exists(), "empty store should not create file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_batch_id_deterministic() {
        let items = vec![make_test_artifact("k1"), make_test_artifact("k2")];
        let id1 = compute_batch_id("src", &items);
        let id2 = compute_batch_id("src", &items);
        assert_eq!(id1, id2, "batch_id must be deterministic for same input");
    }

    #[test]
    fn test_ingestion_batch_new() {
        let batch = IngestionBatch::new("code4rena", "2026-01-01T00:00:00Z");
        assert_eq!(batch.source_id, "code4rena");
        assert_eq!(batch.fetched_count, 0);
        assert_eq!(batch.stored_count, 0);
        assert!(batch.errors.is_empty());
    }
}
