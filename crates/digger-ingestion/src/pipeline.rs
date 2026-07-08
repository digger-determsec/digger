/// Ingestion pipeline — orchestrates fetch -> normalize -> validate -> change detect -> incremental store.
///
/// Uses artifact manifests to detect new, modified, and removed artifacts.
/// Only changed artifacts are processed. Unchanged artifacts are skipped entirely.
/// Same input -> same output, always.
///
/// The `run_offline_cycle` function processes EXISTING on-disk corpus data
/// without any network fetch — this is the offline host entry point.
use crate::dedup;
use crate::manifest::{self, SourceManifest};
use crate::sources::{self, SourceConfig};
use crate::store::{self, IngestionBatch};
use crate::IngestionError;
use digger_knowledge_models::NormalizedKnowledge;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::SystemTime;

/// Default directory for manifest files.
pub const MANIFEST_DIR: &str = ".digger/manifests";

/// Run the full ingestion pipeline with incremental change detection.
pub fn run_ingestion(
    corpus_dir: &str,
    source_filter: Option<&str>,
) -> Result<Vec<IngestionBatch>, IngestionError> {
    let corpus_path = Path::new(corpus_dir);
    let manifest_dir = corpus_path.join(MANIFEST_DIR);
    let existing_hashes = store::load_existing_hashes(corpus_path);
    let sources = sources::get_sources();
    let mut batches = Vec::new();

    for source in &sources {
        if let Some(filter) = source_filter {
            if source.source_id != filter {
                continue;
            }
        }

        if !source.enabled {
            continue;
        }

        let batch = run_source_ingestion(source, corpus_path, &manifest_dir, &existing_hashes)?;
        batches.push(batch);
    }

    // Rebuild knowledge graph if any source changed
    let total_changes: usize = batches
        .iter()
        .map(|b| b.new_artifacts + b.modified_artifacts + b.removed_artifacts)
        .sum();

    if total_changes > 0 {
        let graph_cache_dir = corpus_path.join(".digger/graph_cache");
        let corpus_path2 = corpus_path;
        let mut all_findings: Vec<digger_knowledge_models::NormalizedFinding> = Vec::new();

        // Collect all findings from all source corpus files
        for source in &sources {
            if !source.enabled {
                continue;
            }
            let items = store::load_corpus(corpus_path2, &source.source_id);
            for item in items {
                all_findings.extend(item.findings);
            }
        }

        let cached =
            digger_knowledge::graph_builder::build_or_load_graph(&all_findings, &graph_cache_dir);

        for batch in &mut batches {
            if batch.new_artifacts + batch.modified_artifacts + batch.removed_artifacts > 0 {
                batch.errors.push(format!(
                    "Graph: {} nodes, {} edges ({} findings)",
                    cached.node_count, cached.edge_count, cached.finding_count
                ));
            }
        }
    }

    Ok(batches)
}

/// Run an offline ingestion cycle over existing on-disk corpus data.
///
/// This processes all JSON files already in the corpus directory without
/// any network fetch. It rebuilds the knowledge graph from the existing
/// data and produces a deterministic snapshot hash. This is the entry
/// point for the always-on offline host.
///
/// The network-fetch path (`run_ingestion`) is separate and default-off.
pub fn run_offline_cycle(corpus_dir: &str) -> Result<OfflineCycleResult, IngestionError> {
    let corpus_path = Path::new(corpus_dir);
    if !corpus_path.exists() {
        return Err(IngestionError::Other(format!(
            "corpus directory '{}' does not exist",
            corpus_dir
        )));
    }

    // Load all findings from existing corpus files
    let mut all_findings: Vec<digger_knowledge_models::NormalizedFinding> = Vec::new();
    let sources = sources::get_sources();

    for source in &sources {
        if !source.enabled {
            continue;
        }
        let items = store::load_corpus(corpus_path, &source.source_id);
        for item in items {
            all_findings.extend(item.findings);
        }
    }

    let finding_count = all_findings.len();

    // Rebuild knowledge graph
    let graph_cache_dir = corpus_path.join(".digger/graph_cache");
    let cached =
        digger_knowledge::graph_builder::build_or_load_graph(&all_findings, &graph_cache_dir);

    // Compute content hash for snapshot pinning
    let snapshot_hash = compute_offline_snapshot_hash(&all_findings);

    Ok(OfflineCycleResult {
        finding_count,
        graph_nodes: cached.node_count,
        graph_edges: cached.edge_count,
        snapshot_hash,
    })
}

/// Result of an offline ingestion cycle.
#[derive(Debug, Clone)]
pub struct OfflineCycleResult {
    /// Number of findings processed from disk.
    pub finding_count: usize,
    /// Knowledge graph node count.
    pub graph_nodes: usize,
    /// Knowledge graph edge count.
    pub graph_edges: usize,
    /// Deterministic content hash (FNV-1a) for snapshot pinning.
    pub snapshot_hash: String,
}

/// Compute a deterministic content hash for a set of findings (FNV-1a).
fn compute_offline_snapshot_hash(
    findings: &[digger_knowledge_models::NormalizedFinding],
) -> String {
    let mut pairs: Vec<(&str, String)> = findings
        .iter()
        .map(|f| (f.finding_id.as_str(), f.vulnerability_class.to_string()))
        .collect();
    pairs.sort();
    let mut hash: u64 = 14695981039346656037;
    for (fid, cls) in &pairs {
        for byte in fid.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(1099511628211);
        }
        for byte in cls.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(1099511628211);
        }
    }
    format!("{:016x}", hash)
}

/// Run ingestion for a single source with incremental change detection.
fn run_source_ingestion(
    source: &SourceConfig,
    corpus_dir: &Path,
    manifest_dir: &Path,
    existing_hashes: &BTreeSet<String>,
) -> Result<IngestionBatch, IngestionError> {
    let timestamp = real_now();
    let mut batch = IngestionBatch::new(&source.source_id, &timestamp);

    // Generate run ID
    batch.run_id = store::compute_run_id(&source.source_id, &timestamp);

    // Load manifest for this source
    let mut manifest = SourceManifest::load(manifest_dir, &source.source_id);

    // 1. Fetch
    let items = match source.source_id.as_str() {
        "code4rena" => {
            crate::sources::code4rena::ingest("code-423n4", "2021-02-slingshot-findings")
                .unwrap_or_else(|e| {
                    batch.errors.push(format!("Fetch error: {}", e));
                    vec![]
                })
        }
        "sherlock" => {
            crate::sources::sherlock::ingest("sherlock-audit", "2022-08-sentiment-judging")
                .unwrap_or_else(|e| {
                    batch.errors.push(format!("Fetch error: {}", e));
                    vec![]
                })
        }
        "defillama" => crate::sources::defillama::ingest().unwrap_or_else(|e| {
            batch.errors.push(format!("Fetch error: {}", e));
            vec![]
        }),
        "slowmist" => crate::sources::slowmist::ingest().unwrap_or_else(|e| {
            batch.errors.push(format!("Fetch error: {}", e));
            vec![]
        }),
        "rekt" => crate::sources::rekt::ingest().unwrap_or_else(|e| {
            batch.errors.push(format!("Fetch error: {}", e));
            vec![]
        }),
        "defihacklabs" => crate::sources::defihacklabs::ingest().unwrap_or_else(|e| {
            batch.errors.push(format!("Fetch error: {}", e));
            vec![]
        }),
        "immunefi" => crate::sources::immunefi::ingest().unwrap_or_else(|e| {
            batch.errors.push(format!("Fetch error: {}", e));
            vec![]
        }),
        "github-advisories" => crate::sources::github_advisories::ingest().unwrap_or_else(|e| {
            batch.errors.push(format!("Fetch error: {}", e));
            vec![]
        }),
        "solana-docs" => crate::sources::solana_docs::ingest().unwrap_or_else(|e| {
            batch.errors.push(format!("Fetch error: {}", e));
            vec![]
        }),
        _ => {
            batch
                .errors
                .push(format!("Unknown source: {}", source.source_id));
            vec![]
        }
    };

    batch.fetched_count = items.len();
    batch.normalized_count = items.len();

    // 2. Validate (confidence check)
    let validated: Vec<NormalizedKnowledge> = items
        .into_iter()
        .filter(|item| item.findings.iter().all(|f| f.confidence >= 0.5))
        .collect();
    batch.validated_count = validated.len();

    // 3. Change detection against manifest
    let changes = manifest::detect_changes(&validated, &manifest);
    batch.new_artifacts = changes.new.len();
    batch.modified_artifacts = changes.modified.len();
    batch.unchanged_artifacts = changes.unchanged.len();
    batch.removed_artifacts = changes.missing.len();

    // 4. Legacy dedup (finding-level, against full corpus)
    let all_finding_ids: Vec<String> = validated
        .iter()
        .flat_map(|item| item.findings.iter().map(|f| f.finding_id.clone()))
        .collect();
    let dedup_result = dedup::dedup_findings(&all_finding_ids, existing_hashes);
    batch.dedup_count = dedup_result.duplicate_count;

    // 5. Filter to only new + modified artifacts
    let change_set: BTreeSet<String> = changes
        .new
        .iter()
        .chain(changes.modified.iter())
        .cloned()
        .collect();

    let dedup_set: BTreeSet<String> = dedup_result.new_ids.iter().cloned().collect();

    let to_store: Vec<NormalizedKnowledge> = validated
        .into_iter()
        .filter(|item| {
            // Store if:
            // (a) artifact is new or modified in manifest, OR
            // (b) artifact has new findings not in corpus
            change_set.contains(&item.knowledge_id)
                || item
                    .findings
                    .iter()
                    .any(|f| dedup_set.contains(&f.finding_id))
        })
        .collect();

    // 6. Incremental store — merge into existing corpus
    let existing_corpus = store::load_corpus(corpus_dir, &source.source_id);
    let modified_ids: BTreeSet<String> = changes.modified.iter().cloned().collect();
    let removed_ids: BTreeSet<String> = changes.missing.iter().cloned().collect();

    let merged = store::merge_corpus(existing_corpus, to_store, &modified_ids, &removed_ids);

    if !merged.is_empty() {
        let output_path = corpus_dir.join(format!("{}.json", source.source_id));
        match store::store_knowledge(&merged, &output_path) {
            Ok(count) => batch.stored_count = count,
            Err(e) => batch.errors.push(format!("Store error: {}", e)),
        }
    }

    // 7. Update manifest
    let _fetched_ids: BTreeSet<String> = merged
        .iter()
        .map(|item| item.knowledge_id.clone())
        .collect();

    for item in &merged {
        let content_hash = SourceManifest::compute_content_hash(item);
        manifest.record_ingestion(item, &content_hash, &timestamp, &batch.run_id);
    }

    // Mark missing artifacts as removed
    if !changes.missing.is_empty() {
        let all_fetched_ids: BTreeSet<String> =
            merged.iter().map(|i| i.knowledge_id.clone()).collect();
        manifest.mark_missing_as_removed(&all_fetched_ids, &timestamp);
    }

    manifest.last_sync = timestamp;
    if let Err(e) = manifest.save(manifest_dir) {
        batch.errors.push(format!("Manifest save error: {}", e));
    }

    batch.batch_id = store::compute_batch_id(&source.source_id, &merged);

    Ok(batch)
}

/// Get current UTC timestamp.
fn real_now() -> String {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            // Simple UTC formatting without external deps
            let days = secs / 86400;
            let time_of_day = secs % 86400;
            let hours = time_of_day / 3600;
            let minutes = (time_of_day % 3600) / 60;
            let seconds = time_of_day % 60;

            // Convert days since epoch to Y-M-D (simplified)
            let mut y = 1970u64;
            let mut remaining = days;
            loop {
                let days_in_year = if is_leap(y) { 366 } else { 365 };
                if remaining < days_in_year {
                    break;
                }
                remaining -= days_in_year;
                y += 1;
            }
            let m = day_of_year_to_month(remaining, is_leap(y));
            let d = day_of_year_to_day(remaining, is_leap(y));

            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                y, m, d, hours, minutes, seconds
            )
        }
        Err(_) => "2026-01-01T00:00:00Z".into(),
    }
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn day_of_year_to_month(day: u64, leap: bool) -> u64 {
    // M3 FIX: Correct cumulative month boundaries
    let feb = if leap { 29 } else { 28 };
    let cumulative = [
        0,
        31,
        31 + feb,
        31 + feb + 31,
        31 + feb + 61,
        31 + feb + 91,
        31 + feb + 121,
        31 + feb + 152,
        31 + feb + 183,
        31 + feb + 213,
        31 + feb + 244,
        31 + feb + 274,
        31 + feb + 304,
    ];
    for m in 0..12u64 {
        if day <= cumulative[(m + 1) as usize] {
            return m + 1;
        }
    }
    12
}

fn day_of_year_to_day(day: u64, leap: bool) -> u64 {
    let feb = if leap { 29 } else { 28 };
    let cumulative = [
        0,
        31,
        31 + feb,
        31 + feb + 31,
        31 + feb + 61,
        31 + feb + 91,
        31 + feb + 121,
        31 + feb + 152,
        31 + feb + 183,
        31 + feb + 213,
        31 + feb + 244,
        31 + feb + 274,
        31 + feb + 304,
    ];
    for m in 0..12u64 {
        if day <= cumulative[(m + 1) as usize] {
            return day - cumulative[m as usize] + 1;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_now_format() {
        let ts = real_now();
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        assert_eq!(ts.len(), 20);
    }

    #[test]
    fn test_is_leap() {
        assert!(is_leap(2024));
        assert!(!is_leap(2023));
        assert!(is_leap(2000));
        assert!(!is_leap(1900));
    }

    #[test]
    fn test_offline_cycle_missing_dir_errors() {
        let result = run_offline_cycle("/nonexistent/path/does/not/exist");
        assert!(result.is_err());
    }

    #[test]
    fn test_offline_cycle_empty_dir() {
        let dir = std::env::temp_dir().join("digger_offline_test_empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let result = run_offline_cycle(dir.to_str().unwrap());
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.finding_count, 0);
        assert!(r.snapshot_hash.len() == 16);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_offline_cycle_deterministic() {
        let dir = std::env::temp_dir().join("digger_offline_test_det");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Write as code4rena.json (an enabled source_id from get_sources())
        let json = serde_json::json!([{
            "knowledge_id": "k:test",
            "source_id": "test",
            "source_kind": "AuditRepository",
            "source_identifier": "test.json",
            "subject": "Test",
            "subject_category": "test",
            "findings": [{
                "finding_id": "det-001",
                "original_finding_id": "T-1",
                "report_id": "r-1",
                "protocol_name": "Test",
                "protocol_category": "Vault",
                "protocol_domain": "Vaults",
                "protocol_pattern": null,
                "vulnerability_class": "Reentrancy",
                "attack_goal": "drain",
                "capability_pattern": [],
                "violated_invariant": {"kind": "conservation", "description": "", "affected_state_vars": []},
                "attack_technique": "ReentrancyExploit",
                "mitigation_pattern": null,
                "security_assumptions": [],
                "severity": "High",
                "root_cause": "MissingAuthorityCheck",
                "impact_text": "",
                "description_text": "",
                "remediation_text": "",
                "impacted_contracts": [],
                "impacted_functions": [],
                "confidence": 1.0
            }],
            "evidence": [],
            "invariants": [],
            "architectural_patterns": [],
            "mitigation_patterns": [],
            "references": [],
            "claims": [],
            "raw_sections": {}
        }]);
        std::fs::write(
            dir.join("code4rena.json"),
            serde_json::to_string_pretty(&json).unwrap(),
        )
        .unwrap();

        let r1 = run_offline_cycle(dir.to_str().unwrap()).unwrap();
        let r2 = run_offline_cycle(dir.to_str().unwrap()).unwrap();

        assert_eq!(r1.finding_count, 1);
        assert_eq!(
            r1.snapshot_hash, r2.snapshot_hash,
            "offline cycle must be deterministic"
        );
        assert_eq!(r1.finding_count, r2.finding_count);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
