/// Artifact manifest — tracks every ingested artifact for incremental change detection.
///
/// Each source gets a manifest file at `.digger/manifests/{source_id}.json`.
/// The manifest records content hashes, timestamps, and state for every artifact,
/// enabling the pipeline to detect new, modified, removed, and unchanged artifacts
/// without reprocessing the full corpus.
use crate::IngestionError;
use digger_knowledge_models::NormalizedKnowledge;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Version of the manifest format.
pub const MANIFEST_VERSION: u32 = 1;

/// Version of the parser used during ingestion.
pub const PARSER_VERSION: &str = "1.0.0";

/// Version of the extractor used during ingestion.
pub const EXTRACTOR_VERSION: &str = "1.0.0";

/// State of an artifact in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArtifactState {
    /// Actively present in the corpus.
    Active,
    /// Detected as removed from the source.
    Removed,
    /// Failed extraction or normalization.
    Failed,
}

/// Metadata tracked for each ingested artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Deterministic content hash (SHA-256 of serialized artifact).
    pub content_hash: String,
    /// When this artifact was first ingested.
    pub first_seen: String,
    /// When this artifact was last seen during a sync.
    pub last_seen: String,
    /// When this artifact was last ingested/updated.
    pub ingested_at: String,
    /// Timestamp of the source data retrieval.
    pub retrieval_timestamp: String,
    /// Source-specific commit or version (if applicable).
    pub source_commit_or_version: Option<String>,
    /// Parser version that processed this artifact.
    pub parser_version: String,
    /// Extractor version that processed this artifact.
    pub extractor_version: String,
    /// Source identifier (filename, URL, etc.).
    pub source_identifier: String,
    /// Ingestion run ID that produced this artifact.
    pub ingestion_run_id: String,
    /// Finding IDs contained in this artifact.
    pub finding_ids: Vec<String>,
    /// Current state.
    pub state: ArtifactState,
}

/// Complete manifest for a single source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceManifest {
    /// Manifest format version.
    pub version: u32,
    /// Source identifier.
    pub source_id: String,
    /// Last successful sync timestamp.
    pub last_sync: String,
    /// Total active artifacts.
    pub active_count: usize,
    /// Total removed artifacts.
    pub removed_count: usize,
    /// All artifact entries keyed by knowledge_id.
    pub artifacts: BTreeMap<String, ArtifactEntry>,
}

/// Change classification for an artifact during sync.
#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactChange {
    /// New artifact not previously seen.
    New,
    /// Artifact content has changed since last ingestion.
    Modified {
        old_content_hash: String,
        new_content_hash: String,
    },
    /// Artifact is unchanged (same content hash).
    Unchanged,
}

/// Result of comparing fetched artifacts against the manifest.
#[derive(Debug, Clone)]
pub struct ChangeDetectionResult {
    /// New artifacts to ingest.
    pub new: Vec<String>,
    /// Modified artifacts to re-ingest.
    pub modified: Vec<String>,
    /// Unchanged artifacts to skip.
    pub unchanged: Vec<String>,
    /// Artifacts in manifest but not in fetch (potentially removed).
    pub missing: Vec<String>,
}

impl SourceManifest {
    /// Create a new empty manifest for a source.
    pub fn new(source_id: &str) -> Self {
        Self {
            version: MANIFEST_VERSION,
            source_id: source_id.to_string(),
            last_sync: String::new(),
            active_count: 0,
            removed_count: 0,
            artifacts: BTreeMap::new(),
        }
    }

    /// Load manifest from disk, or create empty if not found.
    pub fn load(manifest_dir: &Path, source_id: &str) -> Self {
        let path = Self::manifest_path(manifest_dir, source_id);
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(manifest) = serde_json::from_str::<SourceManifest>(&content) {
                    return manifest;
                }
            }
        }
        Self::new(source_id)
    }

    /// Save manifest to disk.
    pub fn save(&self, manifest_dir: &Path) -> Result<(), IngestionError> {
        std::fs::create_dir_all(manifest_dir)?;
        let path = Self::manifest_path(manifest_dir, &self.source_id);
        let json =
            serde_json::to_string_pretty(self).map_err(|e| IngestionError::Other(e.to_string()))?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Get the file path for a source manifest.
    pub fn manifest_path(manifest_dir: &Path, source_id: &str) -> PathBuf {
        manifest_dir.join(format!("{}.json", source_id))
    }

    /// Compute a deterministic content hash for a NormalizedKnowledge artifact.
    pub fn compute_content_hash(item: &NormalizedKnowledge) -> String {
        let json = serde_json::to_string(item).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Record an artifact as ingested in the manifest.
    pub fn record_ingestion(
        &mut self,
        item: &NormalizedKnowledge,
        content_hash: &str,
        timestamp: &str,
        run_id: &str,
    ) {
        let finding_ids: Vec<String> = item.findings.iter().map(|f| f.finding_id.clone()).collect();

        let entry = ArtifactEntry {
            content_hash: content_hash.to_string(),
            first_seen: self
                .artifacts
                .get(&item.knowledge_id)
                .map(|e| e.first_seen.clone())
                .unwrap_or_else(|| timestamp.to_string()),
            last_seen: timestamp.to_string(),
            ingested_at: timestamp.to_string(),
            retrieval_timestamp: timestamp.to_string(),
            source_commit_or_version: None,
            parser_version: PARSER_VERSION.to_string(),
            extractor_version: EXTRACTOR_VERSION.to_string(),
            source_identifier: item.source_identifier.clone(),
            ingestion_run_id: run_id.to_string(),
            finding_ids,
            state: ArtifactState::Active,
        };

        self.artifacts.insert(item.knowledge_id.clone(), entry);
        self.active_count = self
            .artifacts
            .values()
            .filter(|e| e.state == ArtifactState::Active)
            .count();
    }

    /// Mark artifacts as removed if they are not in the fetched set.
    pub fn mark_missing_as_removed(
        &mut self,
        fetched_ids: &std::collections::BTreeSet<String>,
        timestamp: &str,
    ) {
        for (id, entry) in &mut self.artifacts {
            if entry.state == ArtifactState::Active && !fetched_ids.contains(id) {
                entry.state = ArtifactState::Removed;
                entry.last_seen = timestamp.to_string();
                self.removed_count += 1;
            }
        }
        self.active_count = self
            .artifacts
            .values()
            .filter(|e| e.state == ArtifactState::Active)
            .count();
    }
}

/// Compare fetched artifacts against the manifest to detect changes.
pub fn detect_changes(
    fetched: &[NormalizedKnowledge],
    manifest: &SourceManifest,
) -> ChangeDetectionResult {
    let mut new = Vec::new();
    let mut modified = Vec::new();
    let mut unchanged = Vec::new();

    // Build set of fetched IDs for missing detection
    let fetched_ids: std::collections::BTreeSet<String> = fetched
        .iter()
        .map(|item| item.knowledge_id.clone())
        .collect();

    for item in fetched {
        let content_hash = SourceManifest::compute_content_hash(item);

        match manifest.artifacts.get(&item.knowledge_id) {
            Some(entry) if entry.content_hash == content_hash => {
                unchanged.push(item.knowledge_id.clone());
            }
            Some(_entry) => {
                modified.push(item.knowledge_id.clone());
            }
            None => {
                new.push(item.knowledge_id.clone());
            }
        }
    }

    // Find artifacts in manifest but not in fetched set
    let missing: Vec<String> = manifest
        .artifacts
        .iter()
        .filter(|(id, entry)| entry.state == ArtifactState::Active && !fetched_ids.contains(*id))
        .map(|(id, _)| id.clone())
        .collect();

    ChangeDetectionResult {
        new,
        modified,
        unchanged,
        missing,
    }
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
    fn test_content_hash_deterministic() {
        let item = make_test_artifact("k1");
        let h1 = SourceManifest::compute_content_hash(&item);
        let h2 = SourceManifest::compute_content_hash(&item);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_different_for_different_content() {
        let mut item1 = make_test_artifact("k1");
        let mut item2 = make_test_artifact("k1");
        item1.findings[0].description_text = "content A".into();
        item2.findings[0].description_text = "content B".into();
        let h1 = SourceManifest::compute_content_hash(&item1);
        let h2 = SourceManifest::compute_content_hash(&item2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_detect_changes_new_only() {
        let manifest = SourceManifest::new("test");
        let items = vec![make_test_artifact("k1"), make_test_artifact("k2")];
        let result = detect_changes(&items, &manifest);
        assert_eq!(result.new.len(), 2);
        assert_eq!(result.modified.len(), 0);
        assert_eq!(result.unchanged.len(), 0);
    }

    #[test]
    fn test_detect_changes_unchanged() {
        let mut manifest = SourceManifest::new("test");
        let item = make_test_artifact("k1");
        let hash = SourceManifest::compute_content_hash(&item);
        manifest.record_ingestion(&item, &hash, "2026-01-01T00:00:00Z", "run-1");

        let result = detect_changes(&[item], &manifest);
        assert_eq!(result.new.len(), 0);
        assert_eq!(result.unchanged.len(), 1);
    }

    #[test]
    fn test_detect_changes_modified() {
        let mut manifest = SourceManifest::new("test");
        let item1 = make_test_artifact("k1");
        let hash = SourceManifest::compute_content_hash(&item1);
        manifest.record_ingestion(&item1, &hash, "2026-01-01T00:00:00Z", "run-1");

        let mut item2 = make_test_artifact("k1");
        item2.findings[0].description_text = "modified content".into();
        let result = detect_changes(&[item2], &manifest);
        assert_eq!(result.modified.len(), 1);
        assert_eq!(result.unchanged.len(), 0);
    }

    #[test]
    fn test_detect_changes_missing() {
        let mut manifest = SourceManifest::new("test");
        let item = make_test_artifact("k1");
        let hash = SourceManifest::compute_content_hash(&item);
        manifest.record_ingestion(&item, &hash, "2026-01-01T00:00:00Z", "run-1");

        let result = detect_changes(&[], &manifest);
        assert_eq!(result.missing.len(), 1);
    }

    #[test]
    fn test_manifest_roundtrip() {
        let manifest = SourceManifest::new("test");
        let dir = std::env::temp_dir().join("digger_manifest_test");
        let _ = std::fs::create_dir_all(&dir);
        manifest.save(&dir).unwrap();
        let loaded = SourceManifest::load(&dir, "test");
        assert_eq!(loaded.source_id, "test");
        assert_eq!(loaded.version, MANIFEST_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
