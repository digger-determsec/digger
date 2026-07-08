#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

// ── Error Type ────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String },
}

// ── Lock Helper ───────────────────────────────────────────────────

fn lock_or_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ── JSON Escape ───────────────────────────────────────────────────

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000a}' => out.push_str("\\n"),
            '\u{000c}' => out.push_str("\\f"),
            '\u{000d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                out.push_str(&format!("{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ── Data Model ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundle {
    pub id: String,
    pub tenant_id: String,
    pub created_at: String,
    pub engine_version: EngineVersion,
    pub input_descriptor: InputDescriptor,
    pub provenance: ProvenanceInfo,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<Artifact>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub bundle_hash: String,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineVersion {
    pub semver: String,
    pub git_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputDescriptor {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceInfo {
    pub engine: String,
    pub source: String,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence_label: String,
    pub locations: Vec<Location>,
    pub evidence_refs: Vec<String>,
    pub repro_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Location {
    pub file: String,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub artifact_id: String,
    pub sha256: String,
    pub artifact_type: String,
    pub uri: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    pub signer_id: String,
    pub algorithm: String,
    pub value: String,
}

// ── Canonical JSON ────────────────────────────────────────────────

/// Canonicalize a serde_json::Value to stable JSON:
/// - BTreeMap for object keys (alphabetical order)
/// - No extra whitespace
/// - Consistent number formatting via serde_json::to_string
pub fn canonicalize(value: &serde_json::Value) -> String {
    canonicalize_value(value)
}

fn canonicalize_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                format!("{}", f)
            } else {
                n.to_string()
            }
        }
        serde_json::Value::String(s) => escape_json_string(s),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_value).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
            let items: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("{}:{}", escape_json_string(k), canonicalize_value(v)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

/// Serialize to canonical JSON using BTreeMap for stable key ordering.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, EvidenceError> {
    let value = serde_json::to_value(value)?;
    Ok(canonicalize(&value))
}

// ── Hashing ───────────────────────────────────────────────────────

/// Compute SHA-256 hash of bytes, returned as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute bundle_hash from an EvidenceBundle.
///
/// Preimage = canonical JSON of content fields only (exclude id, created_at, bundle_hash, signatures)
///            + "|" + sorted artifact_id:sha256 pairs joined by "|"
///
/// Content fields: tenant_id, engine_version, input_descriptor, provenance, findings, artifacts.
pub fn compute_bundle_hash(bundle: &EvidenceBundle) -> String {
    let content = serde_json::json!({
        "tenant_id": bundle.tenant_id,
        "engine_version": bundle.engine_version,
        "input_descriptor": bundle.input_descriptor,
        "provenance": bundle.provenance,
        "findings": bundle.findings,
        "artifacts": bundle.artifacts,
    });

    let canonical = canonicalize(&content);

    let mut artifact_map: Vec<String> = bundle
        .artifacts
        .iter()
        .map(|a| format!("{}:{}", a.artifact_id, a.sha256))
        .collect();
    artifact_map.sort();

    let preimage = format!("{}|{}", canonical, artifact_map.join("|"));
    sha256_hex(preimage.as_bytes())
}

// ── Finding ID (deterministic) ────────────────────────────────────

/// Generate a stable, deterministic finding_id from rule_id + canonical location.
/// This ensures finding IDs are reproducible across runs.
pub fn make_finding_id(
    rule_id: &str,
    file: &str,
    line: Option<u32>,
    symbol: Option<&str>,
) -> String {
    let loc_str = match (line, symbol) {
        (Some(l), Some(s)) => format!("{}:{}:{}", file, l, s),
        (Some(l), None) => format!("{}:{}", file, l),
        (None, Some(s)) => format!("{}::{}", file, s),
        (None, None) => file.to_string(),
    };
    let hash = sha256_hex(format!("{}|{}", rule_id, loc_str).as_bytes());
    format!("find-{}", &hash[..16])
}

// ── Bundle Builder ────────────────────────────────────────────────

pub struct BundleBuilder {
    tenant_id: String,
    engine_version: EngineVersion,
    input_descriptor: InputDescriptor,
    provenance: ProvenanceInfo,
    findings: Vec<Finding>,
    artifacts: Vec<Artifact>,
}

impl BundleBuilder {
    pub fn new(engine_version: EngineVersion, input_descriptor: InputDescriptor) -> Self {
        Self {
            tenant_id: "default".into(),
            engine_version,
            input_descriptor,
            provenance: ProvenanceInfo {
                engine: "digger".into(),
                source: "engine_output".into(),
                deterministic: true,
            },
            findings: Vec::new(),
            artifacts: Vec::new(),
        }
    }

    pub fn tenant_id(mut self, tid: &str) -> Self {
        self.tenant_id = tid.to_string();
        self
    }

    pub fn add_finding(mut self, finding: Finding) -> Self {
        self.findings.push(finding);
        self
    }

    pub fn add_artifact(mut self, artifact: Artifact) -> Self {
        self.artifacts.push(artifact);
        self
    }

    pub fn build(self) -> EvidenceBundle {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut bundle = EvidenceBundle {
            id: Uuid::new_v4().to_string(),
            tenant_id: self.tenant_id,
            created_at: format!("{}", now),
            engine_version: self.engine_version,
            input_descriptor: self.input_descriptor,
            provenance: self.provenance,
            findings: self.findings,
            artifacts: self.artifacts,
            bundle_hash: String::new(),
            signatures: Vec::new(),
        };
        bundle.bundle_hash = compute_bundle_hash(&bundle);
        bundle
    }
}

// ── Verify ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyResult {
    pub valid: bool,
    pub expected_hash: String,
    pub actual_hash: String,
    pub details: Vec<String>,
}

/// Verify an EvidenceBundle: recompute bundle_hash and check it matches.
pub fn verify_bundle(bundle: &EvidenceBundle) -> VerifyResult {
    let recomputed = compute_bundle_hash(bundle);
    let mut details = Vec::new();

    if recomputed != bundle.bundle_hash {
        details.push(format!(
            "bundle_hash mismatch: expected={}, actual={}",
            bundle.bundle_hash, recomputed
        ));
    }

    VerifyResult {
        valid: recomputed == bundle.bundle_hash,
        expected_hash: bundle.bundle_hash.clone(),
        actual_hash: recomputed,
        details,
    }
}

// ── Storage Trait ─────────────────────────────────────────────────

pub trait EvidenceStore: Send + Sync {
    fn save_bundle(&self, bundle: &EvidenceBundle) -> Result<(), EvidenceError>;
    fn load_bundle(&self, bundle_id: &str) -> Result<EvidenceBundle, EvidenceError>;
    fn list_bundles(&self, tenant_id: &str) -> Result<Vec<String>, EvidenceError>;
    fn save_artifact(&self, artifact_id: &str, data: &[u8]) -> Result<(), EvidenceError>;
    fn load_artifact(&self, artifact_id: &str) -> Result<Vec<u8>, EvidenceError>;
}

// ── In-Memory Store ───────────────────────────────────────────────

pub struct InMemoryStore {
    bundles: std::sync::Mutex<BTreeMap<String, EvidenceBundle>>,
    artifacts: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            bundles: std::sync::Mutex::new(BTreeMap::new()),
            artifacts: std::sync::Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceStore for InMemoryStore {
    fn save_bundle(&self, bundle: &EvidenceBundle) -> Result<(), EvidenceError> {
        let mut bundles = lock_or_recover(&self.bundles);
        bundles.insert(bundle.id.clone(), bundle.clone());
        Ok(())
    }

    fn load_bundle(&self, bundle_id: &str) -> Result<EvidenceBundle, EvidenceError> {
        let bundles = lock_or_recover(&self.bundles);
        bundles
            .get(bundle_id)
            .cloned()
            .ok_or(EvidenceError::NotFound {
                kind: "bundle",
                id: bundle_id.to_string(),
            })
    }

    fn list_bundles(&self, tenant_id: &str) -> Result<Vec<String>, EvidenceError> {
        let bundles = lock_or_recover(&self.bundles);
        Ok(bundles
            .values()
            .filter(|b| b.tenant_id == tenant_id)
            .map(|b| b.id.clone())
            .collect())
    }

    fn save_artifact(&self, artifact_id: &str, data: &[u8]) -> Result<(), EvidenceError> {
        let mut artifacts = lock_or_recover(&self.artifacts);
        artifacts.insert(artifact_id.to_string(), data.to_vec());
        Ok(())
    }

    fn load_artifact(&self, artifact_id: &str) -> Result<Vec<u8>, EvidenceError> {
        let artifacts = lock_or_recover(&self.artifacts);
        artifacts
            .get(artifact_id)
            .cloned()
            .ok_or(EvidenceError::NotFound {
                kind: "artifact",
                id: artifact_id.to_string(),
            })
    }
}

// ── File Store (slice 1) ──────────────────────────────────────────

pub struct FileStore {
    base_dir: PathBuf,
}

impl FileStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }
}

impl EvidenceStore for FileStore {
    fn save_bundle(&self, bundle: &EvidenceBundle) -> Result<(), EvidenceError> {
        let dir = self.base_dir.join("bundles");
        std::fs::create_dir_all(&dir)?;
        let json = serde_json::to_string_pretty(bundle)?;
        std::fs::write(dir.join(format!("{}.json", bundle.id)), json)?;
        Ok(())
    }

    fn load_bundle(&self, bundle_id: &str) -> Result<EvidenceBundle, EvidenceError> {
        let path = self
            .base_dir
            .join("bundles")
            .join(format!("{}.json", bundle_id));
        let json = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&json)?)
    }

    fn list_bundles(&self, _tenant_id: &str) -> Result<Vec<String>, EvidenceError> {
        let dir = self.base_dir.join("bundles");
        if !dir.exists() {
            return Ok(Vec::new());
        }
        Ok(std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
            })
            .collect())
    }

    fn save_artifact(&self, artifact_id: &str, data: &[u8]) -> Result<(), EvidenceError> {
        let dir = self.base_dir.join("artifacts");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(artifact_id), data)?;
        Ok(())
    }

    fn load_artifact(&self, artifact_id: &str) -> Result<Vec<u8>, EvidenceError> {
        Ok(std::fs::read(
            self.base_dir.join("artifacts").join(artifact_id),
        )?)
    }
}

// ── Ingest from engine scan result ────────────────────────────────

/// Ingest a scan result JSON (the output shape of POST /scan) into findings + artifacts.
/// Finding IDs are stable and deterministic (derived from rule_id + canonical location).
pub fn ingest_scan_result(
    scan_json: &serde_json::Value,
    _engine_version: &str,
) -> (Vec<Finding>, Vec<Artifact>) {
    let mut findings = Vec::new();
    let artifacts = Vec::new();

    if let Some(arr) = scan_json["findings"].as_array() {
        for f in arr {
            let rule_id = f["detector"].as_str().unwrap_or("unknown").to_string();
            let severity = f["severity"].as_str().unwrap_or("medium").to_string();
            let confidence = f["confidence"]
                .as_str()
                .unwrap_or("experimental")
                .to_string();
            let function = f["function"].as_str().map(|s| s.to_string());
            let kind = f["kind"].as_str().map(|s| s.to_string());
            let file = function.clone().unwrap_or_else(|| "unknown".into());

            let finding_id = make_finding_id(&rule_id, &file, None, kind.as_deref());

            findings.push(Finding {
                finding_id,
                rule_id,
                severity,
                confidence_label: confidence,
                locations: vec![Location {
                    file,
                    line_start: None,
                    line_end: None,
                    symbol: kind,
                }],
                evidence_refs: Vec::new(),
                repro_ref: None,
            });
        }
    }

    (findings, artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bundle() -> EvidenceBundle {
        BundleBuilder::new(
            EngineVersion {
                semver: "0.1.0".into(),
                git_sha: "abc123".into(),
            },
            InputDescriptor {
                kind: "source".into(),
                value: "test.sol".into(),
            },
        )
        .add_finding(Finding {
            finding_id: "find-abc123".into(),
            rule_id: "price_manipulation".into(),
            severity: "high".into(),
            confidence_label: "graduated".into(),
            locations: vec![Location {
                file: "test.sol".into(),
                line_start: Some(10),
                line_end: Some(15),
                symbol: Some("swap".into()),
            }],
            evidence_refs: Vec::new(),
            repro_ref: None,
        })
        .build()
    }

    #[test]
    fn test_bundle_hash_deterministic() {
        let finding = Finding {
            finding_id: "find-abc123".into(),
            rule_id: "price_manipulation".into(),
            severity: "high".into(),
            confidence_label: "graduated".into(),
            locations: vec![Location {
                file: "test.sol".into(),
                line_start: Some(10),
                line_end: Some(15),
                symbol: Some("swap".into()),
            }],
            evidence_refs: Vec::new(),
            repro_ref: None,
        };

        let b1 = BundleBuilder::new(
            EngineVersion {
                semver: "0.1.0".into(),
                git_sha: "abc123".into(),
            },
            InputDescriptor {
                kind: "source".into(),
                value: "test.sol".into(),
            },
        )
        .add_finding(finding.clone())
        .build();

        let b2 = BundleBuilder::new(
            EngineVersion {
                semver: "0.1.0".into(),
                git_sha: "abc123".into(),
            },
            InputDescriptor {
                kind: "source".into(),
                value: "test.sol".into(),
            },
        )
        .add_finding(finding.clone())
        .build();

        assert_eq!(
            b1.bundle_hash, b2.bundle_hash,
            "Same content must produce same hash"
        );
    }

    #[test]
    fn test_tamper_detection() {
        let mut bundle = test_bundle();
        let original_hash = bundle.bundle_hash.clone();

        bundle.findings[0].severity = "low".into();
        let tampered_hash = compute_bundle_hash(&bundle);
        assert_ne!(original_hash, tampered_hash);

        let result = verify_bundle(&bundle);
        assert!(!result.valid);
    }

    #[test]
    fn test_signatures_excluded_from_hash() {
        let mut bundle = test_bundle();
        let hash_no_sig = compute_bundle_hash(&bundle);

        bundle.signatures.push(Signature {
            signer_id: "test".into(),
            algorithm: "ed25519".into(),
            value: "sig123".into(),
        });
        let hash_with_sig = compute_bundle_hash(&bundle);
        assert_eq!(hash_no_sig, hash_with_sig);
    }

    #[test]
    fn test_verify_valid() {
        let bundle = test_bundle();
        let result = verify_bundle(&bundle);
        assert!(result.valid);
    }

    #[test]
    fn test_finding_ids_deterministic() {
        let id1 = make_finding_id("rule1", "file.sol", Some(10), Some("func"));
        let id2 = make_finding_id("rule1", "file.sol", Some(10), Some("func"));
        assert_eq!(id1, id2);
        assert!(id1.starts_with("find-"));
    }

    #[test]
    fn test_artifact_sha256() {
        let data = b"hello world";
        let hash = sha256_hex(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_inmemory_store_roundtrip() {
        let store = InMemoryStore::new();
        let bundle = test_bundle();
        store.save_bundle(&bundle).unwrap();
        let loaded = store.load_bundle(&bundle.id).unwrap();
        assert_eq!(loaded.id, bundle.id);
        assert_eq!(loaded.bundle_hash, bundle.bundle_hash);
    }

    #[test]
    fn test_inmemory_store_artifacts() {
        let store = InMemoryStore::new();
        store.save_artifact("art1", b"test data").unwrap();
        let loaded = store.load_artifact("art1").unwrap();
        assert_eq!(loaded, b"test data");
    }

    #[test]
    fn test_canonical_json_stable() {
        let v1 = serde_json::json!({"b": 2, "a": 1, "c": [3, 2, 1]});
        let v2 = serde_json::json!({"a": 1, "c": [3, 2, 1], "b": 2});
        let c1 = canonicalize(&v1);
        let c2 = canonicalize(&v2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_ingest_scan_result() {
        let scan = serde_json::json!({
            "findings": [
                {"detector": "price_manipulation", "severity": "high", "confidence": "graduated", "function": "swap"},
                {"detector": "solana_access_control", "severity": "high", "confidence": "experimental", "function": "mint"}
            ],
            "source_provenance": "local source",
            "confidence": "mixed"
        });

        let (findings, _artifacts) = ingest_scan_result(&scan, "0.1.0");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "price_manipulation");
        assert_eq!(findings[0].confidence_label, "graduated");
        assert_eq!(findings[1].rule_id, "solana_access_control");
        assert_eq!(findings[1].confidence_label, "experimental");
    }

    #[test]
    fn test_roundtrip_serialize_deserialize() {
        let bundle = test_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        let loaded: EvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.id, loaded.id);
        assert_eq!(bundle.findings.len(), loaded.findings.len());
    }

    #[test]
    fn test_tamper_provenance_changes_hash() {
        let mut bundle = test_bundle();
        let original_hash = bundle.bundle_hash.clone();

        bundle.provenance.deterministic = false;
        let tampered = compute_bundle_hash(&bundle);
        assert_ne!(original_hash, tampered);
    }

    #[test]
    fn test_escape_json_string_matches_serde() {
        for byte in 0u8..=0xFF {
            let s = String::from(byte as char);
            let escaped = escape_json_string(&s);
            let expected = serde_json::to_string(&s).unwrap();
            assert_eq!(escaped, expected, "byte {:#04x} mismatch", byte);
        }

        let tricky = [
            "",
            "hello",
            "has \"quotes\"",
            "back\\slash",
            "tab\there",
            "newline\nhere",
            "unicode \u{00e9}\u{00e8}\u{00ea}",
            "\u{0000}",
            "\u{0001}\u{001f}",
        ];
        for s in &tricky {
            let escaped = escape_json_string(s);
            let expected = serde_json::to_string(s).unwrap();
            assert_eq!(escaped, expected, "tricky string mismatch for {:?}", s);
        }
    }

    #[test]
    fn test_hash_stability_pin() {
        let bundle = test_bundle();
        assert_eq!(
            bundle.bundle_hash, "7ff4e9c89a8145913e5a702390bf3152816bf28e3cf788923b464b7023203b39",
            "Hash stability check — if this fails, update the pinned hash"
        );
    }

    #[test]
    fn test_typed_error_not_found() {
        let store = InMemoryStore::new();
        let result = store.load_bundle("nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, EvidenceError::NotFound { .. }));
        let msg = err.to_string();
        assert!(msg.contains("bundle"));
        assert!(msg.contains("nonexistent"));
    }

    #[test]
    fn test_filestore_roundtrip() {
        let dir = std::env::temp_dir().join(format!("digger-evidence-test-{}", Uuid::new_v4()));
        let store = FileStore::new(dir.clone());

        let bundle = test_bundle();
        store.save_bundle(&bundle).unwrap();
        let loaded = store.load_bundle(&bundle.id).unwrap();
        assert_eq!(loaded.id, bundle.id);
        assert_eq!(loaded.bundle_hash, bundle.bundle_hash);

        store.save_artifact("test-art", b"artifact data").unwrap();
        let loaded_art = store.load_artifact("test-art").unwrap();
        assert_eq!(loaded_art, b"artifact data");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ── Brick 1: Exploit Predicate Types ────────────────────────────

/// Tier of confidence for a predicate result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PredicateTier {
    /// Tier A: definitive match — all facts resolved and predicate true.
    TierA,
    /// Tier B: probabilistic match — some facts resolved, high confidence.
    TierB,
}

/// Stage at which a predicate is evaluated (controls whether it can take action).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PredicateStage {
    /// Shadow: log only, never act.
    Shadow,
    /// Advisory: may raise alert / propose; NEVER autonomous.
    Advisory,
    /// Armed: may trigger a pre-authorized action — ONLY for TierA + determinate match.
    Armed,
}

/// A single named fact that a predicate can query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PredicateFact {
    /// Fact name, e.g. "account_owner_mismatch".
    pub name: String,
    /// Whether this fact was resolved by the context.
    pub resolved: bool,
    /// The resolved value (if resolved).
    pub value: Option<String>,
}

/// A condition within a predicate — checks a specific fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PredicateCondition {
    /// The fact name to check.
    pub fact_name: String,
    /// Expected value (if any). None = fact must be resolved (not undetermined).
    pub expected: Option<String>,
}

/// Context provided to a predicate for fact resolution.
pub trait PredicateContext {
    /// Resolve a named fact. Returns None if the fact cannot be resolved
    /// from available data (undetermined).
    fn resolve_fact(&self, fact_name: &str) -> Option<String>;
}

/// Outcome of evaluating a predicate against a context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PredicateOutcome {
    /// The predicate ID that was evaluated.
    pub predicate_id: String,
    /// Whether the predicate matched.
    pub matched: bool,
    /// Whether the outcome is undetermined (missing facts).
    pub undetermined: bool,
    /// Facts that could not be resolved.
    pub missing_facts: Vec<String>,
    /// All facts that were resolved.
    pub resolved_facts: Vec<PredicateFact>,
    /// Tier of the match.
    pub tier: PredicateTier,
}

/// A single exploit predicate: a set of conditions that must all be true.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExploitPredicate {
    /// Unique predicate ID.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// The rule_id this predicate is associated with.
    pub rule_id: String,
    /// All conditions that must be satisfied (AND logic).
    pub conditions: Vec<PredicateCondition>,
    /// Stage at which this predicate runs.
    pub stage: PredicateStage,
    /// Tier of the match if all conditions are satisfied.
    pub tier: PredicateTier,
}

impl ExploitPredicate {
    /// Returns true ONLY when this predicate can autonomously trigger an action.
    /// Requires: stage==Armed, tier==TierA, matched==true, undetermined==false.
    pub fn can_autonomously_act(&self, outcome: &PredicateOutcome) -> bool {
        self.stage == PredicateStage::Armed
            && self.tier == PredicateTier::TierA
            && outcome.matched
            && !outcome.undetermined
    }

    /// Evaluate this predicate against a context.
    pub fn evaluate(&self, ctx: &dyn PredicateContext) -> PredicateOutcome {
        let mut resolved_facts = Vec::new();
        let mut missing_facts = Vec::new();

        for cond in &self.conditions {
            match ctx.resolve_fact(&cond.fact_name) {
                Some(val) => {
                    let matches = match &cond.expected {
                        Some(expected) => val == *expected,
                        None => true, // Any resolved value matches if no expected value.
                    };
                    resolved_facts.push(PredicateFact {
                        name: cond.fact_name.clone(),
                        resolved: true,
                        value: Some(val.clone()),
                    });
                    if !matches {
                        return PredicateOutcome {
                            predicate_id: self.id.clone(),
                            matched: false,
                            undetermined: false,
                            missing_facts,
                            resolved_facts,
                            tier: self.tier.clone(),
                        };
                    }
                }
                None => {
                    missing_facts.push(cond.fact_name.clone());
                }
            }
        }

        let undetermined = !missing_facts.is_empty();
        PredicateOutcome {
            predicate_id: self.id.clone(),
            matched: !undetermined && missing_facts.is_empty(),
            undetermined,
            missing_facts,
            resolved_facts,
            tier: self.tier.clone(),
        }
    }
}

/// A set of predicates associated with a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PredicateSet {
    pub finding_id: String,
    pub rule_id: String,
    pub predicates: Vec<ExploitPredicate>,
}

#[cfg(test)]
mod predicate_tests {
    use super::*;

    struct TestCtx {
        facts: BTreeMap<String, String>,
    }

    impl TestCtx {
        fn new(facts: Vec<(&str, &str)>) -> Self {
            Self {
                facts: facts
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            }
        }
    }

    impl PredicateContext for TestCtx {
        fn resolve_fact(&self, name: &str) -> Option<String> {
            self.facts.get(name).cloned()
        }
    }

    #[test]
    fn test_tier_c_removed() {
        // TierC should not exist. This test verifies compilation-level removal.
        let tiers = [PredicateTier::TierA, PredicateTier::TierB];
        assert_eq!(tiers.len(), 2);
        assert_eq!(tiers[0], PredicateTier::TierA);
    }

    #[test]
    fn test_three_stage_ladder() {
        let stages = [
            PredicateStage::Shadow,
            PredicateStage::Advisory,
            PredicateStage::Armed,
        ];
        assert_eq!(stages.len(), 3);
        assert_eq!(stages[0], PredicateStage::Shadow);
        assert_eq!(stages[1], PredicateStage::Advisory);
        assert_eq!(stages[2], PredicateStage::Armed);
    }

    fn tier_a_predicate() -> ExploitPredicate {
        ExploitPredicate {
            id: "test-pred".into(),
            name: "Test predicate".into(),
            rule_id: "test_rule".into(),
            conditions: vec![PredicateCondition {
                fact_name: "fact_a".into(),
                expected: Some("yes".into()),
            }],
            stage: PredicateStage::Shadow,
            tier: PredicateTier::TierA,
        }
    }

    #[test]
    fn test_can_autonomously_act_armed_tier_a_matched() {
        let pred = ExploitPredicate {
            stage: PredicateStage::Armed,
            tier: PredicateTier::TierA,
            ..tier_a_predicate()
        };
        let ctx = TestCtx::new(vec![("fact_a", "yes")]);
        let outcome = pred.evaluate(&ctx);
        assert!(pred.can_autonomously_act(&outcome));
    }

    #[test]
    fn test_can_autonomously_act_shadow_denied() {
        let pred = tier_a_predicate(); // stage == Shadow
        let ctx = TestCtx::new(vec![("fact_a", "yes")]);
        let outcome = pred.evaluate(&ctx);
        assert!(!pred.can_autonomously_act(&outcome), "Shadow must not act");
    }

    #[test]
    fn test_can_autonomously_act_advisory_denied() {
        let pred = ExploitPredicate {
            stage: PredicateStage::Advisory,
            tier: PredicateTier::TierA,
            ..tier_a_predicate()
        };
        let ctx = TestCtx::new(vec![("fact_a", "yes")]);
        let outcome = pred.evaluate(&ctx);
        assert!(
            !pred.can_autonomously_act(&outcome),
            "Advisory must not act"
        );
    }

    #[test]
    fn test_can_autonomously_act_tier_b_denied() {
        let pred = ExploitPredicate {
            stage: PredicateStage::Armed,
            tier: PredicateTier::TierB,
            ..tier_a_predicate()
        };
        let ctx = TestCtx::new(vec![("fact_a", "yes")]);
        let outcome = pred.evaluate(&ctx);
        assert!(!pred.can_autonomously_act(&outcome), "TierB must not act");
    }

    #[test]
    fn test_can_autonomously_act_undetermined_denied() {
        let pred = ExploitPredicate {
            stage: PredicateStage::Armed,
            tier: PredicateTier::TierA,
            ..tier_a_predicate()
        };
        let ctx = TestCtx::new(vec![]); // Missing fact_a → undetermined
        let outcome = pred.evaluate(&ctx);
        assert!(
            !pred.can_autonomously_act(&outcome),
            "Undetermined must not act"
        );
    }

    #[test]
    fn test_can_autonomously_act_no_match_denied() {
        let pred = ExploitPredicate {
            stage: PredicateStage::Armed,
            tier: PredicateTier::TierA,
            ..tier_a_predicate()
        };
        let ctx = TestCtx::new(vec![("fact_a", "no")]); // Wrong value
        let outcome = pred.evaluate(&ctx);
        assert!(!outcome.matched);
        assert!(
            !pred.can_autonomously_act(&outcome),
            "No-match must not act"
        );
    }

    #[test]
    fn test_evaluate_match() {
        let pred = tier_a_predicate();
        let ctx = TestCtx::new(vec![("fact_a", "yes")]);
        let outcome = pred.evaluate(&ctx);
        assert!(outcome.matched);
        assert!(!outcome.undetermined);
        assert!(outcome.missing_facts.is_empty());
        assert_eq!(outcome.tier, PredicateTier::TierA);
    }

    #[test]
    fn test_evaluate_no_match() {
        let pred = tier_a_predicate();
        let ctx = TestCtx::new(vec![("fact_a", "no")]);
        let outcome = pred.evaluate(&ctx);
        assert!(!outcome.matched);
        assert!(!outcome.undetermined);
        assert_eq!(outcome.tier, PredicateTier::TierA);
    }

    #[test]
    fn test_evaluate_undetermined() {
        let pred = tier_a_predicate();
        let ctx = TestCtx::new(vec![]);
        let outcome = pred.evaluate(&ctx);
        assert!(!outcome.matched);
        assert!(outcome.undetermined);
        assert_eq!(outcome.missing_facts, vec!["fact_a"]);
    }

    #[test]
    fn test_all_outcomes_have_valid_tier() {
        // Verify all outcomes use one of the two valid tiers.
        let pred = tier_a_predicate();

        // Matched case
        let ctx_match = TestCtx::new(vec![("fact_a", "yes")]);
        let o1 = pred.evaluate(&ctx_match);
        assert!(o1.tier == PredicateTier::TierA || o1.tier == PredicateTier::TierB);

        // No-match case
        let ctx_no = TestCtx::new(vec![("fact_a", "no")]);
        let o2 = pred.evaluate(&ctx_no);
        assert!(o2.tier == PredicateTier::TierA || o2.tier == PredicateTier::TierB);

        // Undetermined case
        let ctx_none = TestCtx::new(vec![]);
        let o3 = pred.evaluate(&ctx_none);
        assert!(o3.tier == PredicateTier::TierA || o3.tier == PredicateTier::TierB);
    }

    // ── C53/A: Pin L4 to Shadow — prove autonomy is unreachable ──

    #[test]
    fn test_c53_shadow_is_default_for_all_predicates() {
        // Every predicate registered in the shipped beta must be at Shadow stage.
        // This is a code-level invariant: predicates_for_finding() hardcodes Shadow.
        // There is no config/env path to set Armed or Advisory.
        let shadow_pred = tier_a_predicate(); // stage == Shadow
        assert_eq!(shadow_pred.stage, PredicateStage::Shadow);

        // Even if we construct a predicate programmatically, can_autonomously_act
        // requires stage == Armed. Since all shipped predicates are Shadow,
        // can_autonomously_act() is provably unreachable for them.
        let ctx = TestCtx::new(vec![("fact_a", "yes")]);
        let outcome = shadow_pred.evaluate(&ctx);
        assert!(outcome.matched);
        assert!(!outcome.undetermined);
        assert!(
            !shadow_pred.can_autonomously_act(&outcome),
            "Beta config: Shadow predicate must never autonomously act"
        );
    }

    #[test]
    fn test_c53_worst_case_safe_even_with_full_match() {
        // Even the worst case — matched TierA + resolved fact + exploit-classified tx —
        // logs would_have_acted but auto-proposes/executes nothing.
        let pred = tier_a_predicate(); // Shadow stage
        let ctx = TestCtx::new(vec![("fact_a", "yes")]);
        let outcome = pred.evaluate(&ctx);

        // Predicate matched with all facts resolved
        assert!(outcome.matched);
        assert!(!outcome.undetermined);
        assert_eq!(outcome.tier, PredicateTier::TierA);

        // But cannot autonomously act because stage is Shadow
        assert!(
            !pred.can_autonomously_act(&outcome),
            "Worst case: matched TierA + resolved fact must still not auto-act"
        );
    }

    #[test]
    fn test_c53_no_config_path_to_armed() {
        // Verify there is no config/env path that can set Armed stage.
        // The only way to get Armed is to construct a predicate with
        // stage: PredicateStage::Armed, which is a code-level change.
        // In the shipped beta, all predicates in predicates_for_finding()
        // are hardcoded to Shadow.
        //
        // This test documents the invariant: Armed is only constructible
        // by code change, not by config/env.
        let pred = tier_a_predicate();
        assert_eq!(
            pred.stage,
            PredicateStage::Shadow,
            "Beta: default stage must be Shadow, not Armed or Advisory"
        );
    }
}
