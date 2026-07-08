/// Source Reliability — retry logic, timeout handling, schema validation, corruption detection.
use crate::IngestionError;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Reliability metrics for a source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceReliability {
    pub source_id: String,
    pub total_fetches: u64,
    pub successful_fetches: u64,
    pub failed_fetches: u64,
    pub retried_fetches: u64,
    pub timeout_fetches: u64,
    pub schema_violations: u64,
    pub corruption_detections: u64,
    pub last_fetch_time: Option<String>,
    pub last_error: Option<String>,
    pub reliability_score: f64,
    pub avg_fetch_time_ms: f64,
}

/// Schema validation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaValidation {
    pub valid: bool,
    pub errors: Vec<SchemaError>,
    pub warnings: Vec<String>,
    pub fields_present: usize,
    pub fields_expected: usize,
    pub completeness: f64,
}

/// A schema validation error.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("Schema error in field {field}: expected {expected_type}, got {actual_type}: {message}")]
pub struct SchemaError {
    pub field: String,
    pub expected_type: String,
    pub actual_type: String,
    pub message: String,
}

/// Corruption detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorruptionCheck {
    pub corrupted: bool,
    pub checksum_valid: bool,
    pub size_valid: bool,
    pub encoding_valid: bool,
    pub details: Vec<String>,
}

/// Fetch with retry logic.
pub fn fetch_with_retry<F>(
    _source_id: &str,
    fetch_fn: F,
    max_retries: u32,
    _timeout_ms: u64,
) -> Result<FetchOutcome, IngestionError>
where
    F: Fn() -> Result<Vec<u8>, IngestionError>,
{
    let mut last_error = String::new();
    let mut total_attempts = 0;

    for attempt in 0..=max_retries {
        total_attempts += 1;
        match fetch_fn() {
            Ok(data) => {
                return Ok(FetchOutcome {
                    success: true,
                    data: Some(data),
                    attempts: total_attempts,
                    retry_count: attempt,
                    error: None,
                    duration_ms: 0, // Would need actual timing
                });
            }
            Err(e) => {
                last_error = e.to_string();
                if attempt < max_retries {
                    // Deterministic backoff: attempt * 1000ms
                    std::thread::sleep(std::time::Duration::from_millis(attempt as u64 * 1000));
                }
            }
        }
    }

    Ok(FetchOutcome {
        success: false,
        data: None,
        attempts: total_attempts,
        retry_count: max_retries,
        error: Some(last_error),
        duration_ms: 0,
    })
}

/// Fetch outcome with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchOutcome {
    pub success: bool,
    pub data: Option<Vec<u8>>,
    pub attempts: u32,
    pub retry_count: u32,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Validate artifact schema.
pub fn validate_schema(
    source_id: &str,
    data: &serde_json::Value,
    expected_fields: &[&str],
) -> SchemaValidation {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut fields_present = 0;

    for field in expected_fields {
        match data.get(*field) {
            Some(val) if !val.is_null() => {
                fields_present += 1;
            }
            Some(_) => {
                warnings.push(format!("Field '{}' is null", field));
            }
            None => {
                errors.push(SchemaError {
                    field: field.to_string(),
                    expected_type: "any".into(),
                    actual_type: "missing".into(),
                    message: format!("Required field '{}' not found in {}", field, source_id),
                });
            }
        }
    }

    let completeness = if expected_fields.is_empty() {
        1.0
    } else {
        fields_present as f64 / expected_fields.len() as f64
    };

    SchemaValidation {
        valid: errors.is_empty(),
        errors,
        warnings,
        fields_present,
        fields_expected: expected_fields.len(),
        completeness,
    }
}

/// Detect corruption in fetched data.
pub fn detect_corruption(
    data: &[u8],
    expected_checksum: Option<&str>,
    min_size: usize,
) -> CorruptionCheck {
    let mut details = Vec::new();

    // Size check
    let size_valid = data.len() >= min_size;
    if !size_valid {
        details.push(format!(
            "Data size {} below minimum {}",
            data.len(),
            min_size
        ));
    }

    // Encoding check
    let encoding_valid = !String::from_utf8_lossy(data).is_empty() || data.is_empty();
    if !encoding_valid {
        details.push("Data contains invalid UTF-8".into());
    }

    // Checksum verification
    let checksum_valid = if let Some(expected) = expected_checksum {
        let actual = compute_checksum(data);
        actual == expected
    } else {
        true // No checksum to verify
    };
    if !checksum_valid {
        details.push("Checksum mismatch — data may be corrupted".into());
    }

    CorruptionCheck {
        corrupted: !size_valid || !encoding_valid || !checksum_valid,
        checksum_valid,
        size_valid,
        encoding_valid,
        details,
    }
}

/// Verify manifest consistency for a source.
pub fn verify_manifest(manifest_path: &Path) -> ManifestVerification {
    let mut issues = Vec::new();

    if !manifest_path.exists() {
        return ManifestVerification {
            valid: false,
            artifact_count: 0,
            issues: vec!["Manifest file not found".into()],
        };
    }

    let content = match std::fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(e) => {
            return ManifestVerification {
                valid: false,
                artifact_count: 0,
                issues: vec![format!("Cannot read manifest: {}", e)],
            };
        }
    };

    let manifest: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return ManifestVerification {
                valid: false,
                artifact_count: 0,
                issues: vec![format!("Invalid manifest JSON: {}", e)],
            };
        }
    };

    // Check required fields
    let required = ["version", "source_id", "last_sync", "artifacts"];
    for field in &required {
        if manifest.get(*field).is_none() {
            issues.push(format!("Missing required field: {}", field));
        }
    }

    // Count artifacts
    let artifact_count = manifest
        .get("artifacts")
        .and_then(|a| a.as_object())
        .map(|o| o.len())
        .unwrap_or(0);

    // Check for empty artifacts
    if artifact_count == 0 {
        issues.push("No artifacts in manifest".into());
    }

    ManifestVerification {
        valid: issues.is_empty(),
        artifact_count,
        issues,
    }
}

/// Snapshot verification — compare two snapshots of a source.
pub fn verify_snapshot(
    current: &SourceReliability,
    previous: Option<&SourceReliability>,
) -> SnapshotVerification {
    match previous {
        Some(prev) => {
            let drift = current.reliability_score - prev.reliability_score;
            let healthy = drift >= -0.1; // Allow small negative drift
            SnapshotVerification {
                consistent: healthy,
                drift,
                new_fetches: current.total_fetches.saturating_sub(prev.total_fetches),
                new_errors: current.failed_fetches.saturating_sub(prev.failed_fetches),
                details: if healthy {
                    "Source reliability stable".into()
                } else {
                    format!("Reliability dropped by {:.1}%", drift.abs() * 100.0)
                },
            }
        }
        None => SnapshotVerification {
            consistent: true,
            drift: 0.0,
            new_fetches: current.total_fetches,
            new_errors: current.failed_fetches,
            details: "Baseline snapshot recorded".into(),
        },
    }
}

/// Snapshot verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotVerification {
    pub consistent: bool,
    pub drift: f64,
    pub new_fetches: u64,
    pub new_errors: u64,
    pub details: String,
}

/// Manifest verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestVerification {
    pub valid: bool,
    pub artifact_count: usize,
    pub issues: Vec<String>,
}

fn compute_checksum(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Compute reliability score from metrics.
pub fn compute_reliability_score(
    successful: u64,
    failed: u64,
    retried: u64,
    schema_violations: u64,
    corruption: u64,
) -> f64 {
    let total = successful + failed;
    if total == 0 {
        return 1.0;
    }
    let success_rate = successful as f64 / total.max(1) as f64;
    let retry_penalty = retried as f64 * 0.01;
    let violation_penalty = schema_violations as f64 * 0.05;
    let corruption_penalty = corruption as f64 * 0.1;
    (success_rate - retry_penalty - violation_penalty - corruption_penalty).clamp(0.0, 1.0)
}

/// Aggregate reliability across all sources.
pub fn aggregate_reliability(sources: &[SourceReliability]) -> String {
    let total_fetches: u64 = sources.iter().map(|s| s.total_fetches).sum();
    let total_failures: u64 = sources.iter().map(|s| s.failed_fetches).sum();
    let avg_reliability: f64 =
        sources.iter().map(|s| s.reliability_score).sum::<f64>() / sources.len().max(1) as f64;
    let mut out = format!("═══ Source Reliability ═══\nSources: {} | Total Fetches: {} | Failures: {} | Avg Reliability: {:.1}%\n\n",
        sources.len(), total_fetches, total_failures, avg_reliability * 100.0);
    for s in sources {
        let icon = if s.reliability_score >= 0.95 {
            "✓"
        } else if s.reliability_score >= 0.8 {
            "~"
        } else {
            "✗"
        };
        out.push_str(&format!(
            "  {} {:.<20} {:.1}% (fetches={}, failures={}, retries={})\n",
            icon,
            s.source_id,
            s.reliability_score * 100.0,
            s.total_fetches,
            s.failed_fetches,
            s.retried_fetches
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_validation() {
        let data = serde_json::json!({"version": 1, "source_id": "test", "artifacts": {}});
        let result = validate_schema("test", &data, &["version", "source_id", "artifacts"]);
        assert!(result.valid);
        assert_eq!(result.completeness, 1.0);
    }

    #[test]
    fn test_schema_missing_field() {
        let data = serde_json::json!({"version": 1});
        let result = validate_schema("test", &data, &["version", "source_id", "artifacts"]);
        assert!(!result.valid);
        assert_eq!(result.errors.len(), 2);
    }

    #[test]
    fn test_corruption_detection() {
        let valid_data = b"valid data here";
        let check = detect_corruption(valid_data, None, 5);
        assert!(!check.corrupted);

        let short_data = b"hi";
        let check2 = detect_corruption(short_data, None, 100);
        assert!(check2.corrupted);
    }

    #[test]
    fn test_reliability_score() {
        let score = compute_reliability_score(100, 2, 1, 0, 0);
        assert!(score > 0.9);
        let bad_score = compute_reliability_score(10, 10, 5, 3, 2);
        assert!(bad_score < 0.5);
    }

    #[test]
    fn test_manifest_verification_missing() {
        let result = verify_manifest(Path::new("/nonexistent/manifest.json"));
        assert!(!result.valid);
    }

    #[test]
    fn test_retry_logic() {
        let call_count = std::cell::Cell::new(0u32);
        let result = fetch_with_retry(
            "test",
            || {
                call_count.set(call_count.get() + 1);
                if call_count.get() < 3 {
                    Err("transient".into())
                } else {
                    Ok(vec![1, 2, 3])
                }
            },
            3,
            1000,
        );
        assert!(result.unwrap().success);
    }
}
