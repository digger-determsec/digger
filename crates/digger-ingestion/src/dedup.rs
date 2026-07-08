/// Deduplication engine — prevents duplicate ingestion.
use std::collections::BTreeSet;

/// Deduplication result for a batch.
#[derive(Debug, Clone)]
pub struct DedupResult {
    /// Total items checked.
    pub total: usize,
    /// Items that are new (not duplicates).
    pub new_count: usize,
    /// Items that are duplicates.
    pub duplicate_count: usize,
    /// IDs of new items.
    pub new_ids: Vec<String>,
    /// IDs of duplicate items.
    pub duplicate_ids: Vec<String>,
}

/// Check for duplicates against existing corpus hashes.
///
/// Uses deterministic hash comparison.
pub fn dedup_findings(new_hashes: &[String], existing_hashes: &BTreeSet<String>) -> DedupResult {
    let mut new_ids = Vec::new();
    let mut duplicate_ids = Vec::new();

    for hash in new_hashes {
        if existing_hashes.contains(hash) {
            duplicate_ids.push(hash.clone());
        } else {
            new_ids.push(hash.clone());
        }
    }

    DedupResult {
        total: new_hashes.len(),
        new_count: new_ids.len(),
        duplicate_count: duplicate_ids.len(),
        new_ids,
        duplicate_ids,
    }
}

/// Compute deterministic hash for a finding.
pub fn compute_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_no_duplicates() {
        let new = vec!["a".into(), "b".into(), "c".into()];
        let existing = BTreeSet::new();
        let result = dedup_findings(&new, &existing);
        assert_eq!(result.new_count, 3);
        assert_eq!(result.duplicate_count, 0);
    }

    #[test]
    fn test_dedup_with_duplicates() {
        let new = vec!["a".into(), "b".into(), "c".into()];
        let mut existing = BTreeSet::new();
        existing.insert("a".into());
        let result = dedup_findings(&new, &existing);
        assert_eq!(result.new_count, 2);
        assert_eq!(result.duplicate_count, 1);
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = compute_hash("test content");
        let h2 = compute_hash("test content");
        assert_eq!(h1, h2);
    }
}
