/// Immunefi source fetcher.
///
/// Immunefi discloses vulnerabilities through their bug bounty platform.
/// Uses their public vulnerability disclosure data.
use crate::IngestionError;
use digger_knowledge_models::NormalizedKnowledge;

/// Ingest Immunefi disclosures from their public API.
pub fn ingest() -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    // Immunefi has a public API for disclosed vulnerabilities
    // https://immunefi.com/bounty/ for bounty data
    // For now, return empty — would fetch from Immunefi API in production
    // when they provide a public disclosure endpoint

    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_immunefi_ingest_returns_empty() {
        let result = ingest().expect("immunefi ingest should not error");
        assert!(result.is_empty());
    }
}
