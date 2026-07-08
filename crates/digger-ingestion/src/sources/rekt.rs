/// Rekt News source fetcher.
///
/// Rekt News publishes exploit postmortems at rekt.news but has no
/// public API or data archive. The RektHQ/Reports GitHub repo contains
/// only a single PDF report.
///
/// Coverage of Rekt-reported incidents is provided through:
/// - SlowMist CSV (overlapping exploit records)
/// - DeFiHackLabs (PoC reproductions of the same exploits)
///
/// This source is maintained as a stub for when/if a public archive
/// or API becomes available. It does not currently produce findings.
use crate::IngestionError;
use digger_knowledge_models::*;

/// Ingest Rekt News postmortems.
///
/// Returns empty — no public data source available.
/// See source code comments for coverage alternatives.
pub fn ingest() -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rekt_ingest_returns_empty() {
        let result = ingest().expect("rekt ingest should not error");
        assert!(result.is_empty());
    }
}
