/// Sherlock source fetcher and normalizer.
///
/// Sherlock repos are structured as individual contest repos:
/// - Repo name: `YYYY-MM-protocol-judging`
/// - Root contains: individual issue directories (002-M/, 004-H/, etc.)
/// - Each directory contains: issue files (.md) and report.md
use crate::fetcher;
use crate::IngestionError;
use digger_knowledge::normalizer;
use digger_knowledge::sherlock;
use digger_knowledge_models::NormalizedKnowledge;

/// Ingest Sherlock findings from a specific contest repo.
pub fn ingest(owner: &str, repo: &str) -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    let result = fetcher::fetch_github_repo(owner, repo, ".")?;

    let mut items = Vec::new();

    // Process all markdown files in the repo
    for (name, content) in &result.items {
        if name.ends_with(".md") {
            if let Ok(report) = sherlock::parse_sherlock_report(content, name) {
                let knowledge = normalizer::normalize_report(&report);
                items.push(knowledge);
            }
        }
    }

    Ok(items)
}
