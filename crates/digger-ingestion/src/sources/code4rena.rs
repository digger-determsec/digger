/// Code4rena source fetcher and normalizer.
///
/// Code4rena repos are structured as individual contest repos:
/// - Repo name: `YYYY-MM-protocol-name` or `YYYY-MM-protocol-name-findings`
/// - Root contains: report.md, individual auditor directories
/// - Each auditor directory contains: submission.md
use crate::fetcher;
use crate::IngestionError;
use digger_knowledge::code4rena;
use digger_knowledge::normalizer;
use digger_knowledge_models::NormalizedKnowledge;

/// Ingest Code4rena findings from a specific contest repo.
pub fn ingest(owner: &str, repo: &str) -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    let result = fetcher::fetch_github_repo(owner, repo, ".")?;

    let mut items = Vec::new();

    // Try report.md first
    if let Some(content) = result.items.get("report.md") {
        if let Ok(report) = code4rena::parse_code4rena_report(content, "report.md") {
            let knowledge = normalizer::normalize_report(&report);
            items.push(knowledge);
        }
    }

    // Also try individual auditor submissions
    for (name, content) in &result.items {
        if name.ends_with("-submission.md") || name.ends_with(".md") {
            if name == "report.md" {
                continue; // Already processed
            }
            if let Ok(report) = code4rena::parse_code4rena_report(content, name) {
                let knowledge = normalizer::normalize_report(&report);
                items.push(knowledge);
            }
        }
    }

    Ok(items)
}

/// List available Code4rena contest repos.
pub fn list_contests() -> Result<Vec<String>, IngestionError> {
    let output = std::process::Command::new("gh")
        .args([
            "api",
            "orgs/code-423n4/repos",
            "--paginate",
            "--jq",
            ".[].name",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(IngestionError::Process(format!("gh api error: {}", stderr)));
    }

    let names_str = String::from_utf8_lossy(&output.stdout);
    let contests: Vec<String> = names_str
        .lines()
        .filter(|name| name.contains("-findings") || name.contains("202"))
        .map(String::from)
        .collect();

    Ok(contests)
}
