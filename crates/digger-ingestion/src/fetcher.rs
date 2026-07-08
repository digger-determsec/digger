/// HTTP fetchers for security sources.
///
/// Uses `gh` CLI for authenticated GitHub API access (avoids rate limits).
/// All fetchers are deterministic: same URL → same content.
use crate::IngestionError;
use std::collections::BTreeMap;
use std::process::Command;

/// Fetch result for a single source.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// Source identifier.
    pub source_id: String,
    /// Fetched content (keyed by identifier).
    pub items: BTreeMap<String, String>,
    /// Number of items fetched.
    pub count: usize,
    /// Errors during fetch.
    pub errors: Vec<String>,
}

/// Fetch from a GitHub repository using gh CLI (authenticated).
pub fn fetch_github_repo(
    owner: &str,
    repo: &str,
    path: &str,
) -> Result<FetchResult, IngestionError> {
    let mut result = FetchResult {
        source_id: format!("{}/{}", owner, repo),
        items: BTreeMap::new(),
        count: 0,
        errors: vec![],
    };

    // Use git clone --depth 1 for bulk fetching (much faster than per-file API calls)
    let temp_dir = format!("/tmp/digger-ingest-{}", repo);
    let _ = std::fs::remove_dir_all(&temp_dir);

    let clone_url = format!("https://github.com/{}/{}.git", owner, repo);

    // Egress gate: authorize before spawning network subprocess
    if let Err(e) = digger_egress::authorize_global(&clone_url, "clone-git-repo") {
        return Err(IngestionError::Process(format!("egress denied: {e}")));
    }

    let clone_output = Command::new("git")
        .args(["clone", "--depth", "1", &clone_url, &temp_dir])
        .output()?;

    if !clone_output.status.success() {
        let stderr = String::from_utf8_lossy(&clone_output.stderr);
        return Err(IngestionError::Process(format!(
            "git clone error: {}",
            stderr
        )));
    }

    // Walk the cloned repo and collect all files
    let base_path = if path == "." {
        std::path::PathBuf::from(&temp_dir)
    } else {
        std::path::PathBuf::from(&temp_dir).join(path)
    };

    collect_files(&base_path, &base_path, &mut result)?;

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(result)
}

/// Recursively collect files from a local directory (after git clone).
fn collect_files(
    base: &std::path::Path,
    dir: &std::path::Path,
    result: &mut FetchResult,
) -> Result<(), IngestionError> {
    collect_files_depth(base, dir, result, 0, 50)
}

fn collect_files_depth(
    base: &std::path::Path,
    dir: &std::path::Path,
    result: &mut FetchResult,
    depth: usize,
    max_depth: usize,
) -> Result<(), IngestionError> {
    if depth > max_depth {
        return Ok(());
    }

    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_depth(base, &path, result, depth + 1, max_depth)?;
        } else if path.is_file() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.starts_with('.') {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&path) {
                let relative = path.strip_prefix(base).unwrap_or(&path);
                let key = relative.to_string_lossy().replace('\\', "/");
                result.items.insert(key, content);
                result.count += 1;
            }
        }
    }
    Ok(())
}

/// Fetch from DefiLlama hacks API.
pub fn fetch_defillama() -> Result<FetchResult, IngestionError> {
    let api_url = "https://api.llama.fi/hacks";

    // Egress gate: authorize before spawning network subprocess
    if let Err(e) = digger_egress::authorize_global(api_url, "github-api") {
        return Err(IngestionError::Process(format!("egress denied: {e}")));
    }

    let output = Command::new("gh")
        .args(["api", "https://api.llama.fi/hacks"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(IngestionError::Process(format!("gh api error: {}", stderr)));
    }

    let content = String::from_utf8_lossy(&output.stdout).to_string();

    let mut items = BTreeMap::new();
    items.insert("hacks.json".to_string(), content);

    Ok(FetchResult {
        source_id: "defillama".into(),
        items,
        count: 1,
        errors: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_result_structure() {
        let result = FetchResult {
            source_id: "test".into(),
            items: BTreeMap::new(),
            count: 0,
            errors: vec![],
        };
        assert_eq!(result.count, 0);
    }

    #[test]
    fn test_fetch_result_deterministic_json() {
        let mut items = BTreeMap::new();
        items.insert("z-file".to_string(), "content_z".to_string());
        items.insert("a-file".to_string(), "content_a".to_string());
        items.insert("m-file".to_string(), "content_m".to_string());

        let result = FetchResult {
            source_id: "test".into(),
            items,
            count: 3,
            errors: vec![],
        };

        let keys: Vec<&str> = result.items.keys().map(|s| s.as_str()).collect();
        assert_eq!(
            keys,
            vec!["a-file", "m-file", "z-file"],
            "BTreeMap keys must be sorted"
        );
        assert_eq!(result.count, 3);
    }
}
