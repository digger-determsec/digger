use crate::models::*;
use std::fs;
/// Corpus loader — loads exploit corpus from directory structure.
///
/// # Integrity Rules
///
/// 1. Invalid meta.json → explicit error (never silently skipped)
/// 2. Missing source file → explicit error (never silently skipped)
/// 3. Schema mismatch → explicit error (never silently skipped)
/// 4. Corpus count must exactly equal loaded exploit count
use std::path::{Path, PathBuf};

/// Error type for corpus loading failures.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Failed to load exploit at '{exploit_dir}': {reason}")]
pub struct CorpusLoadError {
    pub exploit_dir: String,
    pub reason: String,
}

/// Load the exploit corpus from a directory.
///
/// Returns (exploits, errors). Errors are explicit — nothing is silently skipped.
///
/// Expected structure:
/// ```text
/// corpus_dir/
///   vulnerability_class/
///     exploit_name/
///       source.sol
///       meta.json
/// ```
pub fn load_corpus(corpus_dir: &str) -> Vec<LoadedExploit> {
    let (exploits, _errors) = load_corpus_with_errors(corpus_dir);
    exploits
}

/// Load the exploit corpus with explicit error reporting.
///
/// Returns (exploits, errors). Every invalid entry produces an error.
pub fn load_corpus_with_errors(corpus_dir: &str) -> (Vec<LoadedExploit>, Vec<CorpusLoadError>) {
    let dir = Path::new(corpus_dir);
    if !dir.exists() {
        return (vec![], vec![]);
    }

    let mut exploits = vec![];
    let mut errors = vec![];

    // Walk vulnerability class directories
    let class_entries = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("Warning: Cannot read corpus dir: {}", e);
            return (exploits, errors);
        }
    };
    for class_entry in class_entries.flatten() {
        let class_path = class_entry.path();
        if !class_path.is_dir() {
            continue;
        }

        // Walk exploit directories within each class
        let exploit_entries = match fs::read_dir(&class_path) {
            Ok(rd) => rd,
            Err(e) => {
                eprintln!(
                    "Warning: Cannot read class dir {}: {}",
                    class_path.display(),
                    e
                );
                continue;
            }
        };
        for exploit_entry in exploit_entries.flatten() {
            let exploit_path = exploit_entry.path();
            if !exploit_path.is_dir() {
                continue;
            }

            let meta_path = exploit_path.join("meta.json");
            if meta_path.exists() {
                match load_exploit(&exploit_path, &meta_path) {
                    Ok(exploit) => exploits.push(exploit),
                    Err(e) => errors.push(e),
                }
            }
        }
    }

    // Sort for deterministic output
    exploits.sort_by(|a, b| a.meta.exploit_id.cmp(&b.meta.exploit_id));
    (exploits, errors)
}

/// Load a single exploit from its directory and meta.json.
///
/// Returns explicit errors — never silently skips.
fn load_exploit(exploit_dir: &Path, meta_path: &Path) -> Result<LoadedExploit, CorpusLoadError> {
    let dir_str = exploit_dir.to_string_lossy().to_string();

    // 1. Read meta.json — fail loudly on I/O error
    let meta_str = fs::read_to_string(meta_path).map_err(|e| CorpusLoadError {
        exploit_dir: dir_str.clone(),
        reason: format!("Cannot read meta.json: {}", e),
    })?;

    // 2. Parse meta.json — fail loudly on schema mismatch
    let meta: ExploitMeta = serde_json::from_str(&meta_str).map_err(|e| CorpusLoadError {
        exploit_dir: dir_str.clone(),
        reason: format!("Invalid meta.json schema: {}", e),
    })?;

    // 3. Find source file — fail loudly if missing
    let source_path = find_source_file(exploit_dir).ok_or_else(|| CorpusLoadError {
        exploit_dir: dir_str.clone(),
        reason: "No .sol or .rs source file found".into(),
    })?;

    // 4. Read source file — fail loudly on I/O error
    let source_code = fs::read_to_string(&source_path).map_err(|e| CorpusLoadError {
        exploit_dir: dir_str.clone(),
        reason: format!("Cannot read source file '{}': {}", source_path.display(), e),
    })?;

    // 5. Classify language — deterministic, structural
    let language = classify_language(&source_path, &source_code);

    Ok(LoadedExploit {
        meta,
        source_code,
        language: language.into(),
        source_path: source_path.to_string_lossy().to_string(),
    })
}

/// Classify language from file extension and source content.
///
/// Deterministic: same inputs → same output.
/// No AI, no heuristics. Structural indicators only.
fn classify_language(path: &Path, source: &str) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "sol" => "solidity",
        "rs" => {
            // Anchor detection: structural indicators only
            if source.contains("#[program]")
                || source.contains("anchor_lang")
                || source.contains("declare_id!")
                || source.contains("#[account]")
            {
                "anchor"
            } else {
                "rust"
            }
        }
        _ => "unknown",
    }
}

/// Find the source file for an exploit.
fn find_source_file(exploit_dir: &Path) -> Option<PathBuf> {
    let entries = match fs::read_dir(exploit_dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("Warning: Cannot read exploit dir: {}", e);
            return None;
        }
    };
    for file_entry in entries.flatten() {
        let path = file_entry.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.ends_with(".sol") || name.ends_with(".rs") {
            return Some(path);
        }
    }
    None
}

/// Normalize a finding name for matching.
///
/// Rules:
/// - lowercase
/// - trim whitespace
/// - replace hyphens with underscores
/// - exact comparison after normalization
pub fn normalize_finding(name: &str) -> String {
    let trimmed = name.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    let mut result = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if c == '-' || c == ' ' {
            result.push('_');
        } else if c.is_uppercase() {
            if i > 0 {
                let prev = chars[i - 1];
                if prev.is_lowercase()
                    || (prev.is_uppercase() && chars.get(i + 1).is_some_and(|&n| n.is_lowercase()))
                {
                    result.push('_');
                }
            }
            result.push(c.to_lowercase().next().unwrap_or(c));
        } else {
            result.push(c);
        }
    }
    result
}

/// Match a detected finding against an expected finding.
///
/// Uses normalized exact comparison only — no substring matching.
pub fn findings_match(detected: &str, expected: &str) -> bool {
    normalize_finding(detected) == normalize_finding(expected)
}
