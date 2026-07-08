//! Shared utilities for fuzz evidence artifact parsers.

pub(crate) fn extract_after(content: &str, markers: &[&str]) -> Option<String> {
    let lc = content.to_lowercase();
    for marker in markers {
        if let Some(pos) = lc.find(marker) {
            let after = &content[pos + marker.len()..];
            for line in after.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

pub(crate) fn clean_name(s: &str) -> String {
    s.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(':')
        .to_string()
}
