/// Sherlock audit contest report parser.
///
/// Parses Sherlock judging repo README.md files containing
/// consolidated findings after judging.
///
/// Format:
///   # Issue [H|M|L]-[NUMBER]: Title
///   ## Found by
///   ### Summary
///   ### Root Cause
///   ### Attack Path
///   ### Impact
///   ### Mitigation
///   ### Fix
///
/// Deterministic regex-based parsing. No ML. No heuristics.
use digger_knowledge_models::*;
use regex::Regex;

/// Local parse error for the Sherlock parser.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Parse error in {filename}: {message}")]
pub struct ParseError {
    pub message: String,
    pub filename: String,
    pub line: Option<usize>,
}

/// Parse a Sherlock judging README.md file.
pub fn parse_sherlock_report(content: &str, filename: &str) -> Result<AuditReport, ParseError> {
    let protocol_name = extract_protocol_name(filename);
    let audit_date = extract_date(filename);
    let findings = extract_findings(content);
    let report_id = compute_report_id(filename, &protocol_name);

    Ok(AuditReport {
        report_id,
        protocol_name,
        protocol_category: classify_protocol_category(content),
        auditor: "Sherlock".into(),
        reviewers: extract_reviewers(content),
        audit_date,
        source_repo: "sherlock-audit".into(),
        source_path: filename.into(),
        commit_hash: None,
        scope: vec![],
        findings,
        privileged_roles: vec![],
        centralization_notes: vec![],
        raw_sections: extract_sections(content),
    })
}

/// Extract protocol name from filename.
/// Pattern: 2025-07-cap-judging → cap
fn extract_protocol_name(filename: &str) -> String {
    let Ok(re) = Regex::new(r"\d{4}-\d{2}-(.+?)(?:-judging)?\.md") else {
        return filename.replace(".md", "").replace('-', " ");
    };
    if let Some(caps) = re.captures(filename) {
        return caps[1].replace('-', " ");
    }
    filename.replace(".md", "").replace('-', " ")
}

/// Extract date from filename.
fn extract_date(filename: &str) -> Option<String> {
    let Ok(re) = Regex::new(r"(\d{4}-\d{2})") else {
        return None;
    };
    re.captures(filename).map(|caps| caps[1].to_string())
}

/// Extract reviewer names from "Found by" sections.
fn extract_reviewers(content: &str) -> Vec<String> {
    let mut reviewers = Vec::new();
    let Ok(re) = Regex::new(r"(?i)## Found by\s*\n\s*(.+?)(?:\n|$)") else {
        return reviewers;
    };
    for caps in re.captures_iter(content) {
        for name in caps[1].split(',') {
            let name = name.trim().replace('_', " ");
            if !name.is_empty() && !reviewers.contains(&name) {
                reviewers.push(name);
            }
        }
    }
    reviewers
}

/// Extract all sections from the document.
fn extract_sections(content: &str) -> std::collections::BTreeMap<String, String> {
    let mut sections = std::collections::BTreeMap::new();
    let mut current_section = String::new();
    let mut current_content = String::new();

    for line in content.lines() {
        if line.starts_with('#') {
            if !current_section.is_empty() {
                sections.insert(current_section.clone(), current_content.trim().to_string());
            }
            current_section = line.trim_start_matches('#').trim().to_string();
            current_content.clear();
        } else {
            current_content.push_str(line);
            current_content.push('\n');
        }
    }
    if !current_section.is_empty() {
        sections.insert(current_section, current_content.trim().to_string());
    }
    sections
}

/// Extract findings from content.
fn extract_findings(content: &str) -> Vec<ExtractedFinding> {
    let mut findings = Vec::new();

    // Match finding headings: # Issue H-1: Title, # Issue M-1: Title
    // Also match: # Title (single heading format — Sherlock judging repos)
    let Ok(finding_re) = Regex::new(r"(?m)^#\s+(?:Issue\s+([HMLhml])-(\d+)\s*:\s*)?(.+?)$") else {
        return vec![];
    };
    let Ok(next_heading_re) = Regex::new(r"(?m)^#{1,3}\s") else {
        return vec![];
    };

    for caps in finding_re.captures_iter(content) {
        let (finding_id, title, severity) = if let Some(severity_letter) = caps.get(1) {
            // Format: # Issue H-1: Title
            let number = &caps[2];
            let title = caps[3].trim().to_string();
            let finding_id = format!("{}-{}", severity_letter.as_str().to_uppercase(), number);
            let severity = match severity_letter.as_str().to_uppercase().as_str() {
                "H" => FindingSeverity::High,
                "M" => FindingSeverity::Medium,
                "L" => FindingSeverity::Low,
                _ => FindingSeverity::Informational,
            };
            (finding_id, title, severity)
        } else if let Some(title_match) = caps.get(3) {
            // Format: # Title (single heading)
            let title = title_match.as_str().trim().to_string();
            if title.is_empty() || title.len() < 5 {
                continue; // Skip very short titles
            }
            let finding_id = format!("SHERLOCK-{}", title.len());
            let severity = FindingSeverity::Medium; // Default for Sherlock
            (finding_id, title, severity)
        } else {
            continue;
        };

        // Extract body between this heading and the next
        let start = match caps.get(0) {
            Some(m) => m.end(),
            None => continue,
        };
        let rest = &content[start..];

        let body = if let Some(next) = next_heading_re.find(rest) {
            &rest[..next.start()]
        } else {
            rest
        };

        let body = body.trim().to_string();

        // Extract sections
        let summary = extract_section(&body, "Summary");
        let impact = extract_section(&body, "Impact");
        let mitigation = extract_section(&body, "Mitigation");

        findings.push(ExtractedFinding {
            finding_id,
            title,
            severity,
            impact,
            likelihood: None,
            description: summary,
            root_cause: String::new(),
            exploit_path: None,
            impacted_contracts: vec![],
            impacted_functions: vec![],
            remediation: mitigation,
            status: FindingStatus::Open,
            references: vec![],
            code_snippets: vec![],
        });
    }

    findings
}

/// Extract a section by name.
fn extract_section(body: &str, name: &str) -> String {
    let Ok(re) = Regex::new(&format!(r"(?i)##?\s*{}", name)) else {
        return String::new();
    };
    if let Some(m) = re.find(body) {
        let rest = &body[m.end()..];
        let Ok(next) = Regex::new(r"(?m)^##?\s") else {
            return rest.trim().to_string();
        };
        if let Some(end) = next.find(rest) {
            rest[..end.start()].trim().to_string()
        } else {
            rest.trim().to_string()
        }
    } else {
        String::new()
    }
}

/// Classify protocol category.
fn classify_protocol_category(content: &str) -> ProtocolCategory {
    let lower = content.to_lowercase();
    if lower.contains("lending")
        || lower.contains("borrow")
        || lower.contains("collateral")
        || lower.contains("liquidat")
    {
        return ProtocolCategory::Lending;
    }
    if lower.contains("stablecoin") || lower.contains("peg") {
        return ProtocolCategory::Stablecoin;
    }
    if lower.contains("dex") || lower.contains("swap") || lower.contains("amm") {
        return ProtocolCategory::DEX;
    }
    if lower.contains("yield") || lower.contains("staking") || lower.contains("farm") {
        return ProtocolCategory::Yield;
    }
    if lower.contains("bridge") || lower.contains("cross-chain") {
        return ProtocolCategory::Bridge;
    }
    if lower.contains("governance") || lower.contains("voting") {
        return ProtocolCategory::Governance;
    }
    if lower.contains("vault") || lower.contains("strategy") {
        return ProtocolCategory::Vault;
    }
    ProtocolCategory::Unknown
}

/// Compute deterministic report ID.
fn compute_report_id(filename: &str, protocol_name: &str) -> String {
    let mut h: u64 = 0;
    for byte in filename.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    for byte in protocol_name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("{:x}", h)
}

/// Sherlock knowledge source — implements KnowledgeSource.
pub struct SherlockSource;

impl KnowledgeSource for SherlockSource {
    fn source_id(&self) -> &str {
        "sherlock"
    }

    fn source_kind(&self) -> KnowledgeSourceKind {
        KnowledgeSourceKind::AuditRepository
    }

    fn description(&self) -> &str {
        "Sherlock audit contest reports (judging repos)"
    }

    fn supported_formats(&self) -> Vec<&str> {
        vec!["md"]
    }

    fn extract(
        &self,
        content: &str,
        identifier: &str,
    ) -> Result<NormalizedKnowledge, ExtractionError> {
        let report = parse_sherlock_report(content, identifier).map_err(|e| ExtractionError {
            message: e.message,
            source_identifier: identifier.into(),
            line: e.line,
        })?;

        let normalized = super::normalizer::normalize_report(&report);
        Ok(normalized)
    }
}
