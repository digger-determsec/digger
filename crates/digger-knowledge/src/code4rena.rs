/// Code4rena report parser.
///
/// Parses Code4rena contest report.md files containing findings
/// organized by severity with inline descriptions, PoCs, and mitigations.
///
/// Format:
///   YAML frontmatter (sponsor, slug, date, title, contest)
///   Overview with warden list
///   Findings by severity: ## [H-01] Title
///     *Submitted by ...*
///     Description
///     ### Proof of Concept
///     ### Recommended Mitigation Steps
///
/// Deterministic regex-based parsing. No ML. No heuristics.
use digger_knowledge_models::*;
use regex::Regex;

/// Local parse error for the Code4rena parser.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Parse error in {filename}: {message}")]
pub struct ParseError {
    pub message: String,
    pub filename: String,
    pub line: Option<usize>,
}

/// Parse a Code4rena report.md file.
pub fn parse_code4rena_report(content: &str, filename: &str) -> Result<AuditReport, ParseError> {
    let metadata = extract_frontmatter(content);
    let protocol_name = metadata
        .get("sponsor")
        .cloned()
        .unwrap_or_else(|| extract_protocol_from_filename(filename));
    let contest_date = metadata.get("date").cloned();
    let _contest_id = metadata.get("contest").cloned();

    let sections = extract_sections(content);
    let findings = extract_findings(content, &protocol_name);
    let report_id = compute_report_id(filename, &protocol_name);

    Ok(AuditReport {
        report_id,
        protocol_name,
        protocol_category: classify_protocol_category(content),
        auditor: "Code4rena".into(),
        reviewers: extract_wardens(content),
        audit_date: contest_date,
        source_repo: "code-423n4".into(),
        source_path: filename.into(),
        commit_hash: None,
        scope: vec![],
        findings,
        privileged_roles: vec![],
        centralization_notes: vec![],
        raw_sections: sections,
    })
}

/// Extract YAML frontmatter from report.
fn extract_frontmatter(content: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();

    if !content.starts_with("---") {
        return map;
    }

    let end = content[3..].find("---").map(|p| p + 3);
    if let Some(end) = end {
        let frontmatter = &content[3..end];
        for line in frontmatter.lines() {
            let line = line.trim();
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().trim_matches('"').to_string();
                map.insert(key, value);
            }
        }
    }

    map
}

/// Extract protocol name from filename.
fn extract_protocol_from_filename(filename: &str) -> String {
    // Pattern: 2024-08-superposition-findings.md or similar
    let Ok(re) = Regex::new(r"\d{4}-\d{2}-(.+?)(?:-findings)?\.md") else {
        return filename.replace(".md", "").replace('-', " ");
    };
    if let Some(caps) = re.captures(filename) {
        return caps[1].replace('-', " ");
    }
    filename.replace(".md", "").replace('-', " ")
}

/// Extract warden names from the overview section.
fn extract_wardens(content: &str) -> Vec<String> {
    let mut wardens = Vec::new();
    let Ok(re) = Regex::new(r"\[([^\]]+)\]\(https://code4rena\.com/@") else {
        return wardens;
    };
    for caps in re.captures_iter(content) {
        let name = caps[1].trim().to_string();
        if !wardens.contains(&name) {
            wardens.push(name);
        }
    }
    wardens
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

/// Extract findings from report content.
fn extract_findings(content: &str, _protocol_name: &str) -> Vec<ExtractedFinding> {
    let mut findings = Vec::new();

    // Match finding headings: ## [H-01] Title, ## [M-01] Title, ## [L-01] Title
    // Also match: # BUG 1 Title, # BUG 2 Title (submission format)
    let Ok(finding_re) =
        Regex::new(r"(?m)^#{1,3}\s*(?:\[[HMLhml]-(\d{2})\]\s*(.+?)$|BUG\s+(\d+)\s+(.+?)$)")
    else {
        return vec![];
    };
    let Ok(next_bug_re) = Regex::new(r"(?m)^#\s+BUG\s+\d+") else {
        return vec![];
    };

    for caps in finding_re.captures_iter(content) {
        let (finding_id, title, severity) = if let Some(severity_letter) = caps.get(1) {
            // Format: [H-01] Title
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
        } else if let Some(bug_number) = caps.get(3) {
            // Format: # BUG 1 Title
            let title = caps[4].trim().to_string();
            let finding_id = format!("BUG-{}", bug_number.as_str());
            // Infer severity from title or default to Medium
            let severity = if title.to_lowercase().contains("critical")
                || title.to_lowercase().contains("high")
            {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            };
            (finding_id, title, severity)
        } else {
            continue;
        };

        // Extract body between this heading and the next # BUG heading
        let start = match caps.get(0) {
            Some(m) => m.end(),
            None => continue,
        };
        let rest = &content[start..];

        // Find the next # BUG heading (same level)
        let body = if let Some(next) = next_bug_re.find(rest) {
            &rest[..next.start()]
        } else {
            rest
        };

        let body = body.trim().to_string();

        // Extract description, impact, mitigation from body
        let description = extract_section_text(&body, "Vulnerability Details", "Impact");
        let impact = extract_section_text(&body, "Impact", "Proof of Concept");
        let mitigation = extract_section_text(&body, "Recommended Mitigation Steps", "");

        // If no sections found, use Summary as description
        let description = if description.is_empty() {
            extract_section_text(&body, "Summary", "")
        } else {
            description
        };

        findings.push(ExtractedFinding {
            finding_id,
            title,
            severity,
            impact,
            likelihood: None,
            description,
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

/// Extract text between two section headings.
fn extract_section_text(body: &str, start_name: &str, end_name: &str) -> String {
    let Ok(start_re) = Regex::new(&format!(r"(?i)###?\s*{}", regex::escape(start_name))) else {
        return String::new();
    };
    let end_re = if end_name.is_empty() {
        None
    } else {
        Regex::new(&format!(r"(?i)###?\s*{}", regex::escape(end_name))).ok()
    };

    if let Some(start_match) = start_re.find(body) {
        let rest = &body[start_match.end()..];
        if let Some(end_match) = end_re.as_ref().and_then(|r| r.find(rest)) {
            rest[..end_match.start()].trim().to_string()
        } else {
            rest.trim().to_string()
        }
    } else {
        String::new()
    }
}

/// Classify protocol category from content.
fn classify_protocol_category(content: &str) -> ProtocolCategory {
    let lower = content.to_lowercase();
    if lower.contains("lending") || lower.contains("borrow") || lower.contains("collateral") {
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
    if lower.contains("perp") || lower.contains("perpetual") || lower.contains("futures") {
        return ProtocolCategory::Perps;
    }
    if lower.contains("vault") || lower.contains("strategy") {
        return ProtocolCategory::Vault;
    }
    if lower.contains("nft") || lower.contains("erc-721") {
        return ProtocolCategory::NFT;
    }
    if lower.contains("game") || lower.contains("gaming") {
        return ProtocolCategory::Gaming;
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

/// Code4rena knowledge source — implements KnowledgeSource.
pub struct Code4renaSource;

impl KnowledgeSource for Code4renaSource {
    fn source_id(&self) -> &str {
        "code4rena"
    }

    fn source_kind(&self) -> KnowledgeSourceKind {
        KnowledgeSourceKind::AuditRepository
    }

    fn description(&self) -> &str {
        "Code4rena competitive audit contest reports"
    }

    fn supported_formats(&self) -> Vec<&str> {
        vec!["md"]
    }

    fn extract(
        &self,
        content: &str,
        identifier: &str,
    ) -> Result<NormalizedKnowledge, ExtractionError> {
        let report = parse_code4rena_report(content, identifier).map_err(|e| ExtractionError {
            message: e.message,
            source_identifier: identifier.into(),
            line: e.line,
        })?;

        let normalized = super::normalizer::normalize_report(&report);
        Ok(normalized)
    }
}
