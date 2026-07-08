/// Pashov Audit Group report parser.
/// Deterministic regex-based parsing. No ML. No heuristics.
use digger_knowledge_models::*;
use regex::Regex;

/// Local parse error for the Pashov parser.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Parse error in {filename}: {message}")]
pub struct ParseError {
    pub message: String,
    pub filename: String,
    pub line: Option<usize>,
}

/// Parse a Pashov audit Markdown report.
pub fn parse_pashov_report(content: &str, filename: &str) -> Result<AuditReport, ParseError> {
    let protocol_name = extract_protocol_name(filename, content);
    let protocol_category = classify_protocol_category(content);
    let auditor = extract_auditor(content);
    let reviewers = extract_reviewers(content);
    let audit_date = extract_date(filename);
    let commit_hash = extract_commit_hash(content);
    let scope = extract_scope(content);
    let privileged_roles = extract_privileged_roles(content);
    let centralization_notes = extract_centralization_notes(content);
    let sections = extract_sections(content);
    let findings = extract_findings_from_sections(&sections, content);
    let report_id = compute_report_id(filename, &protocol_name);

    Ok(AuditReport {
        report_id,
        protocol_name,
        protocol_category,
        auditor,
        reviewers,
        audit_date,
        source_repo: "pashov/audits".into(),
        source_path: filename.into(),
        commit_hash,
        scope,
        findings,
        privileged_roles,
        centralization_notes,
        raw_sections: sections,
    })
}

fn extract_protocol_name(filename: &str, content: &str) -> String {
    if let Ok(fname_re) = Regex::new(r"^([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)[-_]security[-_]review") {
        if let Some(caps) = fname_re.captures(filename) {
            return caps[1].replace('-', " ");
        }
    }
    if let Ok(about_re) = Regex::new(r"(?i)#\s*About\s+(.+?)(?:\s*$|\n)") {
        if let Some(caps) = about_re.captures(content) {
            let name = caps[1].trim();
            if !name.is_empty() && name != "pashov" && name != "Pashov Audit Group" {
                return name.to_string();
            }
        }
    }
    filename
        .replace("-security-review", "")
        .replace('_', " ")
        .to_string()
}

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
    if lower.contains("token") || lower.contains("erc-20") || lower.contains("erc20") {
        return ProtocolCategory::Token;
    }
    ProtocolCategory::Unknown
}

fn extract_auditor(content: &str) -> String {
    if content.contains("Pashov Audit Group") {
        "Pashov Audit Group".into()
    } else if content.contains("pashov") {
        "pashov".into()
    } else {
        "unknown".into()
    }
}

fn extract_reviewers(content: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r"(?i)engaged?\s+to\s+review.*?by\s+([A-Za-z\s,]+?)(?:\.|<)") else {
        return vec![];
    };
    if let Some(caps) = re.captures(content) {
        return caps[1]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    vec![]
}

fn extract_date(filename: &str) -> Option<String> {
    let Ok(re) = Regex::new(r"(\d{4}-\d{2}-\d{2})") else {
        return None;
    };
    re.captures(filename).map(|caps| caps[1].to_string())
}

fn extract_commit_hash(content: &str) -> Option<String> {
    let Ok(re) = Regex::new(r"(?i)commit\s+hash.*?([a-f0-9]{40})") else {
        return None;
    };
    re.captures(content).map(|caps| caps[1].to_string())
}

/// Find a section by heading names (case-insensitive).
/// Returns the content between the matching heading and the next heading.
fn find_section(content: &str, heading_names: &[&str]) -> Option<String> {
    let lower_content = content.to_lowercase();
    for name in heading_names {
        let pattern = format!("# {}", name.to_lowercase());
        if let Some(start_pos) = lower_content.find(&pattern) {
            let after_heading = &content[start_pos + pattern.len()..];
            // Find the next heading
            let end = after_heading
                .find('\n')
                .map(|pos| {
                    let rest = &after_heading[pos + 1..];
                    rest.find("\n#")
                        .map(|p| pos + 1 + p)
                        .unwrap_or(after_heading.len())
                })
                .unwrap_or(after_heading.len());
            return Some(after_heading[..end].trim().to_string());
        }
    }
    None
}

fn extract_scope(content: &str) -> Vec<ScopedFile> {
    let mut files = Vec::new();
    if let Some(section) = find_section(content, &["Scope", "Security Assessment Summary"]) {
        let Ok(file_re) =
            Regex::new(r"(?:^|\n)\s*[-*]?\s*[`]?([a-zA-Z0-9_/.-]+\.(?:sol|rs|ts|js|vy))[`]?")
        else {
            return files;
        };
        for caps in file_re.captures_iter(&section) {
            let path = caps[1].trim().to_string();
            let language = detect_language(&path);
            files.push(ScopedFile { path, language });
        }
    }
    files
}

fn detect_language(path: &str) -> String {
    if path.ends_with(".sol") {
        "solidity".into()
    } else if path.ends_with(".rs") {
        "rust".into()
    } else if path.ends_with(".ts") || path.ends_with(".js") {
        "typescript".into()
    } else if path.ends_with(".vy") {
        "vyper".into()
    } else {
        "unknown".into()
    }
}

fn extract_privileged_roles(content: &str) -> Vec<PrivilegedRole> {
    let mut roles = Vec::new();
    if let Some(section) = find_section(
        content,
        &["Privileged Roles", "Centralization", "Observations"],
    ) {
        let Ok(role_re) = Regex::new(r"(?i)\*?\*?([A-Za-z\s]+?)(?:\*?\*?)\s*:\s*(.+?)(?:\n|$)")
        else {
            return roles;
        };
        for caps in role_re.captures_iter(&section) {
            let role_name = caps[1].trim().to_string();
            let description = caps[2].trim().to_string();
            if !role_name.is_empty() && role_name.len() < 50 {
                roles.push(PrivilegedRole {
                    role_name,
                    description,
                    functions: vec![],
                    risk_level: "unknown".into(),
                });
            }
        }
    }
    roles
}

fn extract_centralization_notes(content: &str) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(section) = find_section(content, &["Centralization", "Observations"]) {
        for line in section.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed.len() > 10 {
                notes.push(trimmed.to_string());
            }
        }
    }
    notes
}

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

fn extract_findings_from_sections(
    _sections: &std::collections::BTreeMap<String, String>,
    content: &str,
) -> Vec<ExtractedFinding> {
    let mut findings = Vec::new();
    let Ok(finding_re) = Regex::new(r"(?m)^#{1,3}\s*\[([CHMLchml])-(\d{2})\]\s*(.+?)$") else {
        return vec![];
    };
    let Ok(next_finding_re) = Regex::new(r"(?m)^#{1,3}\s*\[[CHMLchml]-\d{2}\]") else {
        return vec![];
    };

    for caps in finding_re.captures_iter(content) {
        let severity_letter = &caps[1];
        let number = &caps[2];
        let title = caps[3].trim().to_string();
        let finding_id = format!("{}-{}", severity_letter.to_uppercase(), number);

        let severity = match severity_letter.to_uppercase().as_str() {
            "C" => FindingSeverity::Critical,
            "H" => FindingSeverity::High,
            "M" => FindingSeverity::Medium,
            "L" => FindingSeverity::Low,
            _ => FindingSeverity::Informational,
        };

        let start = match caps.get(0) {
            Some(m) => m.end(),
            None => continue,
        };
        let remaining = &content[start..];
        let body = if let Some(next) = next_finding_re.find(remaining) {
            &remaining[..next.start()]
        } else {
            remaining
        };

        let impact = extract_finding_field(body, &["Impact", "Severity"]);
        let description = extract_finding_field(body, &["Description"]);
        let root_cause = extract_finding_field(body, &["Root Cause", "Root cause"]);
        let remediation = extract_finding_field(body, &["Remediation", "Recommendations"]);

        // If no section headings found, use the body as description
        // but skip section markers and status indicators
        let description = if description.is_empty() {
            let trimmed = body.trim();
            // Skip lines that are section markers, status indicators, or empty
            let meaningful: Vec<&str> = trimmed
                .lines()
                .skip_while(|line| {
                    let l = line.trim();
                    l.is_empty()
                        || l.starts_with("## ")
                        || l.starts_with("_Resolved_")
                        || l.starts_with("_Acknowledged_")
                        || l.starts_with("*Resolved*")
                        || l.starts_with("*Acknowledged*")
                        || l.starts_with("**Impact")
                        || l.starts_with("**Severity")
                        || l.starts_with("**Likelihood")
                        || l.starts_with("Impact:")
                        || l.starts_with("Severity:")
                        || l.starts_with("Likelihood:")
                })
                .collect();
            let desc_text = meaningful.join("\n").trim().to_string();
            if !desc_text.is_empty() && desc_text.len() > 10 {
                if desc_text.len() > 500 {
                    let mut end = 500;
                    while !desc_text.is_char_boundary(end) {
                        end -= 1;
                    }
                    desc_text[..end].to_string()
                } else {
                    desc_text
                }
            } else {
                description
            }
        } else {
            description
        };

        let status = if body.contains("_Resolved_") || body.contains("*Resolved*") {
            FindingStatus::Resolved
        } else if body.contains("_Acknowledged_") || body.contains("*Acknowledged*") {
            FindingStatus::Acknowledged
        } else {
            FindingStatus::Unknown
        };

        let impacted_contracts = extract_impacted_items(body);
        let impacted_functions = extract_function_names(body);

        findings.push(ExtractedFinding {
            finding_id,
            title,
            severity,
            impact,
            likelihood: None,
            description,
            root_cause: if root_cause.is_empty() {
                String::new()
            } else {
                root_cause
            },
            exploit_path: None,
            impacted_contracts,
            impacted_functions,
            remediation,
            status,
            references: vec![],
            code_snippets: vec![],
        });
    }

    findings
}

fn extract_finding_field(body: &str, names: &[&str]) -> String {
    for name in names {
        let pattern = format!(
            r"(?i)\*?\*?{}\*?\*?\s*:?\s*(.+?)(?:\n\*?\*?[A-Z]|\n##|$)",
            regex::escape(name)
        );
        let Ok(re) = Regex::new(&pattern) else {
            continue;
        };
        if let Some(caps) = re.captures(body) {
            return caps[1].trim().to_string();
        }
    }
    String::new()
}

fn extract_impacted_items(body: &str) -> Vec<String> {
    let mut items = Vec::new();
    let Ok(re) = Regex::new(r"[`]([A-Za-z0-9_]+\.(?:sol|rs|ts|js))[`]") else {
        return items;
    };
    for caps in re.captures_iter(body) {
        let item = caps[1].to_string();
        if !items.contains(&item) {
            items.push(item);
        }
    }
    items
}

fn extract_function_names(body: &str) -> Vec<String> {
    let mut names = Vec::new();
    let Ok(re) = Regex::new(r"[`]([a-z][a-zA-Z0-9_]*)[(]") else {
        return names;
    };
    for caps in re.captures_iter(body) {
        let name = caps[1].to_string();
        if !names.contains(&name) && name.len() > 2 {
            names.push(name);
        }
    }
    names
}

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

/// Pashov Audit Group knowledge source — implements KnowledgeSource.
pub struct PashovSource;

impl KnowledgeSource for PashovSource {
    fn source_id(&self) -> &str {
        "pashov/audits"
    }

    fn source_kind(&self) -> KnowledgeSourceKind {
        KnowledgeSourceKind::AuditRepository
    }

    fn description(&self) -> &str {
        "Pashov Audit Group security review reports"
    }

    fn supported_formats(&self) -> Vec<&str> {
        vec!["md"]
    }

    fn extract(
        &self,
        content: &str,
        identifier: &str,
    ) -> Result<NormalizedKnowledge, ExtractionError> {
        let report = parse_pashov_report(content, identifier).map_err(|e| ExtractionError {
            message: e.message,
            source_identifier: identifier.into(),
            line: e.line,
        })?;

        let normalized = super::normalizer::normalize_report(&report);

        Ok(normalized)
    }
}
