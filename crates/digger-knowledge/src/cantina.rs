/// Cantina audit report parser.
///
/// Parses Cantina security audit PDFs by extracting text
/// and parsing the common finding structure.
///
/// Cantina reports follow industry-standard format with findings
/// organized by severity (Critical, High, Medium, Low, Informational).
///
/// Deterministic regex-based parsing. No ML. No heuristics.
use crate::pdf_extractor;
use digger_knowledge_models::*;
use regex::Regex;

/// Parse a Cantina PDF audit report.
pub fn parse_cantina_pdf(path: &str) -> Result<AuditReport, ExtractionError> {
    let text = pdf_extractor::extract_text_from_pdf(path)?;
    let cleaned = pdf_extractor::clean_pdf_text(&text);
    let Some(filename_os) = std::path::Path::new(path).file_name() else {
        return Err(ExtractionError {
            message: "Invalid path: no filename".into(),
            source_identifier: path.into(),
            line: None,
        });
    };
    let Some(filename) = filename_os.to_str() else {
        return Err(ExtractionError {
            message: "Invalid filename: not valid UTF-8".into(),
            source_identifier: path.into(),
            line: None,
        });
    };
    parse_cantina_text(&cleaned, filename).map_err(|e| ExtractionError {
        message: e.message,
        source_identifier: filename.into(),
        line: e.line,
    })
}

/// Parse Cantina text content.
pub fn parse_cantina_text(content: &str, filename: &str) -> Result<AuditReport, ParseError> {
    let metadata = pdf_extractor::extract_metadata_from_filename(filename);
    let protocol_name = metadata.name.clone();
    let findings = extract_findings(content);
    let report_id = compute_report_id(filename, &protocol_name);

    Ok(AuditReport {
        report_id,
        protocol_name,
        protocol_category: classify_protocol_category(content),
        auditor: "Cantina".into(),
        reviewers: vec![],
        audit_date: metadata.date,
        source_repo: "cantina".into(),
        source_path: filename.into(),
        commit_hash: extract_commit_hash(content),
        scope: vec![],
        findings,
        privileged_roles: vec![],
        centralization_notes: vec![],
        raw_sections: extract_sections(content),
    })
}

/// Extract findings from Cantina text.
fn extract_findings(content: &str) -> Vec<ExtractedFinding> {
    let mut findings = Vec::new();

    // Match severity-grouped findings:
    // ## Critical Findings
    // ### [C-01] Title
    // or
    // ### Finding C-01: Title
    let Ok(finding_re) =
        Regex::new(r"(?m)^#{1,3}\s*(?:\[)?([CHMLchml])-(\d+)(?:\])?\s*[:\.]?\s*(.+?)$")
    else {
        return vec![];
    };

    let Ok(next_finding_re) = Regex::new(r"(?m)^#{1,3}\s*(?:\[)?[CHMLchml]-\d+(?:\])?") else {
        return vec![];
    };

    for caps in finding_re.captures_iter(content) {
        let sev_letter = &caps[1];
        let number = &caps[2];
        let title = caps[3].trim().to_string();
        let finding_id = format!("{}-{}", sev_letter.to_uppercase(), number);

        let severity = match sev_letter.to_uppercase().as_str() {
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
            &remaining[..remaining.len().min(3000)]
        };

        let description = extract_section_text(
            body,
            &["Description", "Details", "Summary", "Vulnerability Details"],
        );
        let impact = extract_section_text(body, &["Impact"]);
        let recommendation = extract_section_text(
            body,
            &["Recommendation", "Recommendations", "Remediation", "Fix"],
        );
        let poc = extract_section_text(body, &["Proof of Concept", "PoC", "Exploit Scenario"]);

        let description = if description.is_empty() {
            let trimmed = body.trim();
            if trimmed.len() > 500 {
                let mut end = 500;
                while !trimmed.is_char_boundary(end) {
                    end -= 1;
                }
                trimmed[..end].to_string()
            } else {
                trimmed.to_string()
            }
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
            exploit_path: if poc.is_empty() { None } else { Some(poc) },
            impacted_contracts: extract_impacted_items(body),
            impacted_functions: extract_function_names(body),
            remediation: recommendation,
            status: FindingStatus::Unknown,
            references: vec![],
            code_snippets: extract_code_snippets(body),
        });
    }

    findings
}

fn extract_section_text(body: &str, names: &[&str]) -> String {
    let lower = body.to_lowercase();
    for name in names {
        let pattern = format!("### {}", name.to_lowercase());
        if let Some(start_pos) = lower.find(&pattern) {
            let after = &body[start_pos + pattern.len()..];
            let end = after.find("\n###").unwrap_or(after.len());
            return after[..end].trim().to_string();
        }
        let pattern2 = format!("## {}", name.to_lowercase());
        if let Some(start_pos) = lower.find(&pattern2) {
            let after = &body[start_pos + pattern2.len()..];
            let end = after.find("\n##").unwrap_or(after.len());
            return after[..end].trim().to_string();
        }
    }
    String::new()
}

fn extract_sections(content: &str) -> std::collections::BTreeMap<String, String> {
    let mut sections = std::collections::BTreeMap::new();
    let mut current = String::new();
    let mut buf = String::new();
    for line in content.lines() {
        if line.starts_with('#') {
            if !current.is_empty() {
                sections.insert(current.clone(), buf.trim().to_string());
            }
            current = line.trim_start_matches('#').trim().to_string();
            buf.clear();
        } else {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    if !current.is_empty() {
        sections.insert(current, buf.trim().to_string());
    }
    sections
}

fn extract_commit_hash(content: &str) -> Option<String> {
    let Ok(re) = Regex::new(r"(?i)commit\s*(?:hash)?\s*[:=]?\s*[`]?([a-f0-9]{40})") else {
        return None;
    };
    re.captures(content).map(|c| c[1].to_string())
}

fn extract_impacted_items(body: &str) -> Vec<String> {
    let mut items = Vec::new();
    let Ok(re) = Regex::new(r"`([A-Za-z0-9_]+\.(?:sol|rs|ts|js))`") else {
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
    let Ok(re) = Regex::new(r"`([a-z][a-zA-Z0-9_]*)\(`") else {
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

fn extract_code_snippets(body: &str) -> Vec<CodeSnippet> {
    let mut snippets = Vec::new();
    let fence = "`".repeat(3);
    let parts: Vec<&str> = body.split(&fence[..]).collect();
    let mut i = 1;
    while i < parts.len() {
        let block = parts[i];
        let lines: Vec<&str> = block.lines().collect();
        if !lines.is_empty() {
            let lang = lines[0].trim().to_string();
            let mut code = String::new();
            for (idx, line) in lines[1..].iter().enumerate() {
                if idx > 0 {
                    code.push('\n');
                }
                code.push_str(line);
            }
            let code = code.trim().to_string();
            if !code.is_empty() {
                snippets.push(CodeSnippet {
                    language: if lang.is_empty() {
                        "unknown".into()
                    } else {
                        lang
                    },
                    code,
                    context: None,
                });
            }
        }
        i += 2;
    }
    snippets
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
    if lower.contains("bridge") || lower.contains("cross-chain") {
        return ProtocolCategory::Bridge;
    }
    ProtocolCategory::Unknown
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

#[derive(Debug, Clone, thiserror::Error)]
#[error("Parse error in {filename}: {message}")]
pub struct ParseError {
    pub message: String,
    pub filename: String,
    pub line: Option<usize>,
}

/// Cantina knowledge source.
pub struct CantinaSource;

impl KnowledgeSource for CantinaSource {
    fn source_id(&self) -> &str {
        "cantina"
    }

    fn source_kind(&self) -> KnowledgeSourceKind {
        KnowledgeSourceKind::AuditRepository
    }

    fn description(&self) -> &str {
        "Cantina security audit reports"
    }

    fn supported_formats(&self) -> Vec<&str> {
        vec!["pdf", "md"]
    }

    fn extract(
        &self,
        content: &str,
        identifier: &str,
    ) -> Result<NormalizedKnowledge, ExtractionError> {
        if identifier.ends_with(".pdf") || identifier.ends_with(".PDF") {
            let text = pdf_extractor::extract_text_from_pdf(content)?;
            let cleaned = pdf_extractor::clean_pdf_text(&text);
            let report = parse_cantina_text(&cleaned, identifier).map_err(|e| ExtractionError {
                message: e.message,
                source_identifier: identifier.into(),
                line: e.line,
            })?;
            Ok(super::normalizer::normalize_report(&report))
        } else {
            let report = parse_cantina_text(content, identifier).map_err(|e| ExtractionError {
                message: e.message,
                source_identifier: identifier.into(),
                line: e.line,
            })?;
            Ok(super::normalizer::normalize_report(&report))
        }
    }
}
