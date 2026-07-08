/// Trail of Bits audit report parser.
///
/// Parses Trail of Bits security review PDFs by extracting text
/// and parsing the known finding template structure.
///
/// Finding template:
///   TOB-[PROJECT]-[NUMBER]: [Title]
///   **Severity:** [level]
///   **Type:** [category]
///   **Target:** [component]
///   #### Description
///   #### Exploit Scenario
///   #### Recommendation
///
/// Deterministic regex-based parsing. No ML. No heuristics.
use crate::pdf_extractor;
use digger_knowledge_models::*;
use regex::Regex;

/// Parse a Trail of Bits PDF audit report.
pub fn parse_tob_pdf(path: &str) -> Result<AuditReport, ExtractionError> {
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
    parse_tob_text(&cleaned, filename).map_err(|e| ExtractionError {
        message: e.message,
        source_identifier: filename.into(),
        line: e.line,
    })
}

/// Parse Trail of Bits text content (from PDF extraction or Markdown).
pub fn parse_tob_text(content: &str, filename: &str) -> Result<AuditReport, ParseError> {
    let metadata = pdf_extractor::extract_metadata_from_filename(filename);
    let protocol_name = metadata.name.clone();
    let findings = extract_findings(content);
    let report_id = compute_report_id(filename, &protocol_name);

    Ok(AuditReport {
        report_id,
        protocol_name,
        protocol_category: classify_protocol_category(content),
        auditor: "Trail of Bits".into(),
        reviewers: vec![],
        audit_date: metadata.date,
        source_repo: "trailofbits/publications".into(),
        source_path: filename.into(),
        commit_hash: extract_commit_hash(content),
        scope: vec![],
        findings,
        privileged_roles: vec![],
        centralization_notes: vec![],
        raw_sections: extract_sections(content),
    })
}

/// Extract findings from Trail of Bits text.
fn extract_findings(content: &str) -> Vec<ExtractedFinding> {
    let mut findings = Vec::new();

    // Match: TOB-[PROJECT]-[NUMBER]: [Title] or ### TOB-[PROJECT]-[NUMBER]: [Title]
    let Ok(finding_re) = Regex::new(r"(?m)^#{0,3}\s*(TOB-[A-Za-z0-9_-]+-\d+)\s*:\s*(.+?)$") else {
        return vec![];
    };
    let Ok(next_finding_re) = Regex::new(r"(?m)^#{0,3}\s*TOB-[A-Za-z0-9_-]+-\d+\s*:") else {
        return vec![];
    };

    for caps in finding_re.captures_iter(content) {
        let finding_id = caps[1].to_string();
        let title = caps[2].trim().to_string();

        // Extract body
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

        // Extract severity
        let severity = extract_severity(body);

        // Extract sections
        let description = extract_section_text(body, &["Description"]);
        let exploit_scenario = extract_section_text(
            body,
            &["Exploit Scenario", "Exploit scenario", "Proof of Concept"],
        );
        let recommendation = extract_section_text(body, &["Recommendation", "Recommendations"]);
        let _target = extract_bold_field(body, "Target");
        let finding_type = extract_bold_field(body, "Type");

        // Use description or body as description
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
            impact: String::new(),
            likelihood: None,
            description,
            root_cause: finding_type,
            exploit_path: if exploit_scenario.is_empty() {
                None
            } else {
                Some(exploit_scenario)
            },
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

/// Extract severity from body text.
fn extract_severity(body: &str) -> FindingSeverity {
    let Ok(sev_re) = Regex::new(r"(?i)\*?\*?Severity\*?\*?\s*:\s*(\w+)") else {
        return FindingSeverity::Informational;
    };
    if let Some(caps) = sev_re.captures(body) {
        match caps[1].to_lowercase().as_str() {
            "critical" => FindingSeverity::Critical,
            "high" => FindingSeverity::High,
            "medium" => FindingSeverity::Medium,
            "low" => FindingSeverity::Low,
            "informational" | "undetermined" => FindingSeverity::Informational,
            _ => FindingSeverity::Informational,
        }
    } else {
        FindingSeverity::Informational
    }
}

/// Extract a bold field value.
fn extract_bold_field(body: &str, field: &str) -> String {
    let Ok(re) = Regex::new(&format!(
        r"(?i)\*?\*?{}\*?\*?\s*:\s*(.+?)(?:\n|$)",
        regex::escape(field)
    )) else {
        return String::new();
    };
    re.captures(body)
        .map(|c| c[1].trim().to_string())
        .unwrap_or_default()
}

/// Extract text from a named section.
fn extract_section_text(body: &str, names: &[&str]) -> String {
    let lower = body.to_lowercase();
    for name in names {
        let pattern = format!("#### {}", name.to_lowercase());
        if let Some(start_pos) = lower.find(&pattern) {
            let after = &body[start_pos + pattern.len()..];
            let end = after.find("\n####").unwrap_or(after.len());
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
    let Ok(re) = Regex::new(r"`([A-Za-z0-9_]+\.(?:sol|rs|ts|js|vy))`") else {
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
    if lower.contains("governance") || lower.contains("voting") {
        return ProtocolCategory::Governance;
    }
    if lower.contains("nft") || lower.contains("erc-721") {
        return ProtocolCategory::NFT;
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

/// Local parse error.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Parse error in {filename}: {message}")]
pub struct ParseError {
    pub message: String,
    pub filename: String,
    pub line: Option<usize>,
}

/// Trail of Bits knowledge source.
pub struct TrailOfBitsSource;

impl KnowledgeSource for TrailOfBitsSource {
    fn source_id(&self) -> &str {
        "trailofbits"
    }

    fn source_kind(&self) -> KnowledgeSourceKind {
        KnowledgeSourceKind::AuditRepository
    }

    fn description(&self) -> &str {
        "Trail of Bits security review reports"
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
            let report = parse_tob_text(&cleaned, identifier).map_err(|e| ExtractionError {
                message: e.message,
                source_identifier: identifier.into(),
                line: e.line,
            })?;
            Ok(super::normalizer::normalize_report(&report))
        } else {
            // Treat content as already-extracted text
            let report = parse_tob_text(content, identifier).map_err(|e| ExtractionError {
                message: e.message,
                source_identifier: identifier.into(),
                line: e.line,
            })?;
            Ok(super::normalizer::normalize_report(&report))
        }
    }
}

/// Parse a Trail of Bits CSV dataset.
///
/// CSV columns: type, severity, difficulty, static, dynamic, ERC20
pub fn parse_tob_csv(content: &str) -> Vec<NormalizedFinding> {
    let mut findings = Vec::new();

    for (i, line) in content.lines().enumerate() {
        if i == 0 {
            continue; // skip header
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 2 {
            continue;
        }

        let finding_type = fields[0].trim().to_string();
        let severity_str = fields[1].trim().to_string();
        let difficulty = if fields.len() > 2 {
            fields[2].trim().to_string()
        } else {
            String::new()
        };
        let is_static = fields.len() > 3 && fields[3].trim() == "1";
        let is_dynamic = fields.len() > 4 && fields[4].trim() == "1";
        let is_erc20 = fields.len() > 5 && fields[5].trim() == "1";

        let severity = match severity_str.to_lowercase().as_str() {
            "high" => FindingSeverity::High,
            "medium" => FindingSeverity::Medium,
            "low" => FindingSeverity::Low,
            _ => FindingSeverity::Informational,
        };

        let vulnerability_class = classify_tob_type(&finding_type);
        let attack_goal = super::normalizer::map_to_attack_goal(&vulnerability_class);
        let root_cause = infer_tob_root_cause(&finding_type);

        findings.push(NormalizedFinding {
            finding_id: format!("tob:{:x}", {
                let mut h: u64 = 0;
                for byte in format!("TOB-{:04}", i).bytes() {
                    h = h.wrapping_mul(31).wrapping_add(byte as u64);
                }
                h
            }),
            original_finding_id: format!("TOB-{:04}", i),
            report_id: "tob-csv-dataset".into(),
            protocol_name: "Trail of Bits Dataset".into(),
            protocol_category: ProtocolCategory::Unknown,
            protocol_domain: ProtocolDomain::Generic,
            protocol_pattern: None,
            vulnerability_class,
            attack_goal,
            capability_pattern: vec![],
            violated_invariant: ViolatedInvariant {
                kind: "unknown".into(),
                description: "Security invariant violated".into(),
                affected_state_vars: vec![],
            },
            attack_technique: AttackTechnique::Other(finding_type.clone()),
            mitigation_pattern: None,
            security_assumptions: vec![],
            severity: super::normalizer::map_severity(&severity),
            root_cause,
            impact_text: format!(
                "Difficulty: {}, Static: {}, Dynamic: {}, ERC20: {}",
                difficulty, is_static, is_dynamic, is_erc20
            ),
            description_text: format!("Type: {}", finding_type),
            remediation_text: String::new(),
            impacted_contracts: vec![],
            impacted_functions: vec![],
            confidence: 1.0,
        });
    }

    findings
}

fn classify_tob_type(finding_type: &str) -> VulnerabilityClass {
    let lower = finding_type.to_lowercase();
    if lower.contains("reentrancy") {
        return VulnerabilityClass::Reentrancy;
    }
    if lower.contains("access control") || lower.contains("authorization") {
        return VulnerabilityClass::MissingAccessControl;
    }
    if lower.contains("validation") || lower.contains("input validation") {
        return VulnerabilityClass::MissingValidation;
    }
    if lower.contains("arithmetic") || lower.contains("overflow") {
        return VulnerabilityClass::IntegerOverflow;
    }
    if lower.contains("oracle") || lower.contains("price") {
        return VulnerabilityClass::OracleManipulation;
    }
    if lower.contains("front-run") || lower.contains("race") {
        return VulnerabilityClass::FrontRunning;
    }
    if lower.contains("denial") || lower.contains("dos") || lower.contains("grief") {
        return VulnerabilityClass::DenialOfService;
    }
    if lower.contains("flash loan") {
        return VulnerabilityClass::FlashLoanAttack;
    }
    if lower.contains("governance") {
        return VulnerabilityClass::GovernanceAttack;
    }
    if lower.contains("upgrade") || lower.contains("proxy") {
        return VulnerabilityClass::UpgradeabilityRisk;
    }
    if lower.contains("initialization") {
        return VulnerabilityClass::UnprotectedInitialization;
    }
    if lower.contains("precision") || lower.contains("rounding") {
        return VulnerabilityClass::PrecisionLoss;
    }
    if lower.contains("missing logic") || lower.contains("business logic") {
        return VulnerabilityClass::BusinessLogicFlaw;
    }
    if lower.contains("data validation") {
        return VulnerabilityClass::MissingValidation;
    }
    if lower.contains("patching") || lower.contains("configuration") {
        return VulnerabilityClass::MissingValidation;
    }
    if lower.contains("coding-bug") {
        return VulnerabilityClass::BusinessLogicFlaw;
    }
    if lower.contains("sandwich") {
        return VulnerabilityClass::SandwichAttack;
    }
    if lower.contains("unchecked") {
        return VulnerabilityClass::UncheckedReturn;
    }
    if lower.contains("storage") {
        return VulnerabilityClass::StorageCollision;
    }
    VulnerabilityClass::Other(finding_type.to_string())
}

fn infer_tob_root_cause(finding_type: &str) -> StructuralRootCause {
    let lower = finding_type.to_lowercase();
    if lower.contains("validation") || lower.contains("input") {
        return StructuralRootCause::UnvalidatedExternalInput;
    }
    if lower.contains("access control") || lower.contains("authorization") {
        return StructuralRootCause::MissingAuthorityCheck;
    }
    if lower.contains("arithmetic") || lower.contains("overflow") {
        return StructuralRootCause::MissingBoundaryCheck;
    }
    if lower.contains("reentrancy") {
        return StructuralRootCause::CrossFunctionStateInconsistency;
    }
    if lower.contains("oracle") || lower.contains("price") {
        return StructuralRootCause::OracleStaleness;
    }
    if lower.contains("front-run") || lower.contains("race") {
        return StructuralRootCause::FrontRunningRisk;
    }
    if lower.contains("missing logic") || lower.contains("business logic") {
        return StructuralRootCause::IncorrectOperationOrder;
    }
    if lower.contains("configuration") || lower.contains("patching") {
        return StructuralRootCause::MissingAuthorityCheck;
    }
    if lower.contains("precision") || lower.contains("rounding") {
        return StructuralRootCause::IncorrectRoundingDirection;
    }
    StructuralRootCause::Other(finding_type.to_string())
}
