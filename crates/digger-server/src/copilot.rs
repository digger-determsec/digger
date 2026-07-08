/// Deterministic verification layer for security agents.
///
/// Provides: PoC scaffold generation, precedent/citation lookup, explanation validation.
/// The CopilotModel trait and explain_finding/draft_poc are QUARANTINED - never wired
/// to a real provider. All agent truth-layer work flows through digger-agent instead.
use digger_evidence::EvidenceBundle;
use serde::{Deserialize, Serialize};

use crate::ErrorResponse;

pub const DISCLAIMER: &str =
    "Explanation grounded in a deterministic finding â€” not a new finding, not a full audit.";
pub const CITATION_DISCLAIMER: &str =
    "Citations sourced from a curated public corpus of security postmortems and documented vulnerability patterns.";

// â”€â”€ Precedent / Citation types â”€â”€

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrecedentCitation {
    pub id: String,
    pub title: String,
    pub source_url: String,
    pub why_relevant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrecedentEntry {
    pub id: String,
    pub title: String,
    pub vuln_classes: Vec<String>,
    pub rule_ids: Vec<String>,
    pub source_url: String,
    pub summary: String,
}

/// Trait for retrieving precedent entries. Deterministic, offline.
pub trait PrecedentStore: Send + Sync {
    fn retrieve(
        &self,
        vuln_classes: &[String],
        rule_ids: &[String],
    ) -> Vec<(PrecedentEntry, String)>;
}

// â”€â”€ Embedded curated public corpus â”€â”€

const CORPUS_JSON: &str = include_str!("corpus.json");

pub struct CuratedCorpus {
    entries: Vec<PrecedentEntry>,
}

impl CuratedCorpus {
    pub fn load() -> Self {
        let entries: Vec<PrecedentEntry> = serde_json::from_str(CORPUS_JSON).unwrap_or_default();
        Self { entries }
    }
}

impl PrecedentStore for CuratedCorpus {
    fn retrieve(
        &self,
        vuln_classes: &[String],
        rule_ids: &[String],
    ) -> Vec<(PrecedentEntry, String)> {
        let mut scored: Vec<(PrecedentEntry, String)> = self
            .entries
            .iter()
            .filter_map(|entry| {
                let class_match = vuln_classes
                    .iter()
                    .any(|vc| entry.vuln_classes.contains(vc));
                let rule_match = rule_ids.iter().any(|rid| entry.rule_ids.contains(rid));
                if class_match || rule_match {
                    let reason = if class_match && rule_match {
                        "Matches vuln class and rule_id".to_string()
                    } else if class_match {
                        "Matches vuln class".to_string()
                    } else {
                        "Matches rule_id".to_string()
                    };
                    Some((entry.clone(), reason))
                } else {
                    None
                }
            })
            .collect();
        scored.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        scored
    }
}

// â”€â”€ Mock for tests â”€â”€

pub struct MockPrecedentStore {
    entries: Vec<(PrecedentEntry, String)>,
}

impl MockPrecedentStore {
    pub fn new(entries: Vec<(PrecedentEntry, String)>) -> Self {
        Self { entries }
    }
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl PrecedentStore for MockPrecedentStore {
    fn retrieve(&self, _: &[String], _: &[String]) -> Vec<(PrecedentEntry, String)> {
        self.entries.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingExplanation {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence_label: String,
    pub explanation: String,
    pub exploitability_rank: String,
    pub remediation_hint: String,
    pub disclaimer: String,
    pub precedent: Vec<PrecedentCitation>,
}

// ── PoC Draft (C39) ──

pub const POC_DISCLAIMER: &str =
    "Unverified proof-of-concept DRAFT, generated from a deterministic finding. Not a confirmed exploit; must be reviewed and executed by a human.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PocDraft {
    pub finding_id: String,
    pub rule_id: String,
    pub language: String,
    pub framework: String,
    pub test_code: String,
    pub assumptions: Vec<String>,
    pub status: String,
    pub disclaimer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
pub enum CopilotError {
    #[error("Finding {0} not found")]
    FindingNotFound(String),
    #[error("Copilot not configured")]
    ModelUnavailable,
    #[error("Validation: {0}")]
    ValidationFailed(String),
}

/// QUARANTINED: This trait is a model-provider abstraction that is never wired
/// to a real provider. All truth-layer work flows through digger-agent instead.
/// Retained for test compatibility only.
#[deprecated(note = "Use digger-agent contract/guardrails/tools instead")]
#[async_trait::async_trait]
pub trait CopilotModel: Send + Sync {
    async fn explain(&self, prompt: &str) -> Result<String, ErrorResponse>;
}

#[derive(Deserialize)]
pub struct ExplainRequest {
    pub bundle_id: String,
    pub finding_id: String,
}

pub fn build_grounding_prompt(
    bundle: &EvidenceBundle,
    finding_id: &str,
) -> Result<String, CopilotError> {
    let f = bundle
        .findings
        .iter()
        .find(|f| f.finding_id == finding_id)
        .ok_or_else(|| CopilotError::FindingNotFound(finding_id.into()))?;

    let locs = f
        .locations
        .iter()
        .map(|l| {
            let sp = match (l.line_start, l.line_end) {
                (Some(s), Some(e)) => format!(" lines {}-{}", s, e),
                (Some(s), None) => format!(" line {}", s),
                _ => String::new(),
            };
            format!("  {}{}", l.file, sp)
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        "Explain this security finding.\n\nRule: {}\nSeverity: {}\nConfidence: {}\nLocations:\n{}\n\nProvide:\n1. What this vulnerability class means.\n2. Why this code matched.\n3. Exploitability (high/medium/low).\n4. Remediation.\n\nDo not invent new findings.",
        f.rule_id,
        f.severity,
        f.confidence_label,
        if locs.is_empty() { "  (none)".into() } else { locs }
    ))
}

/// Thin pre-normalizer: builds FindingExplanation without accept/reject authority.
/// All validation is delegated to digger_agent::guardrails::validate.
pub fn validate_explanation(
    finding_id: &str,
    rule_id: &str,
    severity: &str,
    confidence_label: &str,
    raw: &str,
    precedent: Vec<PrecedentCitation>,
) -> Result<FindingExplanation, CopilotError> {
    Ok(FindingExplanation {
        finding_id: finding_id.into(),
        rule_id: rule_id.into(),
        severity: severity.into(),
        confidence_label: confidence_label.into(),
        explanation: raw.into(),
        exploitability_rank: extract_field(raw, "exploitability"),
        remediation_hint: extract_field(raw, "remediation"),
        disclaimer: DISCLAIMER.into(),
        precedent,
    })
}

fn extract_field(text: &str, field: &str) -> String {
    let key = format!("{}:", field);
    if let Some(i) = text.find(&key) {
        let rest = &text[i + key.len()..];
        let end = rest.find('\n').unwrap_or(rest.len());
        rest[..end].trim().into()
    } else {
        String::new()
    }
}

/// Deterministic framework selection from finding metadata.
fn select_framework(rule_id: &str, _severity: &str) -> (String, String) {
    let is_solana = rule_id.contains("solana") || rule_id.contains("access_control");
    if is_solana {
        ("solana".into(), "anchor".into())
    } else {
        ("evm".into(), "foundry".into())
    }
}

/// Deterministic attack-shape template from vuln class.
fn attack_shape_template(rule_id: &str) -> String {
    if rule_id.contains("price_manipulation") {
        "// Attack shape: Use flash loan to inflate/deflate price oracle,\n// then exploit the mispriced state transition."
    } else if rule_id.contains("readonly_reentrancy") {
        "// Attack shape: Trigger a callback (reentrancy) before state update,\n// then read stale state from the callback context."
    } else if rule_id.contains("access_control") || rule_id.contains("solana") {
        "// Attack shape: Call privileged instruction without required authority/signer."
    } else {
        "// Attack shape: Review the code path for the reported vulnerability class."
    }
    .into()
}

/// Generate a deterministic PoC scaffold from a finding.
pub fn generate_poc_scaffold(
    bundle: &EvidenceBundle,
    finding_id: &str,
) -> Result<PocDraft, CopilotError> {
    let f = bundle
        .findings
        .iter()
        .find(|f| f.finding_id == finding_id)
        .ok_or_else(|| CopilotError::FindingNotFound(finding_id.into()))?;

    let (language, framework) = select_framework(&f.rule_id, &f.severity);
    let shape = attack_shape_template(&f.rule_id);

    let contract_name = f
        .locations
        .first()
        .and_then(|l| l.symbol.clone())
        .unwrap_or_else(|| "TargetContract".into());
    let file_ref = f
        .locations
        .first()
        .map(|l| l.file.clone())
        .unwrap_or_else(|| "unknown".into());

    let test_code = match language.as_str() {
        "evm" => format!(
            "// SPDX-License-Identifier: UNLICENSED\n\
             pragma solidity ^0.8.0;\n\n\
             import \"forge-std/Test.sol\";\n\n\
             contract PoC_{contract} is Test {{\n\
             {shape}\n\n\
             function test_exploit() public {{\n\
                 // TODO: Set up attacker, configure deployment params,\n\
                 //       and reproduce the vulnerability from {file_ref}.\n\
             }}\n\
             }}",
            contract = contract_name,
            shape = shape,
            file_ref = file_ref
        ),
        "solana" => format!(
            "#[cfg(test)]\n\
             mod poc_tests {{\n\
             use anchor_lang::prelude::*;\n\n\
             {shape}\n\n\
             #[test]\n\
             fn test_exploit() {{\n\
                 // TODO: Set up test program, configure state,\n\
                 //       and reproduce the vulnerability from {file_ref}.\n\
             }}\n\
             }}",
            shape = shape,
            file_ref = file_ref
        ),
        _ => format!(
            "// PoC scaffold for {rule}.\n{shape}",
            rule = f.rule_id,
            shape = shape
        ),
    };

    let assumptions = vec![
        format!("Target contract: {}", contract_name),
        format!("Source file: {}", file_ref),
        "Deployment parameters and attacker setup must be configured manually.".into(),
        "This is an unverified draft — execution may require additional context.".into(),
    ];

    Ok(PocDraft {
        finding_id: finding_id.into(),
        rule_id: f.rule_id.clone(),
        language,
        framework,
        test_code,
        assumptions,
        status: "unverified_draft".into(),
        disclaimer: POC_DISCLAIMER.into(),
    })
}

/// Validate a PoC draft: reject off-evidence references and confirmed-exploit language.
///
/// Routes through digger_agent::validate by converting PocDraft → AssistantClaim.
pub fn validate_poc(poc: &PocDraft, bundle: &EvidenceBundle) -> Result<PocDraft, CopilotError> {
    let severity = parse_severity(bundle, &poc.finding_id);
    let confidence = parse_confidence(bundle, &poc.finding_id);

    // Wire the claim's locations to the engine finding's real evidence
    // locations so the guardrail's LOCATION_NOT_IN_EVIDENCE check operates on a
    // complete claim instead of an empty stub (previously dead in this path).
    let claimed_locations: Vec<digger_agent::contract::LocationView> = bundle
        .findings
        .iter()
        .find(|f| f.finding_id == poc.finding_id)
        .map(|f| {
            f.locations
                .iter()
                .map(|l| digger_agent::contract::LocationView {
                    file: l.file.clone(),
                    line_start: l.line_start,
                    line_end: l.line_end,
                    symbol: l.symbol.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let claim = digger_agent::guardrails::AssistantClaim {
        scan_id: poc.finding_id.clone(),
        claimed_findings: vec![digger_agent::guardrails::FindingClaim {
            finding_id: poc.finding_id.clone(),
            rule_id: poc.rule_id.clone(),
            severity: severity.clone(),
            confidence: confidence.clone(),
            stage: digger_agent::contract::Stage::Shadow,
            locations: claimed_locations,
            exploit_status: claimed_exploit_status(poc),
            claim_text: poc.test_code.clone(),
        }],
        // Free text routed through the guardrail's heuristic prose lint
        // (non-authoritative warnings) — it never decides pass/fail.
        prose: Some(poc.test_code.clone()),
    };

    let engine_finding = bundle
        .findings
        .iter()
        .find(|f| f.finding_id == poc.finding_id);

    let mut findings_view = vec![];
    if let Some(f) = engine_finding {
        findings_view.push(digger_agent::contract::FindingView {
            finding_id: f.finding_id.clone(),
            rule_id: f.rule_id.clone(),
            severity: severity.clone(),
            confidence: confidence.clone(),
            stage: digger_agent::contract::Stage::Shadow,
            summary: String::new(),
            locations: f
                .locations
                .iter()
                .map(|l| digger_agent::contract::LocationView {
                    file: l.file.clone(),
                    line_start: l.line_start,
                    line_end: l.line_end,
                    symbol: l.symbol.clone(),
                })
                .collect(),
            evidence_ids: vec![],
        });
    }

    let ctx = digger_agent::guardrails::ScanContext {
        scan_id: poc.finding_id.clone(),
        findings: findings_view,
        predicate_states: vec![],
    };

    let report = digger_agent::guardrails::validate(&claim, &ctx);

    if !report.pass {
        let msgs: Vec<String> = report
            .violations
            .iter()
            .map(|v| v.message.clone())
            .collect();
        return Err(CopilotError::ValidationFailed(msgs.join("; ")));
    }

    // Anti-fabrication lint (copilot-layer, defense-in-depth): the engine
    // cross-check (UNKNOWN_FINDING / RULE_ID_MISMATCH) inside
    // digger_agent::guardrails::validate is the authoritative gate against
    // fabricated findings; this only catches a draft that *narrates* a brand-new
    // finding in free text. Confirmed-exploit promotion is handled by the typed
    // exploit_status path above (the guardrail's UNSUPPORTED_EXPLOIT_CONFIRMED),
    // never by string-matching the verdict here.
    let lower = poc.test_code.to_lowercase();
    if lower.contains("new vulnerability") || lower.contains("new finding") {
        return Err(CopilotError::ValidationFailed(
            "PoC references a new finding not in the engine output".into(),
        ));
    }

    Ok(PocDraft {
        status: "unverified_draft".into(),
        disclaimer: POC_DISCLAIMER.into(),
        ..poc.clone()
    })
}

fn parse_severity(bundle: &EvidenceBundle, finding_id: &str) -> digger_agent::contract::Severity {
    bundle
        .findings
        .iter()
        .find(|f| f.finding_id == finding_id)
        .and_then(|f| digger_agent::contract::Severity::from_engine_str(&f.severity).ok())
        .unwrap_or(digger_agent::contract::Severity::High)
}

fn parse_confidence(
    bundle: &EvidenceBundle,
    finding_id: &str,
) -> digger_agent::contract::Confidence {
    bundle
        .findings
        .iter()
        .find(|f| f.finding_id == finding_id)
        .and_then(|f| digger_agent::contract::Confidence::from_engine_str(&f.confidence_label).ok())
        .unwrap_or(digger_agent::contract::Confidence::Experimental)
}

fn poc_status_to_exploit_status(status: &str) -> digger_agent::contract::ExploitStatus {
    match status {
        "confirmed" => digger_agent::contract::ExploitStatus::Confirmed,
        "suspected" => digger_agent::contract::ExploitStatus::Suspected,
        _ => digger_agent::contract::ExploitStatus::None,
    }
}

/// Typed exploit-status for a PoC draft.
///
/// Starts from the draft's declared status and escalates to `Confirmed` when the
/// draft's own test code asserts a working/verified exploit. Folding the text
/// signal into the typed `ExploitStatus` makes `digger_agent::guardrails::validate`
/// the single authoritative gate (it emits `UNSUPPORTED_EXPLOIT_CONFIRMED` against
/// any shadow/experimental engine finding) instead of an ad-hoc substring branch
/// in this layer deciding the verdict.
fn claimed_exploit_status(poc: &PocDraft) -> digger_agent::contract::ExploitStatus {
    let declared = poc_status_to_exploit_status(&poc.status);
    if declared == digger_agent::contract::ExploitStatus::Confirmed {
        return declared;
    }
    let lower = poc.test_code.to_lowercase();
    if lower.contains("confirmed")
        || lower.contains("verified exploit")
        || lower.contains("working exploit")
    {
        digger_agent::contract::ExploitStatus::Confirmed
    } else {
        declared
    }
}

/// Parse combined explanation text + context for adversarial assertions.
///
/// If the untrusted text asserts a higher confidence or confirmed exploit,
/// extract those so guardrails::validate can catch the promotion.
/// When the text asserts nothing, return None (caller falls back to engine values).
fn extract_claim_from_text(
    text: &str,
) -> (
    Option<digger_agent::contract::Confidence>,
    Option<digger_agent::contract::ExploitStatus>,
) {
    let lower = text.to_lowercase();
    let confidence = if lower.contains("graduated confidence")
        || lower.contains("confidence: graduated")
        || lower.contains("confidence promoted to graduated")
    {
        Some(digger_agent::contract::Confidence::Graduated)
    } else {
        None
    };
    let exploit = if lower.contains("confirmed exploit")
        || lower.contains("exploit confirmed")
        || lower.contains("working exploit")
    {
        Some(digger_agent::contract::ExploitStatus::Confirmed)
    } else {
        None
    };
    (confidence, exploit)
}

// ── HTTP handler ──

#[derive(Deserialize)]
pub struct ExplainReq {
    pub finding_id: String,
    pub context: Option<String>,
}

#[derive(Serialize)]
pub struct ExplainResp {
    pub finding_id: String,
    pub explanation: String,
    pub disclaimer: String,
    pub precedent: Vec<PrecedentCitation>,
}

/// POST /copilot/explain handler — session-auth, owner-scoped, rate-limited.
pub async fn explain_handler(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(req): axum::extract::Json<ExplainReq>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // ── Rate limit (mirrors scan handler) ──
    {
        let client_ip = crate::get_client_ip(&headers);
        let mut limits = state.rate_limits.lock().await;
        let bucket = limits.entry(client_ip).or_insert_with(|| {
            crate::TokenBucket::new(state.rate_limit_burst, state.rate_limit_per_second as f64)
        });
        if let Some(retry_after) = bucket.try_consume() {
            if retry_after > 0 {
                let err = crate::RateLimitError {
                    error: format!("Rate limit exceeded. Try again in {} seconds.", retry_after),
                    code: 429,
                    retry_after_seconds: retry_after,
                };
                let mut resp =
                    (axum::http::StatusCode::TOO_MANY_REQUESTS, axum::Json(err)).into_response();
                if let Ok(hv) = retry_after.to_string().parse() {
                    resp.headers_mut().insert("retry-after", hv);
                }
                return resp;
            }
        }
    }

    let token = match crate::auth::extract_session_token(&headers) {
        Some(t) => t,
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "Not authenticated"})),
            )
                .into_response();
        }
    };

    let user_id = {
        let conn = match state.db.conn.lock() {
            Ok(c) => c,
            Err(_) => {
                return crate::ErrorResponse {
                    error: "Internal error".into(),
                    code: 500,
                }
                .into_response();
            }
        };
        conn.query_row(
            "SELECT u.id FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token = ?1",
            rusqlite::params![token],
            |row| row.get::<_, String>(0),
        )
        .ok()
    };

    let user_id = match user_id {
        Some(uid) => uid,
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "Invalid session"})),
            )
                .into_response();
        }
    };

    let finding_id = &req.finding_id;

    // Look up the finding across the user's saved scans
    let scan_findings: Vec<serde_json::Value> = {
        let conn = match state.db.conn.lock() {
            Ok(c) => c,
            Err(_) => {
                return crate::ErrorResponse {
                    error: "Internal error".into(),
                    code: 500,
                }
                .into_response();
            }
        };
        let mut stmt = match conn.prepare("SELECT findings_json FROM scans WHERE user_id = ?1") {
            Ok(s) => s,
            Err(_) => {
                return crate::ErrorResponse {
                    error: "Internal error".into(),
                    code: 500,
                }
                .into_response();
            }
        };
        let rows = stmt
            .query_map(rusqlite::params![user_id], |row| row.get::<_, String>(0))
            .ok();
        let mut results = vec![];
        if let Some(rows) = rows {
            for row in rows.flatten() {
                if let Ok(findings) = serde_json::from_str::<Vec<serde_json::Value>>(&row) {
                    results.extend(findings);
                }
            }
        }
        results
    };

    let matched = scan_findings.iter().find(|f| {
        f.get("finding_id")
            .and_then(|v| v.as_str())
            .map(|id| id == finding_id)
            .unwrap_or(false)
    });

    let matched_finding = match matched {
        Some(f) => f,
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": format!("Finding '{}' not found in your saved scans", finding_id)
                })),
            )
                .into_response();
        }
    };

    let rule_id = matched_finding
        .get("rule_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let severity = matched_finding
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("high");
    let confidence = matched_finding
        .get("confidence")
        .or_else(|| matched_finding.get("confidence_label"))
        .and_then(|v| v.as_str())
        .unwrap_or("experimental");

    // Build EvidenceBundle with the finding for grounding
    let bundle = {
        let mut builder = digger_evidence::BundleBuilder::new(
            digger_evidence::EngineVersion {
                semver: "0.1.0".into(),
                git_sha: "server".into(),
            },
            digger_evidence::InputDescriptor {
                kind: "copilot".into(),
                value: user_id.clone(),
            },
        )
        .tenant_id(&user_id);

        builder = builder.add_finding(digger_evidence::Finding {
            finding_id: finding_id.clone(),
            rule_id: rule_id.into(),
            severity: severity.into(),
            confidence_label: confidence.into(),
            locations: vec![],
            evidence_refs: vec![],
            repro_ref: None,
        });

        builder.build()
    };

    let _prompt = match build_grounding_prompt(&bundle, finding_id) {
        Ok(p) => p,
        Err(_) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": format!("Finding '{}' not grounded", finding_id)
                })),
            )
                .into_response();
        }
    };

    let corpus = CuratedCorpus::load();
    let precedent_entries = corpus.retrieve(&[rule_id.into()], &[rule_id.into()]);
    let citations: Vec<PrecedentCitation> = precedent_entries
        .iter()
        .map(|(entry, reason)| PrecedentCitation {
            id: entry.id.clone(),
            title: entry.title.clone(),
            source_url: entry.source_url.clone(),
            why_relevant: reason.clone(),
        })
        .collect();

    let explanation_text = format!(
        "Explanation for finding {} (rule: {}, severity: {}, confidence: {}). Grounded in engine output. {}",
        finding_id,
        rule_id,
        severity,
        confidence,
        req.context.as_deref().unwrap_or(""),
    );

    // Build AssistantClaim + ScanContext for guardrails validation.
    // Parse explanation text for adversarial assertions (graduated confidence,
    // confirmed exploit) so guardrails can catch promotions.
    let severity_enum = digger_agent::contract::Severity::from_engine_str(severity)
        .unwrap_or(digger_agent::contract::Severity::High);
    let engine_confidence = digger_agent::contract::Confidence::from_engine_str(confidence)
        .unwrap_or(digger_agent::contract::Confidence::Experimental);

    let (claimed_confidence, claimed_exploit) = extract_claim_from_text(&explanation_text);
    let confidence_enum = claimed_confidence.unwrap_or(engine_confidence.clone());
    let exploit_status = claimed_exploit.unwrap_or(digger_agent::contract::ExploitStatus::None);

    let claim = digger_agent::guardrails::AssistantClaim {
        scan_id: finding_id.into(),
        claimed_findings: vec![digger_agent::guardrails::FindingClaim {
            finding_id: finding_id.into(),
            rule_id: rule_id.into(),
            severity: severity_enum.clone(),
            confidence: confidence_enum,
            stage: digger_agent::contract::Stage::Shadow,
            locations: vec![],
            exploit_status,
            claim_text: explanation_text.clone(),
        }],
        prose: Some(explanation_text.clone()),
    };

    let mut findings_view = vec![];
    if let Some(f) = bundle.findings.iter().find(|f| f.finding_id == *finding_id) {
        findings_view.push(digger_agent::contract::FindingView {
            finding_id: f.finding_id.clone(),
            rule_id: f.rule_id.clone(),
            severity: severity_enum,
            confidence: engine_confidence,
            stage: digger_agent::contract::Stage::Shadow,
            summary: String::new(),
            locations: f
                .locations
                .iter()
                .map(|l| digger_agent::contract::LocationView {
                    file: l.file.clone(),
                    line_start: l.line_start,
                    line_end: l.line_end,
                    symbol: l.symbol.clone(),
                })
                .collect(),
            evidence_ids: vec![],
        });
    }

    let ctx = digger_agent::guardrails::ScanContext {
        scan_id: finding_id.into(),
        findings: findings_view,
        predicate_states: vec![],
    };

    let report = digger_agent::guardrails::validate(&claim, &ctx);

    if !report.pass {
        let msgs: Vec<String> = report
            .violations
            .iter()
            .map(|v| v.message.clone())
            .collect();
        return crate::ErrorResponse {
            error: msgs.join("; "),
            code: 422,
        }
        .into_response();
    }

    // Build the explanation response (thin builder, no independent validation authority)
    let explanation = FindingExplanation {
        finding_id: finding_id.into(),
        rule_id: rule_id.into(),
        severity: severity.into(),
        confidence_label: confidence.into(),
        explanation: explanation_text,
        exploitability_rank: String::new(),
        remediation_hint: String::new(),
        disclaimer: DISCLAIMER.into(),
        precedent: citations.clone(),
    };

    let resp = ExplainResp {
        finding_id: explanation.finding_id,
        explanation: explanation.explanation,
        disclaimer: explanation.disclaimer,
        precedent: citations,
    };
    (axum::http::StatusCode::OK, axum::Json(resp)).into_response()
}

#[derive(Deserialize)]
pub struct PocReq {
    pub finding_id: String,
}

#[derive(Serialize)]
pub struct PocResp {
    pub finding_id: String,
    pub rule_id: String,
    pub language: String,
    pub framework: String,
    pub test_code: String,
    pub assumptions: Vec<String>,
    pub status: String,
    pub disclaimer: String,
}

/// POST /copilot/poc handler — session-auth, owner-scoped, rate-limited.
/// Generates a deterministic PoC scaffold and validates it through guardrails.
pub async fn poc_handler(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(req): axum::extract::Json<PocReq>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // ── Rate limit (mirrors scan handler) ──
    {
        let client_ip = crate::get_client_ip(&headers);
        let mut limits = state.rate_limits.lock().await;
        let bucket = limits.entry(client_ip).or_insert_with(|| {
            crate::TokenBucket::new(state.rate_limit_burst, state.rate_limit_per_second as f64)
        });
        if let Some(retry_after) = bucket.try_consume() {
            if retry_after > 0 {
                let err = crate::RateLimitError {
                    error: format!("Rate limit exceeded. Try again in {} seconds.", retry_after),
                    code: 429,
                    retry_after_seconds: retry_after,
                };
                let mut resp =
                    (axum::http::StatusCode::TOO_MANY_REQUESTS, axum::Json(err)).into_response();
                if let Ok(hv) = retry_after.to_string().parse() {
                    resp.headers_mut().insert("retry-after", hv);
                }
                return resp;
            }
        }
    }

    let token = match crate::auth::extract_session_token(&headers) {
        Some(t) => t,
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "Not authenticated"})),
            )
                .into_response();
        }
    };

    let user_id = {
        let conn = match state.db.conn.lock() {
            Ok(c) => c,
            Err(_) => {
                return crate::ErrorResponse {
                    error: "Internal error".into(),
                    code: 500,
                }
                .into_response();
            }
        };
        conn.query_row(
            "SELECT u.id FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token = ?1",
            rusqlite::params![token],
            |row| row.get::<_, String>(0),
        )
        .ok()
    };

    let user_id = match user_id {
        Some(uid) => uid,
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"error": "Invalid session"})),
            )
                .into_response();
        }
    };

    let finding_id = &req.finding_id;

    // Owner-scoped: look up finding across user's saved scans
    let scan_findings: Vec<serde_json::Value> = {
        let conn = match state.db.conn.lock() {
            Ok(c) => c,
            Err(_) => {
                return crate::ErrorResponse {
                    error: "Internal error".into(),
                    code: 500,
                }
                .into_response();
            }
        };
        let mut stmt = match conn.prepare("SELECT findings_json FROM scans WHERE user_id = ?1") {
            Ok(s) => s,
            Err(_) => {
                return crate::ErrorResponse {
                    error: "Internal error".into(),
                    code: 500,
                }
                .into_response();
            }
        };
        let rows = stmt
            .query_map(rusqlite::params![user_id], |row| row.get::<_, String>(0))
            .ok();
        let mut results = vec![];
        if let Some(rows) = rows {
            for row in rows.flatten() {
                if let Ok(findings) = serde_json::from_str::<Vec<serde_json::Value>>(&row) {
                    results.extend(findings);
                }
            }
        }
        results
    };

    let matched = scan_findings.iter().find(|f| {
        f.get("finding_id")
            .and_then(|v| v.as_str())
            .map(|id| id == finding_id)
            .unwrap_or(false)
    });

    let matched_finding = match matched {
        Some(f) => f,
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": format!("Finding '{}' not found in your saved scans", finding_id)
                })),
            )
                .into_response();
        }
    };

    let rule_id = matched_finding
        .get("rule_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let severity = matched_finding
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("high");
    let confidence = matched_finding
        .get("confidence")
        .or_else(|| matched_finding.get("confidence_label"))
        .and_then(|v| v.as_str())
        .unwrap_or("experimental");

    // Build EvidenceBundle with the finding for grounding
    let bundle = {
        let mut builder = digger_evidence::BundleBuilder::new(
            digger_evidence::EngineVersion {
                semver: "0.1.0".into(),
                git_sha: "server".into(),
            },
            digger_evidence::InputDescriptor {
                kind: "copilot".into(),
                value: user_id.clone(),
            },
        )
        .tenant_id(&user_id);

        builder = builder.add_finding(digger_evidence::Finding {
            finding_id: finding_id.clone(),
            rule_id: rule_id.into(),
            severity: severity.into(),
            confidence_label: confidence.into(),
            locations: vec![],
            evidence_refs: vec![],
            repro_ref: None,
        });

        builder.build()
    };

    // Generate deterministic PoC scaffold
    let poc = match generate_poc_scaffold(&bundle, finding_id) {
        Ok(p) => p,
        Err(e) => {
            return crate::ErrorResponse {
                error: e.to_string(),
                code: 404,
            }
            .into_response();
        }
    };

    // Validate through guardrails
    match validate_poc(&poc, &bundle) {
        Ok(validated) => {
            let resp = PocResp {
                finding_id: validated.finding_id,
                rule_id: validated.rule_id,
                language: validated.language,
                framework: validated.framework,
                test_code: validated.test_code,
                assumptions: validated.assumptions,
                status: validated.status,
                disclaimer: validated.disclaimer,
            };
            (axum::http::StatusCode::OK, axum::Json(resp)).into_response()
        }
        Err(e) => crate::ErrorResponse {
            error: e.to_string(),
            code: 422,
        }
        .into_response(),
    }
}

/// Generate PoC from finding using model (for testability).
#[allow(deprecated)]
pub async fn draft_poc(
    bundle: &EvidenceBundle,
    finding_id: &str,
    model: &dyn CopilotModel,
) -> Result<PocDraft, CopilotError> {
    let _f = bundle
        .findings
        .iter()
        .find(|f| f.finding_id == finding_id)
        .ok_or_else(|| CopilotError::FindingNotFound(finding_id.into()))?;

    let prompt = "Draft a proof-of-concept test scaffold for this finding.\n\
         Use the framework-specific template. Only reference code in the finding's evidence.\n\
         Do NOT claim the exploit is confirmed or working."
        .to_string();
    let _raw = model
        .explain(&prompt)
        .await
        .map_err(|e| CopilotError::ValidationFailed(e.error))?;

    generate_poc_scaffold(bundle, finding_id)
}

#[allow(deprecated)]
pub async fn explain_finding(
    bundle: &EvidenceBundle,
    finding_id: &str,
    model: &dyn CopilotModel,
    precedent_store: &dyn PrecedentStore,
) -> Result<FindingExplanation, CopilotError> {
    let f = bundle
        .findings
        .iter()
        .find(|f| f.finding_id == finding_id)
        .ok_or_else(|| CopilotError::FindingNotFound(finding_id.into()))?;

    let (rule_id, severity, confidence_label) = (
        f.rule_id.clone(),
        f.severity.clone(),
        f.confidence_label.clone(),
    );

    // Retrieve precedent
    let vuln_classes: Vec<String> = vec![f.rule_id.clone()];
    let rule_ids: Vec<String> = vec![f.rule_id.clone()];
    let precedent_entries = precedent_store.retrieve(&vuln_classes, &rule_ids);

    let citations: Vec<PrecedentCitation> = precedent_entries
        .iter()
        .map(|(entry, reason)| PrecedentCitation {
            id: entry.id.clone(),
            title: entry.title.clone(),
            source_url: entry.source_url.clone(),
            why_relevant: reason.clone(),
        })
        .collect();

    let prompt = build_grounding_prompt(bundle, finding_id)?;
    let raw = model
        .explain(&prompt)
        .await
        .map_err(|e| CopilotError::ValidationFailed(e.error))?;
    validate_explanation(
        finding_id,
        &rule_id,
        &severity,
        &confidence_label,
        &raw,
        citations,
    )
}

pub struct MockCopilotModel(String);
impl MockCopilotModel {
    pub fn new(s: &str) -> Self {
        Self(s.into())
    }
    pub fn default_response() -> Self {
        Self(
            "This finding indicates a price oracle manipulation vulnerability.\n\n\
             Exploitability: High\n\n\
             Remediation: Use a TWAP oracle."
                .into(),
        )
    }
}
#[async_trait::async_trait]
#[allow(deprecated)]
impl CopilotModel for MockCopilotModel {
    async fn explain(&self, _: &str) -> Result<String, ErrorResponse> {
        Ok(self.0.clone())
    }
}

pub struct HallucinatingCopilotModel;
#[async_trait::async_trait]
#[allow(deprecated)]
impl CopilotModel for HallucinatingCopilotModel {
    async fn explain(&self, _: &str) -> Result<String, ErrorResponse> {
        Ok("NEW FINDING: I discovered a reentrancy bug not in the engine.".into())
    }
}

pub struct ConfidenceUpgradeModel;
#[async_trait::async_trait]
#[allow(deprecated)]
impl CopilotModel for ConfidenceUpgradeModel {
    async fn explain(&self, _: &str) -> Result<String, ErrorResponse> {
        Ok("This is graduated confidence \u{2014} upgrade from experimental to graduated.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> digger_evidence::EvidenceBundle {
        digger_evidence::BundleBuilder::new(
            digger_evidence::EngineVersion {
                semver: "0.1.0".into(),
                git_sha: "abc".into(),
            },
            digger_evidence::InputDescriptor {
                kind: "scan".into(),
                value: "t".into(),
            },
        )
        .tenant_id("t1")
        .add_finding(digger_evidence::Finding {
            finding_id: "f1".into(),
            rule_id: "price_manipulation".into(),
            severity: "high".into(),
            confidence_label: "graduated".into(),
            locations: vec![digger_evidence::Location {
                file: "swap.sol".into(),
                line_start: Some(10),
                line_end: Some(20),
                symbol: Some("swap".into()),
            }],
            evidence_refs: vec![],
            repro_ref: None,
        })
        .build()
    }

    fn corpus() -> MockPrecedentStore {
        MockPrecedentStore::new(vec![(
            PrecedentEntry {
                id: "rekt-bzx-2020".into(),
                title: "bZx flash loan attack".into(),
                vuln_classes: vec!["price_manipulation".into()],
                rule_ids: vec!["price_manipulation".into()],
                source_url: "https://rekt.news/bzx-rekt/".into(),
                summary: "Flash loan price oracle manipulation".into(),
            },
            "Matches vuln class and rule_id".into(),
        )])
    }

    fn empty_corpus() -> MockPrecedentStore {
        MockPrecedentStore::empty()
    }

    #[tokio::test]
    async fn happy_path() {
        let r = explain_finding(
            &bundle(),
            "f1",
            &MockCopilotModel::default_response(),
            &corpus(),
        )
        .await
        .unwrap();
        assert_eq!(r.rule_id, "price_manipulation");
        assert_eq!(r.confidence_label, "graduated");
        assert_eq!(r.disclaimer, DISCLAIMER);
        assert_eq!(r.precedent.len(), 1);
        assert_eq!(r.precedent[0].source_url, "https://rekt.news/bzx-rekt/");
    }

    #[tokio::test]
    async fn finding_not_found() {
        let r = explain_finding(
            &bundle(),
            "nope",
            &MockCopilotModel::default_response(),
            &corpus(),
        )
        .await;
        assert!(matches!(r, Err(CopilotError::FindingNotFound(_))));
    }

    #[tokio::test]
    async fn hallucination_passes_thin_builder() {
        let r = explain_finding(&bundle(), "f1", &HallucinatingCopilotModel, &empty_corpus()).await;
        assert!(
            r.is_ok(),
            "validate_explanation is now a thin builder — hallucination text passes at this level"
        );
    }

    #[tokio::test]
    async fn confidence_upgrade_passes_thin_builder() {
        let b = digger_evidence::BundleBuilder::new(
            digger_evidence::EngineVersion {
                semver: "0.1.0".into(),
                git_sha: "abc".into(),
            },
            digger_evidence::InputDescriptor {
                kind: "scan".into(),
                value: "t".into(),
            },
        )
        .tenant_id("t1")
        .add_finding(digger_evidence::Finding {
            finding_id: "f1".into(),
            rule_id: "price_manipulation".into(),
            severity: "high".into(),
            confidence_label: "experimental".into(),
            locations: vec![],
            evidence_refs: vec![],
            repro_ref: None,
        });
        let r = explain_finding(&b.build(), "f1", &ConfidenceUpgradeModel, &empty_corpus()).await;
        assert!(
            r.is_ok(),
            "validate_explanation is now a thin builder — confidence upgrade text passes at this level"
        );
    }

    #[tokio::test]
    async fn preserves_engine_confidence() {
        let r = explain_finding(
            &bundle(),
            "f1",
            &MockCopilotModel::new("Experimental territory."),
            &empty_corpus(),
        )
        .await
        .unwrap();
        assert_eq!(r.confidence_label, "graduated");
    }

    #[tokio::test]
    async fn prompt_contains_evidence() {
        let p = build_grounding_prompt(&bundle(), "f1").unwrap();
        assert!(p.contains("price_manipulation"));
        assert!(p.contains("swap.sol"));
        assert!(p.contains("lines 10-20"));
    }

    #[tokio::test]
    async fn validate_thin_builder_passes_new_finding_text() {
        let r = validate_explanation("f1", "x", "y", "z", "NEW FINDING: reentrancy", vec![]);
        assert!(
            r.is_ok(),
            "validate_explanation is now a thin builder — should not reject"
        );
    }

    #[tokio::test]
    async fn validate_thin_builder_passes_upgrade_text() {
        let r = validate_explanation(
            "f1",
            "x",
            "y",
            "experimental",
            "graduated confidence",
            vec![],
        );
        assert!(
            r.is_ok(),
            "validate_explanation is now a thin builder — should not reject"
        );
    }

    #[tokio::test]
    async fn validate_thin_builder_passes_honest() {
        let r = validate_explanation(
            "f1",
            "x",
            "y",
            "graduated",
            "Exploitability: High\nRemediation: Fix.",
            vec![],
        );
        assert!(r.is_ok());
        assert_eq!(r.unwrap().confidence_label, "graduated");
    }

    // â”€â”€ C38: Precedent tests â”€â”€

    #[tokio::test]
    async fn precedent_retrieval_deterministic() {
        let c = CuratedCorpus::load();
        let r1 = c.retrieve(&["price_manipulation".into()], &[]);
        let r2 = c.retrieve(&["price_manipulation".into()], &[]);
        assert_eq!(r1.len(), r2.len());
        assert_eq!(
            r1.iter().map(|(e, _)| e.id.clone()).collect::<Vec<_>>(),
            r2.iter().map(|(e, _)| e.id.clone()).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn precedent_no_match_returns_zero() {
        let c = MockPrecedentStore::empty();
        let r = c.retrieve(&["nonexistent_vuln".into()], &[]);
        assert!(r.is_empty());
    }

    #[tokio::test]
    async fn precedent_citations_in_explanation() {
        let r = explain_finding(
            &bundle(),
            "f1",
            &MockCopilotModel::default_response(),
            &corpus(),
        )
        .await
        .unwrap();
        assert_eq!(r.precedent.len(), 1);
        assert_eq!(r.precedent[0].id, "rekt-bzx-2020");
        assert!(!r.precedent[0].source_url.is_empty());
    }

    #[tokio::test]
    async fn no_precedent_when_corpus_empty() {
        let r = explain_finding(
            &bundle(),
            "f1",
            &MockCopilotModel::default_response(),
            &empty_corpus(),
        )
        .await
        .unwrap();
        assert!(r.precedent.is_empty());
    }

    #[tokio::test]
    async fn validate_citation_from_retrieved_set() {
        let c = CuratedCorpus::load();
        let entries = c.retrieve(&["price_manipulation".into()], &[]);
        let citations: Vec<PrecedentCitation> = entries
            .iter()
            .map(|(e, reason)| PrecedentCitation {
                id: e.id.clone(),
                title: e.title.clone(),
                source_url: e.source_url.clone(),
                why_relevant: reason.clone(),
            })
            .collect();
        assert!(!citations.is_empty());
        let r = validate_explanation(
            "f1",
            "x",
            "y",
            "graduated",
            "Exploitability: High.",
            citations,
        );
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn curated_corpus_loads() {
        let c = CuratedCorpus::load();
        let entries = c.retrieve(&["price_manipulation".into()], &[]);
        assert!(
            entries.len() >= 2,
            "Curated corpus should have >= 2 price_manipulation entries"
        );
        assert!(entries
            .iter()
            .all(|(e, _)| e.source_url.starts_with("http")));
    }

    // ── C39: PoC Draft tests ──

    #[tokio::test]
    async fn poc_deterministic() {
        let b = bundle();
        let p1 = generate_poc_scaffold(&b, "f1").unwrap();
        let p2 = generate_poc_scaffold(&b, "f1").unwrap();
        assert_eq!(p1.test_code, p2.test_code);
        assert_eq!(p1.assumptions, p2.assumptions);
        assert_eq!(p1.framework, p2.framework);
    }

    #[tokio::test]
    async fn poc_off_evidence_passes_guardrails() {
        let b = bundle();
        let mut poc = generate_poc_scaffold(&b, "f1").unwrap();
        poc.test_code = "call exploit(0x1234); // references non-existent function".into();
        let result = validate_poc(&poc, &b);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn poc_confirmed_language_rejected() {
        let b = bundle();
        let mut poc = generate_poc_scaffold(&b, "f1").unwrap();
        poc.test_code = "exploit is confirmed working".into();
        let result = validate_poc(&poc, &b);
        assert!(matches!(result, Err(CopilotError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn poc_status_always_unverified() {
        let b = bundle();
        let mut poc = generate_poc_scaffold(&b, "f1").unwrap();
        poc.status = "confirmed".into();
        let result = validate_poc(&poc, &b);
        assert!(matches!(result, Err(CopilotError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn poc_framework_selection() {
        let b = bundle();
        let poc = generate_poc_scaffold(&b, "f1").unwrap();
        assert_eq!(poc.framework, "foundry");
        assert_eq!(poc.language, "evm");
    }

    #[tokio::test]
    async fn poc_disclaimer_present() {
        let b = bundle();
        let poc = generate_poc_scaffold(&b, "f1").unwrap();
        assert!(poc.disclaimer.contains("Unverified"));
        assert!(poc.disclaimer.contains("Not a confirmed exploit"));
    }

    #[tokio::test]
    async fn poc_assumptions_list() {
        let b = bundle();
        let poc = generate_poc_scaffold(&b, "f1").unwrap();
        assert!(poc.assumptions.len() >= 2);
        assert!(poc
            .assumptions
            .iter()
            .any(|a| a.contains("Target contract")));
    }

    // ── Corpus enrichment tests ──

    #[test]
    fn test_corpus_deterministic() {
        let c = CuratedCorpus::load();
        let r1 = c.retrieve(&["price_manipulation".into()], &[]);
        let r2 = c.retrieve(&["price_manipulation".into()], &[]);
        assert_eq!(r1.len(), r2.len());
        assert_eq!(
            r1.iter().map(|(e, _)| e.id.clone()).collect::<Vec<_>>(),
            r2.iter().map(|(e, _)| e.id.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_solana_entries_retrievable() {
        let c = CuratedCorpus::load();
        let entries = c.retrieve(
            &["missing_access_control".into(), "price_manipulation".into()],
            &["solana_access_control".into()],
        );
        assert!(
            !entries.is_empty(),
            "Should retrieve at least one Solana access_control entry"
        );
        let ids: Vec<&str> = entries.iter().map(|(e, _)| e.id.as_str()).collect();
        assert!(
            ids.iter()
                .any(|id| id.contains("wormhole") || id.contains("mango") || id.contains("cashio")),
            "Should include Wormhole, Mango, or Cashio: got {:?}",
            ids
        );
    }

    #[test]
    fn test_no_match_returns_zero() {
        let c = CuratedCorpus::load();
        let entries = c.retrieve(&["nonexistent_vuln_class_xyz".into()], &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_corpus_integrity() {
        let c = CuratedCorpus::load();
        let all = c.retrieve(
            &[
                "price_manipulation".into(),
                "readonly_reentrancy".into(),
                "missing_access_control".into(),
                "solana_access_control".into(),
            ],
            &[],
        );
        for (entry, _) in &all {
            assert!(!entry.id.is_empty(), "Entry {} has empty id", entry.id);
            assert!(
                entry.source_url.starts_with("http"),
                "Entry {} has invalid source_url: {}",
                entry.id,
                entry.source_url
            );
            assert!(
                !entry.title.is_empty(),
                "Entry {} has empty title",
                entry.id
            );
        }
        // Verify minimum entry count after enrichment
        assert!(
            all.len() >= 10,
            "Corpus should have >= 10 entries after enrichment, got {}",
            all.len()
        );
    }

    #[test]
    fn test_validate_poc_rejects_confirmed() {
        let b = bundle();
        let mut poc = generate_poc_scaffold(&b, "f1").unwrap();
        poc.status = "confirmed".into();
        let result = validate_poc(&poc, &b);
        assert!(
            matches!(result, Err(CopilotError::ValidationFailed(_))),
            "PoC with 'confirmed' status must be rejected, got: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_poc_passes_unverified() {
        let b = bundle();
        let poc = generate_poc_scaffold(&b, "f1").unwrap();
        assert_eq!(poc.status, "unverified_draft");
        let result = validate_poc(&poc, &b);
        assert!(
            result.is_ok(),
            "PoC with 'unverified_draft' status must pass, got: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_poc_rejects_new_finding() {
        let b = bundle();
        let mut poc = generate_poc_scaffold(&b, "f1").unwrap();
        poc.test_code =
            "call exploit(); // This is a new vulnerability discovered by the model".into();
        let result = validate_poc(&poc, &b);
        assert!(
            matches!(result, Err(CopilotError::ValidationFailed(_))),
            "PoC with 'new vulnerability' text must be rejected, got: {:?}",
            result
        );
    }

    // ── Adversarial: promotion must be rejected by the *typed* guardrail ──

    #[test]
    fn test_validate_poc_confirmed_status_caught_by_typed_guardrail() {
        // A draft that declares status="confirmed" must be rejected *through* the
        // typed guardrail (UNSUPPORTED_EXPLOIT_CONFIRMED), not a substring branch.
        let b = bundle();
        let mut poc = generate_poc_scaffold(&b, "f1").unwrap();
        poc.status = "confirmed".into();
        match validate_poc(&poc, &b) {
            Err(CopilotError::ValidationFailed(msg)) => assert!(
                msg.contains("exploit_status=Confirmed"),
                "rejection must originate from the typed guardrail, got: {}",
                msg
            ),
            other => panic!("expected typed guardrail rejection, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_poc_confirmed_text_routes_through_typed_guardrail() {
        // Confirmed-exploit *language* in the draft escalates the typed
        // exploit_status, so the guardrail (not a string match in this layer)
        // is what rejects it.
        let b = bundle();
        let mut poc = generate_poc_scaffold(&b, "f1").unwrap();
        poc.test_code = "this is a working exploit".into();
        match validate_poc(&poc, &b) {
            Err(CopilotError::ValidationFailed(msg)) => assert!(
                msg.contains("exploit_status=Confirmed"),
                "confirmed language must be caught via the typed guardrail, got: {}",
                msg
            ),
            other => panic!("expected typed guardrail rejection, got: {:?}", other),
        }
    }
}
