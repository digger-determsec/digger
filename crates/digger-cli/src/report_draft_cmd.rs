use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportDraft {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub draft_id: String,
    pub status: String,
    pub sections: Vec<ReportSection>,
    pub evidence_refs: Vec<String>,
    pub limitations: Vec<String>,
    pub is_finding: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSection {
    pub section_id: String,
    pub title: String,
    pub content: String,
    pub evidence_refs: Vec<String>,
}

pub fn generate_report_draft(
    triage_path: &str,
    verification_path: &str,
    json: bool,
    output: Option<&str>,
) {
    let triage_content = match fs::read_to_string(triage_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading triage: {}", e);
            std::process::exit(1);
        }
    };

    let verification_content = match fs::read_to_string(verification_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading verification: {}", e);
            std::process::exit(1);
        }
    };

    let triage: serde_json::Value = match serde_json::from_str(&triage_content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing triage: {}", e);
            std::process::exit(1);
        }
    };

    let verification: serde_json::Value = match serde_json::from_str(&verification_content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing verification: {}", e);
            std::process::exit(1);
        }
    };

    let correlation_id = triage["correlation_id"]
        .as_str()
        .or_else(|| verification["correlation_id"].as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut sections = Vec::new();
    let mut evidence_refs = Vec::new();

    let funcs = triage["surfaces_scanned"].as_array();
    let func_count = funcs.map(|a| a.len()).unwrap_or(0);

    sections.push(ReportSection {
        section_id: "summary".into(),
        title: "Audit Summary".into(),
        content: format!(
            "This report covers {} function-level surfaces from {}",
            func_count,
            triage["target_repository"].as_str().unwrap_or("unknown")
        ),
        evidence_refs: vec![],
    });

    if let Some(arr) = funcs {
        for f in arr {
            if let Some(name) = f["name"].as_str() {
                if let Some(path) = f["path"].as_str() {
                    evidence_refs.push(format!("{}:{}", path, name));
                }
            }
        }
    }

    let missing = triage["missing_evidence"].as_array();
    let missing_count = missing.map(|a| a.len()).unwrap_or(0);

    if missing_count > 0 {
        sections.push(ReportSection {
            section_id: "missing_evidence".into(),
            title: "Missing Evidence".into(),
            content: format!(
                "{} evidence items could not be determined during triage",
                missing_count
            ),
            evidence_refs: evidence_refs.clone(),
        });
    }

    let hyps = triage["candidate_hypotheses"].as_array();
    let hyp_count = hyps.map(|a| a.len()).unwrap_or(0);
    if hyp_count > 0 {
        let mut prod_text = String::new();
        let mut non_prod_text = String::new();
        if let Some(arr) = hyps {
            for h in arr {
                if let Some(desc) = h["description"].as_str() {
                    let class = h
                        .get("file_class")
                        .and_then(|v| v.as_str())
                        .unwrap_or("production");
                    if class == "production" {
                        prod_text.push_str(&format!("- {}\n", desc));
                    } else {
                        non_prod_text.push_str(&format!("- [{}] {}\n", class, desc));
                    }
                }
            }
        }
        if !prod_text.is_empty() {
            sections.push(ReportSection {
                section_id: "hypotheses".into(),
                title: "Candidate Hypotheses (Production)".into(),
                content: format!("Candidate hypotheses from production files:\n{}", prod_text),
                evidence_refs: evidence_refs.clone(),
            });
        }
        if !non_prod_text.is_empty() {
            sections.push(ReportSection {
                section_id: "hypotheses_test".into(),
                title: "Candidate Hypotheses (Test/Example/Dependency)".into(),
                content: format!(
                    "Candidate hypotheses from non-production files (appendix):\n{}",
                    non_prod_text
                ),
                evidence_refs: evidence_refs.clone(),
            });
        }
    }

    let limitations = triage["limitations"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|l| l["description"].as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let verification_status = verification["status"].as_str().unwrap_or("unknown");

    sections.push(ReportSection {
        section_id: "verification".into(),
        title: "Claim Verification".into(),
        content: format!("Verification status: {}", verification_status),
        evidence_refs: evidence_refs.clone(),
    });

    let report = ReportDraft {
        schema_version: "digger.report_draft.v1".into(),
        digger_version: env!("CARGO_PKG_VERSION").into(),
        report_kind: "report_draft".into(),
        draft_id: format!("rd-{}", &format!("{:x}", djbx33a(triage_path.as_bytes()))),
        status: "draft".into(),
        sections,
        evidence_refs,
        limitations,
        is_finding: false,
    };

    let output_json = match serde_json::to_string_pretty(&report) {
        Ok(s) => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                let enriched = crate::chain_trace::enrich_with_trace(
                    v,
                    &correlation_id,
                    "report_draft",
                    vec![triage_path.to_string(), verification_path.to_string()],
                );
                serde_json::to_string_pretty(&enriched).unwrap_or(s)
            } else {
                s
            }
        }
        Err(e) => {
            eprintln!("Error serializing: {}", e);
            std::process::exit(1);
        }
    };

    if json && output.is_none() {
        println!("{}", output_json);
    }

    if let Some(out_path) = output {
        if let Err(e) = fs::write(out_path, &output_json) {
            eprintln!("Error writing output: {}", e);
            std::process::exit(1);
        }
        println!("Written to: {}", out_path);
    } else if !json {
        println!(
            "Report draft: {} with {} sections (is_finding: false)",
            report.draft_id,
            report.sections.len()
        );
    }
}

fn djbx33a(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}
