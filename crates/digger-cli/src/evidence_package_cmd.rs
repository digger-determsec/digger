use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub package_id: String,
    pub status: String,
    pub chain_refs: ChainRefs,
    pub limitations: Vec<String>,
    pub is_finding: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainRefs {
    pub triage_ref: Option<String>,
    pub verification_ref: Option<String>,
    pub report_draft_ref: Option<String>,
}

pub fn create_evidence_package(
    triage_path: &str,
    verification_path: &str,
    report_draft_path: Option<&str>,
    hypothesis_path: Option<&str>,
    proof_task_path: Option<&str>,
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

    let mut all_events: Vec<serde_json::Value> = Vec::new();
    for src in [&triage, &verification] {
        if let Some(events) = src["audit_events"].as_array() {
            for e in events {
                all_events.push(e.clone());
            }
        }
    }
    for extra_path in [hypothesis_path, proof_task_path].iter().flatten() {
        if let Ok(content) = fs::read_to_string(extra_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(events) = val["audit_events"].as_array() {
                    for e in events {
                        all_events.push(e.clone());
                    }
                }
            }
        }
    }
    if let Some(ref rd_path) = report_draft_path {
        if let Ok(rd_content) = fs::read_to_string(rd_path) {
            if let Ok(rd_val) = serde_json::from_str::<serde_json::Value>(&rd_content) {
                if let Some(events) = rd_val["audit_events"].as_array() {
                    for e in events {
                        all_events.push(e.clone());
                    }
                }
            }
        }
    }

    let report_draft_ref = if let Some(rd_path) = report_draft_path {
        if fs::read_to_string(rd_path).is_ok() {
            Some(rd_path.to_string())
        } else {
            None
        }
    } else {
        None
    };

    let verification_status = verification["status"].as_str().unwrap_or("unknown");

    let limitations = vec![
        "Evidence package is a planning-only artifact. No runtime packaging implemented.".into(),
        format!("Verification status: {}", verification_status),
    ];

    let package = EvidencePackage {
        schema_version: "digger.evidence_package.v1".into(),
        digger_version: env!("CARGO_PKG_VERSION").into(),
        report_kind: "evidence_package".into(),
        package_id: format!("ep-{}", &format!("{:x}", djbx33a(triage_path.as_bytes()))),
        status: "assembled".into(),
        chain_refs: ChainRefs {
            triage_ref: Some(triage_path.to_string()),
            verification_ref: Some(verification_path.to_string()),
            report_draft_ref,
        },
        limitations,
        is_finding: false,
    };

    let output_json = match serde_json::to_string_pretty(&package) {
        Ok(s) => {
            if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&s) {
                v["correlation_id"] = serde_json::json!(correlation_id);
                let own_event = serde_json::json!({
                    "event_id": format!("ae-evidence_package-{}", &format!("{:x}", djbx33a(correlation_id.as_bytes()))),
                    "event_type": "evidence_package_completed",
                    "actor": "digger-cli",
                    "action_summary": "Evidence package assembled from chain artifacts",
                    "input_refs": vec![triage_path.to_string(), verification_path.to_string()],
                    "output_refs": vec![correlation_id.clone()],
                    "approval_required": false,
                    "approval_status": "not_required",
                    "policy_decision": "allowed",
                    "is_mutating": false,
                    "is_finding": false,
                });
                all_events.push(own_event);
                v["audit_events"] = serde_json::json!(all_events);
                serde_json::to_string_pretty(&v).unwrap_or(s)
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
            "Evidence package: {} (is_finding: false)",
            package.package_id
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
