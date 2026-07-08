use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimVerification {
    pub schema_version: String,
    pub digger_version: String,
    pub report_kind: String,
    pub verification_id: String,
    pub status: String,
    pub status_reason: String,
    pub extracted_claims: Vec<ExtractedClaim>,
    pub evidence_satisfied: Vec<String>,
    pub evidence_missing: Vec<String>,
    pub validation_failures: Vec<String>,
    pub required_next_steps: Vec<String>,
    pub is_finding: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtractedClaim {
    pub claim_id: String,
    pub claim_text: String,
    pub affected_component: String,
    pub status: String,
}

/// Decompose a claim into component identifiers by matching against
/// triage surfaces, hypotheses, and proof tasks.
fn decompose_claim(claim_text: &str, triage: &serde_json::Value) -> Vec<String> {
    let mut components = Vec::new();
    let claim_lower = claim_text.to_lowercase();

    if let Some(surfaces) = triage["surfaces_scanned"].as_array() {
        for s in surfaces {
            if let Some(name) = s["name"].as_str() {
                if claim_lower.contains(&name.to_lowercase()) {
                    components.push(format!("surface:{}", name));
                }
            }
        }
    }

    if let Some(hyps) = triage["candidate_hypotheses"].as_array() {
        for h in hyps {
            if let Some(desc) = h["description"].as_str() {
                let words: Vec<&str> = desc.split_whitespace().collect();
                let claim_words: Vec<&str> = claim_lower.split_whitespace().collect();
                let overlap = words.iter().filter(|w| claim_words.contains(w)).count();
                if overlap >= 2 {
                    if let Some(id) = h["hypothesis_id"].as_str() {
                        components.push(format!("hypothesis:{}", id));
                    }
                }
            }
        }
    }

    if let Some(tasks) = triage["proof_tasks"].as_array() {
        for t in tasks {
            if let Some(desc) = t["description"].as_str() {
                let words: Vec<&str> = desc.split_whitespace().collect();
                let claim_words: Vec<&str> = claim_lower.split_whitespace().collect();
                let overlap = words.iter().filter(|w| claim_words.contains(w)).count();
                if overlap >= 2 {
                    if let Some(id) = t["task_id"].as_str() {
                        components.push(format!("proof_task:{}", id));
                    }
                }
            }
        }
    }

    if components.is_empty() {
        components.push("unmatched_claim".into());
    }

    components
}

/// Check if evidence concretely contradicts the claim.
/// Only fires when the claim explicitly denies an auth/guard check on a
/// specific function where the engine found has_authority=true.
fn find_contradiction(claim_text: &str, triage: &serde_json::Value) -> Option<String> {
    let claim_lower = claim_text.to_lowercase();

    // Only check for explicit negation patterns tied to a specific function
    let negation_patterns = [
        "no guard on",
        "no authority on",
        "no auth check on",
        "unprotected call to",
        "missing guard on",
        "missing authority on",
    ];

    if let Some(surfaces) = triage["surfaces_scanned"].as_array() {
        for s in surfaces {
            if let Some(name) = s["name"].as_str() {
                let name_lower = name.to_lowercase();
                let has_auth = s["has_authority"].as_bool().unwrap_or(false);
                let has_guard = s["has_auth_signal"].as_bool().unwrap_or(false);

                // Only contradict if claim explicitly negates guard on THIS function
                if (has_auth || has_guard)
                    && negation_patterns
                        .iter()
                        .any(|pat| claim_lower.contains(&format!("{} {}", pat, name_lower)))
                {
                    return Some(format!(
                        "surface:{} (has_authority={}, has_auth_signal={})",
                        name, has_auth, has_guard
                    ));
                }
            }
        }
    }

    None
}

/// Check if the claim requires dynamic (non-static) evidence.
fn needs_dynamic_proof(triage: &serde_json::Value) -> bool {
    if let Some(tasks) = triage["proof_tasks"].as_array() {
        for t in tasks {
            if let Some(evidence_type) = t["evidence_type"].as_str() {
                if evidence_type.contains("runtime")
                    || evidence_type.contains("dynamic")
                    || evidence_type.contains("execution")
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if the claim requires on-chain state verification.
fn needs_chain_state(triage: &serde_json::Value) -> bool {
    if let Some(tasks) = triage["proof_tasks"].as_array() {
        for t in tasks {
            if let Some(desc) = t["description"].as_str() {
                if desc.contains("on-chain") || desc.contains("chain state") || desc.contains("RPC")
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if the claim is outside the triage scope.
fn is_out_of_scope(claim_text: &str, triage: &serde_json::Value) -> bool {
    let surfaces = triage["surfaces_scanned"].as_array();
    let hyps = triage["candidate_hypotheses"].as_array();

    let has_surfaces = surfaces.is_some_and(|a| !a.is_empty());
    let has_hyps = hyps.is_some_and(|a| !a.is_empty());

    if !has_surfaces && !has_hyps {
        return true;
    }

    let claim_lower = claim_text.to_lowercase();
    let chain = triage["chain"].as_str().unwrap_or("");

    let solana_keywords = ["anchor", "pda", "cpi", "spl_token", "system_program"];
    let evm_keywords = ["solidity", "evm", "erc20", "erc721", "opcodes"];

    let chain_set: Vec<&str> = if chain == "solana" {
        evm_keywords.to_vec()
    } else if chain == "evm" {
        solana_keywords.to_vec()
    } else {
        return true;
    };

    chain_set.iter().any(|kw| claim_lower.contains(kw))
}

pub fn verify_claim(triage_path: &str, claim_path: &str, json: bool, output: Option<&str>) {
    let triage_content = match fs::read_to_string(triage_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading triage: {}", e);
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

    let claim_text = match fs::read_to_string(claim_path) {
        Ok(c) => c.trim().to_string(),
        Err(e) => {
            eprintln!("Error reading claim: {}", e);
            std::process::exit(1);
        }
    };

    let correlation_id = triage["correlation_id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let chain = triage["chain"].as_str().unwrap_or("unknown");

    // Step 1: Decompose claim into components
    let components = decompose_claim(&claim_text, &triage);

    // Step 2: Map components to triage evidence
    let mut evidence_satisfied = Vec::new();
    let mut claim_evidence_missing = Vec::new();
    let mut validation_failures = Vec::new();

    // Build a map of surfaces by name
    let surfaces_map: HashMap<String, &serde_json::Value> = triage["surfaces_scanned"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let name = s["name"].as_str()?;
                    Some((name.to_string(), s))
                })
                .collect()
        })
        .unwrap_or_default();

    // Build a map of missing evidence by affected_component
    let missing_by_component: HashMap<String, Vec<&serde_json::Value>> = triage["missing_evidence"]
        .as_array()
        .map(|arr| {
            let mut map: HashMap<String, Vec<&serde_json::Value>> = HashMap::new();
            for m in arr {
                if let Some(component) = m["affected_component"].as_str() {
                    map.entry(component.to_string()).or_default().push(m);
                }
            }
            map
        })
        .unwrap_or_default();

    // Map each claim component to evidence
    for component in &components {
        if let Some(surface_name) = component.strip_prefix("surface:") {
            if let Some(surface) = surfaces_map.get(surface_name) {
                let prov = surface["provenance"].as_str().unwrap_or("unknown");
                evidence_satisfied.push(format!(
                    "Surface '{}' found (provenance={}, engine_derived={})",
                    surface_name,
                    prov,
                    surface["engine_derived"].as_bool().unwrap_or(false)
                ));

                // Check if this specific surface has missing evidence
                if let Some(missing_items) = missing_by_component.get(surface_name) {
                    for item in missing_items {
                        if let Some(desc) = item["description"].as_str() {
                            claim_evidence_missing
                                .push(format!("Surface '{}': {}", surface_name, desc));
                        }
                    }
                }
            }
        } else if component.starts_with("hypothesis:") || component.starts_with("proof_task:") {
            evidence_satisfied.push(format!(
                "Component '{}' found in triage evidence",
                component
            ));
        }
    }

    // Step 3: Check for contradictions
    let contradiction = find_contradiction(&claim_text, &triage);
    if let Some(refuting) = contradiction {
        validation_failures.push(format!("Triage evidence contradicts claim: {}", refuting));
    }

    // Step 4: Check for dynamic/chain-state needs from proof_tasks
    let needs_dynamic = needs_dynamic_proof(&triage);
    let needs_chain = needs_chain_state(&triage);

    // Step 5: Check out-of-scope
    let out_of_scope = is_out_of_scope(&claim_text, &triage);

    // Step 6: Compute status from evidence
    let (status, status_reason): (String, String) = if out_of_scope {
        (
            "out_of_scope".into(),
            format!(
                "Claim target component has no surface in triage for {} chain; falls outside analyzed scope",
                chain
            ),
        )
    } else if !validation_failures.is_empty() {
        ("invalid".into(), validation_failures.join("; "))
    } else if needs_dynamic {
        (
            "needs_dynamic_proof".into(),
            "Triage proof_tasks require runtime/dynamic evidence for this claim component".into(),
        )
    } else if needs_chain {
        (
            "needs_chain_state_verification".into(),
            "Triage proof_tasks require on-chain state verification for this claim component"
                .into(),
        )
    } else if evidence_satisfied.is_empty() {
        (
            "insufficient_evidence".into(),
            format!(
                "No triage surfaces match the {} claim component(s)",
                components.len()
            ),
        )
    } else if !claim_evidence_missing.is_empty() {
        (
            "insufficient_evidence".into(),
            format!(
                "{} surfaces matched but {} required evidence items remain missing for claimed components",
                evidence_satisfied.len(),
                claim_evidence_missing.len()
            ),
        )
    } else {
        (
            "valid".into(),
            format!(
                "All {} claim components map to triage surfaces with no missing required evidence",
                evidence_satisfied.len()
            ),
        )
    };

    // Build next steps from evidence
    let mut required_next_steps = Vec::new();
    match status.as_str() {
        "valid" => {
            required_next_steps
                .push("All claim components have surface evidence with no gaps".into());
            required_next_steps.push(
                "is_finding remains false — human review required for final determination".into(),
            );
        }
        "invalid" => {
            required_next_steps
                .push("Review refuting evidence cited in status_reason for accuracy".into());
            required_next_steps.push("Claim may need revision or withdrawal".into());
        }
        "insufficient_evidence" => {
            required_next_steps.push("Address missing evidence items cited above".into());
            required_next_steps.push("Provide additional source references or proof tasks".into());
        }
        "needs_dynamic_proof" => {
            required_next_steps.push("Execute proof task requiring runtime/dynamic data".into());
            required_next_steps.push("Provide transaction traces or runtime evidence".into());
        }
        "needs_chain_state_verification" => {
            required_next_steps.push("Query on-chain state at specific block/slot".into());
            required_next_steps.push("Provide RPC or explorer evidence".into());
        }
        "out_of_scope" => {
            required_next_steps.push("Claim is outside static triage scope".into());
            required_next_steps
                .push("Provide triage data covering the claimed feature area".into());
        }
        _ => {}
    }

    let verification = ClaimVerification {
        schema_version: "digger.claim_verification.v1".into(),
        digger_version: env!("CARGO_PKG_VERSION").into(),
        report_kind: "claim_verification".into(),
        verification_id: format!("cv-{}", &format!("{:x}", djbx33a(claim_path.as_bytes()))),
        status,
        status_reason,
        extracted_claims: vec![ExtractedClaim {
            claim_id: "c-1".into(),
            claim_text: claim_text.clone(),
            affected_component: components.join(", "),
            status: "extracted".into(),
        }],
        evidence_satisfied,
        evidence_missing: claim_evidence_missing,
        validation_failures,
        required_next_steps,
        is_finding: false,
    };

    let output_json = match serde_json::to_string_pretty(&verification) {
        Ok(s) => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                let enriched = crate::chain_trace::enrich_with_trace(
                    v,
                    &correlation_id,
                    "verify_claim",
                    vec![triage_path.to_string(), claim_path.to_string()],
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
            "Verification: {} — {} (is_finding: false)",
            verification.verification_id, verification.status
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
