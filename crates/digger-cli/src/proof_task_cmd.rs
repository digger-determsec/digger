use digger_agent_proof_task::types::ProofTask;
use digger_agent_proof_task::validation::validate_proof_task;
use std::fs;

pub fn generate_from_hypothesis(
    hypothesis_path: &str,
    triage_path: &str,
    json: bool,
    output: Option<&str>,
) {
    let hyp_content = match fs::read_to_string(hypothesis_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading hypothesis file: {}", e);
            std::process::exit(1);
        }
    };

    let hyp: serde_json::Value = match serde_json::from_str(&hyp_content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing hypothesis JSON: {}", e);
            std::process::exit(1);
        }
    };

    let triage_content = match fs::read_to_string(triage_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading triage file: {}", e);
            std::process::exit(1);
        }
    };

    let triage: serde_json::Value = match serde_json::from_str(&triage_content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing triage JSON: {}", e);
            std::process::exit(1);
        }
    };

    let correlation_id = hyp["correlation_id"]
        .as_str()
        .or_else(|| triage["correlation_id"].as_str())
        .unwrap_or("unknown")
        .to_string();

    let hypothesis_id = hyp["hypothesis_id"].as_str().unwrap_or("unknown");
    let claim = hyp["claim"].as_str().unwrap_or("no claim");

    let surfaces: Vec<String> = hyp["source_surfaces"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let required_evidence: Vec<String> = hyp["evidence_required"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let task_id = format!(
        "pt-{}",
        &format!("{:x}", djbx33a(hypothesis_path.as_bytes()))
    );

    let proof_task = ProofTask::new(
        task_id,
        hypothesis_id.to_string(),
        claim.to_string(),
        surfaces,
        required_evidence,
        vec!["source_review".into()],
        vec!["no_execution".into(), "no_network".into()],
        vec!["evidence_record".into(), "validation_result".into()],
        vec!["evidence_refs_populated".into()],
        vec!["evidence_refs_empty_after_max_attempts".into()],
    );

    let errors = validate_proof_task(&proof_task);
    if !errors.is_empty() {
        eprintln!("Proof task validation failed:");
        for err in &errors {
            eprintln!("  - {:?}", err);
        }
        std::process::exit(1);
    }

    let output_json = match serde_json::to_string_pretty(&proof_task) {
        Ok(s) => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                let enriched = crate::chain_trace::enrich_with_trace(
                    v,
                    &correlation_id,
                    "proof_task",
                    vec![hypothesis_path.to_string(), triage_path.to_string()],
                );
                serde_json::to_string_pretty(&enriched).unwrap_or(s)
            } else {
                s
            }
        }
        Err(e) => {
            eprintln!("Error serializing proof task: {}", e);
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
            "Proof task created: {} (is_finding: false)",
            proof_task.task_id
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
