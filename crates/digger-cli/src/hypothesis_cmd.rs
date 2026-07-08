use crate::chain_trace::enrich_with_trace;
use digger_agent_hypothesis::types::Hypothesis;
use digger_agent_hypothesis::validation::validate;
use std::fs;

/// Legacy Hypothesis command — generate hypotheses from source file.
pub fn run(path: &str, lang: &str, json: bool, output: Option<&str>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    };

    let _lang_str = lang;

    let surface_refs: Vec<String> = content
        .lines()
        .filter(|l| {
            l.contains("function ")
                || l.contains("pub fn ")
                || l.contains("pub struct ")
                || l.contains("mod ")
        })
        .enumerate()
        .map(|(i, _)| format!("{}:{}", path, i + 1))
        .collect();

    let hypothesis = Hypothesis::new(
        format!("h-{:x}", djbx33a(path.as_bytes())),
        format!("Investigate surfaces in {}", path),
        surface_refs,
        vec!["Source code review".into()],
        vec!["No issues found after review".into()],
    );

    let errors = validate(&hypothesis);
    if !errors.is_empty() {
        eprintln!("Hypothesis validation failed:");
        for err in &errors {
            eprintln!("  - {:?}", err);
        }
        std::process::exit(1);
    }

    let output_json = match serde_json::to_string_pretty(&hypothesis) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error serializing hypothesis: {}", e);
            std::process::exit(1);
        }
    };

    if json && output.is_none() {
        println!("{}", output_json);
    }

    if let Some(out_path) = output {
        if let Err(e) = fs::write(out_path, &output_json) {
            eprintln!("Error writing: {}", e);
            std::process::exit(1);
        }
        println!("Written to: {}", out_path);
    } else if !json {
        println!(
            "Hypothesis: {} (is_finding: false)",
            hypothesis.hypothesis_id
        );
    }
}

/// New: create validated hypothesis from triage packet.
pub fn create_from_triage(
    triage_path: &str,
    claim_path: Option<&str>,
    json: bool,
    output: Option<&str>,
) {
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

    let correlation_id = triage["correlation_id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let claim_text = if let Some(cp) = claim_path {
        match fs::read_to_string(cp) {
            Ok(c) => c.trim().to_string(),
            Err(e) => {
                eprintln!("Error reading claim file: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        format!(
            "Investigate triage surfaces from {}",
            triage["target_repository"].as_str().unwrap_or("unknown")
        )
    };

    let mut surfaces: Vec<String> = triage["function_surfaces"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let name = s["name"].as_str()?;
                    let path = s["path"].as_str()?;
                    Some(format!("{}:{}", path, name))
                })
                .collect()
        })
        .unwrap_or_default();

    // Also include engine-derived and repo-intelligence surfaces from surfaces_scanned
    if let Some(scanned) = triage["surfaces_scanned"].as_array() {
        for s in scanned {
            if let Some(name) = s["name"].as_str() {
                if let Some(path) = s["path"].as_str() {
                    let key = format!("{}:{}", path, name);
                    if !surfaces.contains(&key) {
                        surfaces.push(key);
                    }
                }
            }
        }
    }

    let evidence_required: Vec<String> = triage["missing_evidence"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e["description"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let disproof_conditions: Vec<String> = triage["limitations"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|l| l["description"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let hypothesis_id = format!("h-{}", &format!("{:x}", djbx33a(triage_path.as_bytes())));

    let hypothesis = Hypothesis::new(
        hypothesis_id,
        claim_text,
        surfaces,
        evidence_required,
        disproof_conditions,
    );

    let errors = validate(&hypothesis);
    if !errors.is_empty() {
        eprintln!("Hypothesis validation failed:");
        for err in &errors {
            eprintln!("  - {:?}", err);
        }
        std::process::exit(1);
    }

    let output_json = match serde_json::to_string_pretty(&hypothesis) {
        Ok(s) => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                let enriched = enrich_with_trace(
                    v,
                    &correlation_id,
                    "hypothesis",
                    vec![triage_path.to_string()],
                );
                serde_json::to_string_pretty(&enriched).unwrap_or(s)
            } else {
                s
            }
        }
        Err(e) => {
            eprintln!("Error serializing hypothesis: {}", e);
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
            "Hypothesis created: {} (is_finding: false)",
            hypothesis.hypothesis_id
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
