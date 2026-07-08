use crate::{output, report};

pub fn run(
    path: String,
    lang: String,
    json_output: bool,
    surface_json: Option<String>,
    with_corpus: Option<&str>,
) {
    // 1. Read source
    let code = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot read '{}': {}", path, e);
            std::process::exit(1);
        }
    };
    if code.trim().is_empty() {
        eprintln!("error: file '{}' is empty", path);
        std::process::exit(1);
    }
    if !json_output {
        eprintln!(
            "  parsing {} ({:.1} KB) ...",
            path,
            code.len() as f64 / 1024.0
        );
    }

    // 2. Unified pipeline: source provider -> single downstream analysis (Gen2 + Gen3)
    let outcome = match with_corpus {
        Some(corpus_dir) => {
            let store = match load_corpus_store(corpus_dir) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: failed to load corpus from '{}': {}", corpus_dir, e);
                    std::process::exit(1);
                }
            };
            // Auto-compute content hash for snapshot pinning
            let snapshot = digger_hypothesis::derivation::compute_corpus_hash(&store);
            digger_pipeline::investigate_source_with_corpus(
                &code,
                &lang,
                Some(&store),
                Some(&snapshot),
                Some("cli"),
            )
        }
        None => digger_pipeline::investigate_source(&code, &lang),
    };
    let Some(system) = outcome.systems.first() else {
        eprintln!("error: no system produced for '{}'", path);
        std::process::exit(1);
    };
    let result = &system.hypotheses;

    if !json_output {
        eprintln!("  hypotheses: {} generated", result.hypotheses.len());
        for (i, h) in result.hypotheses.iter().enumerate() {
            eprintln!(
                "    {}. [{}] {} ({:.0}%)",
                i + 1,
                h.severity,
                h.hypothesis_type,
                h.evidence
                    .iter()
                    .map(|e| e.graph_facts.len())
                    .sum::<usize>() as f64
                    * 20.0
            );
        }
        // Gen3 now runs in the unified pipeline. Print the exploit-chain count.
        eprintln!(
            "  exploit chains: {} synthesized (Gen3)",
            system.exploits.total_chains
        );
    }

    // 3. Output
    if json_output {
        println!("{}", output::to_json(result));
    } else {
        report::print(result);
    }

    // 4. Surface JSON export (unchanged behavior, sourced from the unified pipeline)
    if let Some(output_path) = surface_json {
        let surface = &system.surface;
        let errors = surface.validate();
        if !errors.is_empty() {
            eprintln!("error: surface validation failed:");
            for err in &errors {
                eprintln!("  - {}", err);
            }
            std::process::exit(1);
        }
        let json = surface.to_json();
        match std::fs::write(&output_path, &json) {
            Ok(_) => eprintln!("  exported surface JSON to {}", output_path),
            Err(e) => {
                eprintln!("error: cannot write '{}': {}", output_path, e);
                std::process::exit(1);
            }
        }
    }
}

/// Load corpus findings from a directory of JSON files and build a
/// HistoricalFindingStore. Each .json file in the directory should
/// contain a Vec<NormalizedKnowledge>.
pub(crate) fn load_corpus_store(
    corpus_dir: &str,
) -> Result<digger_knowledge_models::pattern::HistoricalFindingStore, String> {
    use digger_knowledge_models::finding::NormalizedFinding;
    use digger_knowledge_models::pattern::HistoricalFindingStore;
    use std::collections::BTreeMap;
    use std::path::Path;

    let dir = Path::new(corpus_dir);
    if !dir.exists() {
        return Err(format!("corpus directory '{}' does not exist", corpus_dir));
    }

    let mut all_findings: Vec<NormalizedFinding> = Vec::new();

    for entry in std::fs::read_dir(dir).map_err(|e| format!("read_dir failed: {}", e))? {
        let entry = entry.map_err(|e| format!("entry read failed: {}", e))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = std::fs::read_to_string(&path)
            .map_err(|e| format!("read '{}' failed: {}", path.display(), e))?;
        let knowledge: Vec<digger_knowledge_models::source::NormalizedKnowledge> =
            serde_json::from_str(&data)
                .map_err(|e| format!("parse '{}' failed: {}", path.display(), e))?;
        for k in knowledge {
            all_findings.extend(k.findings);
        }
    }

    // Build indexes (same logic as digger-knowledge store_builder)
    let mut by_class: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_protocol: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_technique: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_severity: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for f in &all_findings {
        let class = f.vulnerability_class.to_string();
        by_class
            .entry(class)
            .or_default()
            .push(f.finding_id.clone());
        by_protocol
            .entry(f.protocol_name.clone())
            .or_default()
            .push(f.finding_id.clone());
        let tech = f.attack_technique.to_string();
        by_technique
            .entry(tech)
            .or_default()
            .push(f.finding_id.clone());
        let sev = f.severity.to_string();
        by_severity
            .entry(sev)
            .or_default()
            .push(f.finding_id.clone());
    }

    Ok(HistoricalFindingStore {
        findings: all_findings,
        by_class,
        by_protocol,
        by_technique,
        by_severity,
        patterns: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid corpus JSON fixture (Vec<NormalizedKnowledge> with 1 finding).
    const FIXTURE_JSON: &str = r#"[
  {
    "knowledge_id": "knowledge:test-001",
    "source_id": "test",
    "source_kind": "AuditRepository",
    "source_identifier": "test.json",
    "subject": "TestProtocol",
    "subject_category": "vault",
    "findings": [
      {
        "finding_id": "test-001",
        "original_finding_id": "T-01",
        "report_id": "report-001",
        "protocol_name": "TestProtocol",
        "protocol_category": "Vault",
        "protocol_domain": "Vaults",
        "protocol_pattern": null,
        "vulnerability_class": "Reentrancy",
        "attack_goal": "drain_funds",
        "capability_pattern": [],
        "violated_invariant": {
          "kind": "asset_conservation",
          "description": "",
          "affected_state_vars": []
        },
        "attack_technique": "ReentrancyExploit",
        "mitigation_pattern": null,
        "security_assumptions": [],
        "severity": "High",
        "root_cause": "MissingAuthorityCheck",
        "impact_text": "",
        "description_text": "",
        "remediation_text": "",
        "impacted_contracts": [],
        "impacted_functions": [],
        "confidence": 1.0
      }
    ],
    "evidence": [],
    "invariants": [],
    "architectural_patterns": [],
    "mitigation_patterns": [],
    "references": [],
    "claims": [],
    "raw_sections": {}
  }
]"#;

    fn make_temp_corpus_dir(test_name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("digger_corpus_test_{test_name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Round-trip: write fixture JSON to a temp dir, load via load_corpus_store,
    /// verify the expected indexes are populated.
    #[test]
    fn round_trip_populates_indexes() {
        let dir = make_temp_corpus_dir("roundtrip");
        std::fs::write(dir.join("test_source.json"), FIXTURE_JSON).unwrap();

        let store = load_corpus_store(dir.to_str().unwrap()).expect("load should succeed");

        assert_eq!(store.findings.len(), 1);
        assert_eq!(store.findings[0].finding_id, "test-001");

        // by_class should have "reentrancy" -> ["test-001"]
        let reentrancy_ids = store.by_class.get("reentrancy").unwrap();
        assert_eq!(reentrancy_ids.len(), 1);
        assert_eq!(reentrancy_ids[0], "test-001");

        // by_technique should have "reentrancy_exploit" -> ["test-001"]
        let tech_ids = store.by_technique.get("reentrancy_exploit").unwrap();
        assert_eq!(tech_ids.len(), 1);
        assert_eq!(tech_ids[0], "test-001");

        // by_protocol should have "TestProtocol" -> ["test-001"]
        let proto_ids = store.by_protocol.get("TestProtocol").unwrap();
        assert_eq!(proto_ids.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Error path: missing directory.
    #[test]
    fn missing_directory_returns_error() {
        let result = load_corpus_store("/nonexistent/path/does/not/exist");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    /// Error path: malformed JSON.
    #[test]
    fn malformed_json_returns_error() {
        let dir = make_temp_corpus_dir("malformed");
        std::fs::write(dir.join("bad.json"), "not valid json at all").unwrap();

        let result = load_corpus_store(dir.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Empty directory produces an empty store with zero findings.
    #[test]
    fn empty_directory_produces_empty_store() {
        let dir = make_temp_corpus_dir("empty");
        let store = load_corpus_store(dir.to_str().unwrap()).expect("empty dir should succeed");
        assert_eq!(store.findings.len(), 0);
        assert!(store.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Non-json files in the directory are silently skipped.
    #[test]
    fn non_json_files_are_skipped() {
        let dir = make_temp_corpus_dir("skipped");
        std::fs::write(dir.join("readme.txt"), "hello").unwrap();
        std::fs::write(dir.join(".gitkeep"), "").unwrap();
        // Only write valid JSON in a .json file
        std::fs::write(dir.join("valid.json"), FIXTURE_JSON).unwrap();

        let store = load_corpus_store(dir.to_str().unwrap()).unwrap();
        assert_eq!(store.findings.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
