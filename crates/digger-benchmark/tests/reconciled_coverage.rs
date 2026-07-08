/// C6.2-0 — Reconciled coverage: target taxonomy vs ground-truth availability.
///
/// Scores against the FULL ADR-0030 target taxonomy, not just corpus expected kinds.
/// Reports per class: covered / partial / zero-coverage-WITH-ground-truth / NO-GROUND-TRUTH-YET.
/// Separates "recall on classes that HAVE ground truth" from "fraction of target taxonomy with ground truth."
use digger_benchmark::loader::normalize_finding;
use digger_parser::parse_program;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let d = env!("CARGO_MANIFEST_DIR");
    Path::new(d)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Full ADR-0030 target taxonomy (17 EVM + Solana classes).
const TARGET_TAXONOMY: &[(&str, &str)] = &[
    ("access-control", "access_control"),
    ("reentrancy", "reentrancy"),
    ("flash-loan", "flash_loan"),
    ("flash_loan_composability", "flash_loan_composability"),
    ("oracle-manipulation", "oracle_manipulation"),
    ("oracle_manipulation", "oracle_manipulation"),
    ("governance_attack", "governance_attack"),
    ("governance", "governance"),
    ("upgradeability", "upgradeability"),
    ("bridge_replay", "bridge_replay"),
    ("bridge_signature", "bridge_signature"),
    ("bridge_threshold", "bridge_threshold"),
    ("bridge_verification", "bridge_verification"),
    ("business_logic", "business_logic"),
    ("cross_contract", "cross_contract"),
    ("cross_function", "cross_function"),
    ("cross_protocol", "cross_protocol"),
    ("delegatecall", "delegatecall"),
    ("initialization", "initialization"),
    ("jit_liquidity", "jit_liquidity"),
    ("mev_extraction", "mev_extraction"),
    ("missing-validation", "missing_validation"),
    ("missing_validation", "missing_validation"),
    ("missing_access_control", "missing_access_control"),
    ("pda_collision", "pda_collision"),
    ("state-desync", "state_desync"),
    ("storage-collision", "storage_collision"),
    ("unsafe-external-call", "unsafe_external_call"),
    ("front_running", "front_running"),
    ("sandwich_attack", "sandwich_attack"),
];

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn reconciled_coverage_baseline() {
    let root = workspace_root();

    let golden_path = root.join("crates/digger-benchmark/fixtures/legacy_golden.json");
    let golden_str = std::fs::read_to_string(&golden_path).expect("legacy_golden.json not found");
    let golden: serde_json::Value = serde_json::from_str(&golden_str).unwrap();
    let golden_cases = golden["cases"].as_array().unwrap();

    // Load categories from ALL sources
    let mut categories: BTreeMap<String, String> = BTreeMap::new();
    for search_dir in &[
        root.join("corpus/known-exploits"),
        root.join("corpus/generalization-benchmark"),
        root.join("corpus/bugs"),
        root.join("corpus/solana-account-model"),
    ] {
        if !search_dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(search_dir).unwrap().flatten() {
            let class_dir = entry.path();
            if !class_dir.is_dir() {
                continue;
            }
            for exploit_dir in std::fs::read_dir(&class_dir).unwrap().flatten() {
                let dir = exploit_dir.path();
                if !dir.is_dir() {
                    continue;
                }
                let mp = dir.join("meta.json");
                if !mp.exists() {
                    continue;
                }
                let meta_str = std::fs::read_to_string(&mp).unwrap_or_default();
                let meta_val: serde_json::Value =
                    serde_json::from_str(&meta_str).unwrap_or_default();
                let case_id = meta_val["exploit_id"].as_str().unwrap_or("").to_string();
                let vclass = meta_val["vulnerability_class"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                if !case_id.is_empty() && !vclass.is_empty() {
                    categories.insert(case_id, vclass);
                }
            }
        }
    }

    // Load expected findings from golden
    let mut expected_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap().to_string();
        let findings: Vec<String> = gc["expected"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        expected_map.insert(case_id, findings);
    }

    // Load categories from solana-account-model (flat 2-level structure)
    let solana_cat_dir = root.join("corpus/solana-account-model");
    if solana_cat_dir.is_dir() {
        for entry in std::fs::read_dir(&solana_cat_dir).unwrap().flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let mp = dir.join("meta.json");
            if !mp.exists() {
                continue;
            }
            let meta_str = std::fs::read_to_string(&mp).unwrap_or_default();
            let meta_val: serde_json::Value = serde_json::from_str(&meta_str).unwrap_or_default();
            let case_id = meta_val["exploit_id"].as_str().unwrap_or("").to_string();
            let vclass = meta_val["vulnerability_class"]
                .as_str()
                .unwrap_or("")
                .to_string();
            if !case_id.is_empty() && !vclass.is_empty() {
                categories.insert(case_id, vclass);
            }
        }
    }

    // Also load solana-account-model expected findings from their meta.json
    let solana_meta_dir = root.join("corpus/solana-account-model");
    if solana_meta_dir.is_dir() {
        for entry in std::fs::read_dir(&solana_meta_dir).unwrap().flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let mp = dir.join("meta.json");
            if !mp.exists() {
                continue;
            }
            let meta_str = std::fs::read_to_string(&mp).unwrap_or_default();
            let meta_val: serde_json::Value = serde_json::from_str(&meta_str).unwrap_or_default();
            let case_id = meta_val["exploit_id"].as_str().unwrap_or("").to_string();
            let findings: Vec<String> = meta_val["expected_findings"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(normalize_finding))
                        .collect()
                })
                .unwrap_or_default();
            if !case_id.is_empty() {
                expected_map.insert(case_id, findings);
            }
        }
    }

    // Build source map from known-exploits (source-bearing)
    let mut source_map: BTreeMap<String, (String, String)> = BTreeMap::new();
    let known_dir = root.join("corpus/known-exploits");
    for entry in std::fs::read_dir(&known_dir).unwrap().flatten() {
        let class_dir = entry.path();
        if !class_dir.is_dir() {
            continue;
        }
        for exploit_dir in std::fs::read_dir(&class_dir).unwrap().flatten() {
            let dir = exploit_dir.path();
            if !dir.is_dir() {
                continue;
            }
            let mp = dir.join("meta.json");
            if !mp.exists() {
                continue;
            }
            let meta_str = std::fs::read_to_string(&mp).unwrap_or_default();
            let meta_val: serde_json::Value = serde_json::from_str(&meta_str).unwrap_or_default();
            let case_id = meta_val["exploit_id"].as_str().unwrap_or("").to_string();
            if case_id.is_empty() {
                continue;
            }
            for src_entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let ep = src_entry.path();
                let ext = ep.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "sol" {
                    let src = std::fs::read_to_string(&ep).unwrap_or_default();
                    source_map.insert(case_id.clone(), (src, "solidity".to_string()));
                    break;
                }
            }
        }
    }

    // Also load solana-account-model cases (Rust/Anchor source)
    let solana_dir = root.join("corpus/solana-account-model");
    if solana_dir.is_dir() {
        for entry in std::fs::read_dir(&solana_dir).unwrap().flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let mp = dir.join("meta.json");
            if !mp.exists() {
                continue;
            }
            let meta_str = std::fs::read_to_string(&mp).unwrap_or_default();
            let meta_val: serde_json::Value = serde_json::from_str(&meta_str).unwrap_or_default();
            let case_id = meta_val["exploit_id"].as_str().unwrap_or("").to_string();
            if case_id.is_empty() {
                continue;
            }
            for src_entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let ep = src_entry.path();
                let ext = ep.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "sol" || ext == "rs" {
                    let src = std::fs::read_to_string(&ep).unwrap_or_default();
                    let lang = if ext == "rs" { "anchor" } else { "solidity" };
                    source_map.insert(case_id.clone(), (src, lang.to_string()));
                    break;
                }
            }
        }
    }

    // Per-class: expected kinds vs detected kinds
    let mut class_expected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut class_detected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut class_cases: BTreeMap<String, usize> = BTreeMap::new();

    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap().to_string();
        let vclass = categories.get(&case_id).cloned().unwrap_or_default();
        *class_cases.entry(vclass.clone()).or_insert(0) += 1;

        if let Some(findings) = expected_map.get(&case_id) {
            for f in findings {
                class_expected
                    .entry(vclass.clone())
                    .or_default()
                    .insert(f.clone());
            }
        }

        if let Some((src, lang)) = source_map.get(&case_id) {
            let raw_prog = parse_program(src, lang);
            let ir = digger_graph::build_system_ir(raw_prog.clone());
            let gen2 = digger_hypothesis::analyze_compat(&ir);
            for h in &gen2 {
                class_detected
                    .entry(vclass.clone())
                    .or_default()
                    .insert(digger_benchmark::loader::normalize_finding(&h.kind));
            }

            // CEI detector
            if let Some(body) = digger_reconstruct::recover_source_body_graph(&raw_prog) {
                let violations = digger_reconstruct::detect_cei_violations(&body);
                let unsuppressed: Vec<_> = violations.iter().filter(|v| !v.suppressed).collect();
                if !unsuppressed.is_empty() {
                    class_detected
                        .entry(vclass.clone())
                        .or_default()
                        .insert("cei_violation".to_string());
                }

                // Solana access-control detector
                let sol_violations = digger_reconstruct::detect_solana_access_violations(&body);
                for sv in &sol_violations {
                    class_detected
                        .entry(vclass.clone())
                        .or_default()
                        .insert(normalize_finding(&sv.violation_kind));
                }
            }
        }
    }

    // Also process solana-account-model cases (not in golden fixture)
    for (case_id, (src, lang)) in &source_map {
        let vclass = categories
            .get(case_id.as_str())
            .cloned()
            .unwrap_or_default();
        *class_cases.entry(vclass.clone()).or_insert(0) += 1;

        if let Some(findings) = expected_map.get(case_id) {
            for f in findings {
                class_expected
                    .entry(vclass.clone())
                    .or_default()
                    .insert(f.clone());
            }
        }

        let raw_prog = parse_program(src, lang);
        let ir = digger_graph::build_system_ir(raw_prog.clone());
        let gen2 = digger_hypothesis::analyze_compat(&ir);
        for h in &gen2 {
            class_detected
                .entry(vclass.clone())
                .or_default()
                .insert(digger_benchmark::loader::normalize_finding(&h.kind));
        }

        if let Some(body) = digger_reconstruct::recover_source_body_graph(&raw_prog) {
            let violations = digger_reconstruct::detect_cei_violations(&body);
            let unsuppressed: Vec<_> = violations.iter().filter(|v| !v.suppressed).collect();
            if !unsuppressed.is_empty() {
                class_detected
                    .entry(vclass.clone())
                    .or_default()
                    .insert("cei_violation".to_string());
            }
            let sol_violations = digger_reconstruct::detect_solana_access_violations(&body);
            for sv in &sol_violations {
                class_detected
                    .entry(vclass.clone())
                    .or_default()
                    .insert(normalize_finding(&sv.violation_kind));
            }
        }
    }

    // Report per-class against FULL target taxonomy (exclude empty-vclass cases)
    let uncategorized_count: usize = class_cases.get("").copied().unwrap_or(0);
    eprintln!();
    eprintln!("===== RECONCOVERAGE: TARGET TAXONOMY vs GROUND TRUTH =====");
    eprintln!();

    // All known classes from corpus
    let mut all_corpus_classes: BTreeSet<String> = class_cases.keys().cloned().collect();
    // Also include ADR-0030 target classes that may not appear in corpus
    for (_, alias) in TARGET_TAXONOMY {
        all_corpus_classes.insert(alias.to_string());
    }

    let mut sorted_classes: Vec<String> = all_corpus_classes.into_iter().collect();
    sorted_classes.sort();

    let mut total_with_gt = 0usize;
    let mut total_matched = 0usize;
    let mut no_gt_count = 0usize;

    for cls in &sorted_classes {
        let cases = class_cases.get(cls).copied().unwrap_or(0);
        let expected = class_expected.get(cls).cloned().unwrap_or_default();
        let detected = class_detected.get(cls).cloned().unwrap_or_default();
        let matched: BTreeSet<_> = expected
            .iter()
            .filter(|e| detected.contains(e.as_str()))
            .cloned()
            .collect();

        let status = if cases == 0 || expected.is_empty() {
            "NO-GROUND-TRUTH-YET"
        } else if matched.len() == expected.len() {
            "covered"
        } else if !matched.is_empty() {
            "partial"
        } else {
            "zero-coverage-WITH-ground-truth"
        };

        if !expected.is_empty() {
            total_with_gt += expected.len();
            total_matched += matched.len();
        } else {
            no_gt_count += 1;
        }

        let recall = if expected.is_empty() {
            0.0
        } else {
            matched.len() as f64 / expected.len() as f64 * 100.0
        };

        eprintln!(
            "  {:<30} cases={:<3} expected={:<3} matched={:<3} recall={:<5} status={}",
            cls,
            cases,
            expected.len(),
            matched.len(),
            format!("{:.0}%", recall),
            status
        );
    }

    // Headline
    let classes_with_gt = sorted_classes
        .iter()
        .filter(|c| {
            class_expected
                .get(c.as_str())
                .is_some_and(|e| !e.is_empty())
        })
        .count();
    let overall_recall = if total_with_gt > 0 {
        total_matched as f64 / total_with_gt as f64 * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!("===== HEADLINE =====");
    let named_classes: usize = sorted_classes.iter().filter(|c| !c.is_empty()).count();
    eprintln!("  target_taxonomy_classes={}", named_classes);
    eprintln!(
        "  classes_with_ground_truth={}/{}",
        classes_with_gt, named_classes
    );
    eprintln!("  no_ground_truth_yet={}", no_gt_count);
    eprintln!(
        "  recall_on_classes_WITH_gt={:.1}% ({}/{})",
        overall_recall, total_matched, total_with_gt
    );
    if uncategorized_count > 0 {
        eprintln!("  uncategorized_cases={}", uncategorized_count);
    }
    eprintln!();
    eprintln!("  Classes with zero coverage but ground truth:");
    for cls in &sorted_classes {
        if cls.is_empty() {
            continue;
        }
        let expected = class_expected
            .get(cls.as_str())
            .cloned()
            .unwrap_or_default();
        let detected = class_detected
            .get(cls.as_str())
            .cloned()
            .unwrap_or_default();
        if !expected.is_empty() && expected.iter().all(|e| !detected.contains(e)) {
            eprintln!("    {} ({} expected kinds)", cls, expected.len());
        }
    }
}
