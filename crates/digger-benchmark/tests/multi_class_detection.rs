/// C6.0-2 — Multi-class detection oracle: honest per-class baseline (corpus-gated).
///
/// Maps every corpus case's vulnerability_class against Digger's CURRENT detections
/// (hypothesis kinds + CEI detector). Produces honest per-class precision/recall.
/// This is the measuring stick for all of Gen 6.
///
/// SEPARATE measurement stream — never touches engine_parity or kind_fidelity.
use digger_benchmark::loader::normalize_finding;
use digger_graph::build_system_ir;
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

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn multi_class_detection_baseline() {
    let root = workspace_root();

    let golden_path = root.join("crates/digger-benchmark/fixtures/legacy_golden.json");
    let golden_str = std::fs::read_to_string(&golden_path).expect("legacy_golden.json not found");
    let golden: serde_json::Value = serde_json::from_str(&golden_str).unwrap();
    let golden_cases = golden["cases"].as_array().unwrap();

    // Load categories + expected findings
    let mut categories: BTreeMap<String, String> = BTreeMap::new();
    let mut expected_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap().to_string();
        let findings: Vec<String> = gc["expected"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        expected_map.insert(case_id.clone(), findings);
    }

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
            let vclass = meta_val["vulnerability_class"]
                .as_str()
                .unwrap_or("")
                .to_string();
            if !case_id.is_empty() && !vclass.is_empty() {
                categories.insert(case_id, vclass);
            }
        }
    }

    // Build source map
    let mut source_map: BTreeMap<String, (String, String)> = BTreeMap::new();
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

    // Per-class accumulators: expected_kinds (from golden) vs detected_kinds
    let mut class_expected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut class_detected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut class_cases: BTreeMap<String, usize> = BTreeMap::new();

    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap().to_string();
        let vclass = categories.get(&case_id).cloned().unwrap_or_default();
        *class_cases.entry(vclass.clone()).or_insert(0) += 1;

        // Expected findings (from golden)
        if let Some(findings) = expected_map.get(&case_id) {
            for f in findings {
                class_expected
                    .entry(vclass.clone())
                    .or_default()
                    .insert(f.clone());
            }
        }

        // Detected findings (from source path + CEI detector)
        if let Some((src, lang)) = source_map.get(&case_id) {
            // Gen2 hypothesis kinds via compat shim (normalized)
            let raw_prog = parse_program(src, lang);
            let ir = build_system_ir(raw_prog.clone());
            let gen2 = digger_hypothesis::analyze_compat(&ir);
            let mut detected: BTreeSet<String> =
                gen2.iter().map(|h| normalize_finding(&h.kind)).collect();

            // CEI detector findings
            if let Some(body) = digger_reconstruct::recover_source_body_graph(&raw_prog) {
                let violations = digger_reconstruct::detect_cei_violations(&body);
                let unsuppressed: Vec<_> = violations.iter().filter(|v| !v.suppressed).collect();
                if !unsuppressed.is_empty() {
                    detected.insert("CEI_VIOLATION".to_string());
                }
            }

            for d in detected {
                class_detected.entry(vclass.clone()).or_default().insert(d);
            }
        }
    }

    // Per-class coverage: which expected kinds are detected?
    eprintln!();
    eprintln!("===== MULTI-CLASS DETECTION BASELINE =====");
    let mut all_classes: Vec<String> = class_cases.keys().cloned().collect();
    all_classes.sort();

    for cls in all_classes.iter() {
        let cases = class_cases.get(cls.as_str()).copied().unwrap_or(0);
        let expected = class_expected
            .get(cls.as_str())
            .cloned()
            .unwrap_or_default();
        let detected = class_detected
            .get(cls.as_str())
            .cloned()
            .unwrap_or_default();
        let matched: BTreeSet<_> = expected.intersection(&detected).cloned().collect();
        let missed: BTreeSet<_> = expected.difference(&detected).cloned().collect();

        let recall = if expected.is_empty() {
            0.0
        } else {
            matched.len() as f64 / expected.len() as f64 * 100.0
        };

        eprintln!(
            "CLASS {} | cases={} expected_kinds={} detected_kinds={} matched={} recall={:.0}%",
            cls,
            cases,
            expected.len(),
            detected.len(),
            matched.len(),
            recall
        );
        if !missed.is_empty() {
            let mut sorted_missed: Vec<_> = missed.iter().collect();
            sorted_missed.sort();
            eprintln!("  MISSED: {:?}", sorted_missed);
        }
    }

    // Summary
    let total_expected: usize = class_expected.values().map(|s| s.len()).sum();
    let total_matched: usize = class_expected
        .iter()
        .filter_map(|(cls, exp)| {
            class_detected
                .get(cls.as_str())
                .map(|det| exp.intersection(det).count())
        })
        .sum();
    let overall_recall = if total_expected > 0 {
        total_matched as f64 / total_expected as f64 * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!("===== SUMMARY =====");
    eprintln!(
        "  total_expected_kinds={} total_matched={} overall_recall={:.1}%",
        total_expected, total_matched, overall_recall
    );
    eprintln!(
        "  classes_with_coverage={}/{}",
        class_expected
            .iter()
            .filter(|(cls, exp)| class_detected
                .get(cls.as_str())
                .is_none_or(|det| !exp.intersection(det).count() == 0))
            .count(),
        all_classes.len()
    );
    eprintln!(
        "  classes_with_zero_coverage={}",
        class_expected
            .iter()
            .filter(|(cls, exp)| class_detected
                .get(cls.as_str())
                .is_none_or(|det| exp.intersection(det).count() == 0))
            .count()
    );
}
