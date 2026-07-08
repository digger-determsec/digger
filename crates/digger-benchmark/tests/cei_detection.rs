/// C5.7-0 — CEI detection harness: stratified per-class + GEN2 overlap (corpus-gated).
///
/// Reports BOTH mixed and stratified precision/recall/F1 per vulnerability_class.
/// Reports overlap between CEI detector firings and GEN2's ReentrancyRisk.
/// ANTI-CIRCULARITY: labels from exploit vulnerability_class, NOT operation ordering.
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

const REENTRANCY_CLASSES: &[&str] = &["reentrancy", "flash-loan", "flash_loan_composability"];

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn cei_detection_metric() {
    let root = workspace_root();

    let golden_path = root.join("crates/digger-benchmark/fixtures/legacy_golden.json");
    let golden_str = std::fs::read_to_string(&golden_path).expect("legacy_golden.json not found");
    let golden: serde_json::Value = serde_json::from_str(&golden_str).unwrap();
    let golden_cases = golden["cases"].as_array().unwrap();

    let mut categories: BTreeMap<String, String> = BTreeMap::new();
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

    // Load expected findings per case from golden (the "expected" field, not "expected_findings")
    let mut expected_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap().to_string();
        let findings: Vec<String> = gc["expected"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(normalize_finding)
                    .collect()
            })
            .unwrap_or_default();
        expected_map.insert(case_id, findings);
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

    // Per-class accumulators
    let mut class_tp: BTreeMap<String, usize> = BTreeMap::new();
    let mut class_fp: BTreeMap<String, usize> = BTreeMap::new();
    let mut class_fn: BTreeMap<String, usize> = BTreeMap::new();
    let mut class_tn: BTreeMap<String, usize> = BTreeMap::new();

    // Mixed accumulators
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut fn_ = 0usize;
    let mut tn = 0usize;

    // GEN2 ReentrancyRisk overlap tracking
    let mut gen2_renrisk_cases: BTreeSet<String> = BTreeSet::new();
    let mut cei_fired_cases: BTreeSet<String> = BTreeSet::new();

    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap();
        let is_cei_positive = categories
            .get(case_id)
            .map(|vc| REENTRANCY_CLASSES.iter().any(|rc| vc == *rc))
            .unwrap_or(false);

        // Track GEN2 ReentrancyRisk cases
        let has_renrisk = expected_map
            .get(case_id)
            .map(|f| f.iter().any(|k| k == "reentrancy_risk"))
            .unwrap_or(false);
        if has_renrisk {
            gen2_renrisk_cases.insert(case_id.to_string());
        }

        if let Some((src, lang)) = source_map.get(case_id) {
            let raw = parse_program(src, lang);
            let body = match digger_reconstruct::recover_source_body_graph(&raw) {
                Some(b) => b,
                None => {
                    let cls = categories.get(case_id).cloned().unwrap_or_default();
                    *class_fn.entry(cls).or_insert(0) += 1;
                    if is_cei_positive {
                        fn_ += 1;
                        eprintln!("CEI {} | GT=POSITIVE DET=NONE (no body) | FN", case_id);
                    } else {
                        tn += 1;
                    }
                    continue;
                }
            };

            let violations = digger_reconstruct::detect_cei_violations(&body);
            let unsuppressed: Vec<_> = violations.iter().filter(|v| !v.suppressed).collect();
            let detected = !unsuppressed.is_empty();
            let cls = categories.get(case_id).cloned().unwrap_or_default();

            if detected {
                cei_fired_cases.insert(case_id.to_string());
            }

            if is_cei_positive && detected {
                tp += 1;
                *class_tp.entry(cls).or_insert(0) += 1;
                eprintln!("CEI {} | GT=POSITIVE DET=FIRED | TP", case_id);
            } else if is_cei_positive && !detected {
                fn_ += 1;
                *class_fn.entry(cls).or_insert(0) += 1;
                eprintln!("CEI {} | GT=POSITIVE DET=NONE | FN", case_id);
            } else if !is_cei_positive && detected {
                fp += 1;
                *class_fp.entry(cls).or_insert(0) += 1;
                eprintln!("CEI {} | GT=NEGATIVE DET=FIRED | FP", case_id);
            } else {
                tn += 1;
                *class_tn.entry(cls).or_insert(0) += 1;
            }
        }
    }

    // ── Mixed metrics ──
    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    eprintln!();
    eprintln!("===== MIXED CEI METRICS =====");
    eprintln!("  TP={} FP={} FN={} TN={}", tp, fp, fn_, tn);
    eprintln!(
        "  precision={:.1}% recall={:.1}% F1={:.1}%",
        precision * 100.0,
        recall * 100.0,
        f1 * 100.0
    );

    // ── Stratified per-class metrics ──
    eprintln!();
    eprintln!("===== STRATIFIED PER-CLASS =====");
    let all_classes: BTreeSet<String> = class_tp
        .keys()
        .chain(class_fp.keys())
        .chain(class_fn.keys())
        .chain(class_tn.keys())
        .cloned()
        .collect();
    for cls in &all_classes {
        let ctp = class_tp.get(cls).copied().unwrap_or(0);
        let cfp = class_fp.get(cls).copied().unwrap_or(0);
        let cfn = class_fn.get(cls).copied().unwrap_or(0);
        let ctn = class_tn.get(cls).copied().unwrap_or(0);
        let p = if ctp + cfp > 0 {
            ctp as f64 / (ctp + cfp) as f64
        } else {
            0.0
        };
        let r = if ctp + cfn > 0 {
            ctp as f64 / (ctp + cfn) as f64
        } else {
            0.0
        };
        let f = if p + r > 0.0 {
            2.0 * p * r / (p + r)
        } else {
            0.0
        };
        eprintln!(
            "  {}: TP={} FP={} FN={} TN={} P={:.0}% R={:.0}% F1={:.0}%",
            cls,
            ctp,
            cfp,
            cfn,
            ctn,
            p * 100.0,
            r * 100.0,
            f * 100.0
        );
    }

    // ── GEN2 ReentrancyRisk overlap ──
    eprintln!();
    eprintln!("===== GEN2 REENTRANCRISK OVERLAP =====");
    let overlap: BTreeSet<String> = gen2_renrisk_cases
        .intersection(&cei_fired_cases)
        .cloned()
        .collect();
    let gen2_only: BTreeSet<String> = gen2_renrisk_cases
        .difference(&cei_fired_cases)
        .cloned()
        .collect();
    let cei_only: BTreeSet<String> = cei_fired_cases
        .difference(&gen2_renrisk_cases)
        .cloned()
        .collect();
    eprintln!("  gen2_renrisk_cases={}", gen2_renrisk_cases.len());
    eprintln!("  cei_fired_cases={}", cei_fired_cases.len());
    eprintln!("  overlap={}", overlap.len());
    eprintln!("  gen2_only={:?} (CEI doesn't add)", sorted(&gen2_only));
    eprintln!("  cei_only={:?} (CEI adds net-new)", sorted(&cei_only));

    eprintln!();
    eprintln!("  ANTI-CIRCULARITY: ground truth from exploit vulnerability_class,");
    eprintln!(
        "  NOT from operation ordering. Labels: {:?}",
        REENTRANCY_CLASSES
    );
}

fn sorted(s: &BTreeSet<String>) -> Vec<String> {
    s.iter().cloned().collect()
}
