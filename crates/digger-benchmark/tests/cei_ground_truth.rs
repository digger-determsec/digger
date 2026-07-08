/// C5.6-0 — Independent CEI ground truth from exploit categories (corpus-gated).
///
/// ANTI-CIRCULARITY: labels are derived from exploit vulnerability_class (historical
/// exploit category), NOT from operation ordering. This is the oracle.
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

/// Independent CEI labels: cases historically classified as reentrancy exploits.
/// Source: vulnerability_class in meta.json — NOT derived from operation ordering.
const REENTRANCY_CLASSES: &[&str] = &[
    "reentrancy",
    "flash-loan", // Flash loan exploits typically involve reentrancy patterns
    "flash_loan_composability", // Cross-protocol composability exploits
];

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn build_cei_ground_truth() {
    let root = workspace_root();
    let golden_path = root.join("crates/digger-benchmark/fixtures/legacy_golden.json");
    let golden_str = std::fs::read_to_string(&golden_path).expect("legacy_golden.json not found");
    let golden: serde_json::Value = serde_json::from_str(&golden_str).unwrap();
    let golden_cases = golden["cases"].as_array().unwrap();

    // Load exploit categories from meta.json
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

    // Build CEI ground truth from vulnerability_class
    let mut cei_positive: BTreeSet<String> = BTreeSet::new();
    let mut all_cases: BTreeSet<String> = BTreeSet::new();

    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap().to_string();
        all_cases.insert(case_id.clone());

        if let Some(vclass) = categories.get(&case_id) {
            let is_reentrancy = REENTRANCY_CLASSES.iter().any(|rc| vclass == *rc);
            if is_reentrancy {
                cei_positive.insert(case_id);
            }
        }
    }

    // Also check generalization-benchmark and bugs for categories
    let gen_dir = root.join("corpus/generalization-benchmark");
    if gen_dir.is_dir() {
        for entry in std::fs::read_dir(&gen_dir).unwrap().flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let mp = p.join("meta.json");
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
            if !case_id.is_empty() {
                all_cases.insert(case_id.clone());
                categories.insert(case_id, vclass);
            }
        }
    }

    eprintln!("===== CEI GROUND TRUTH (INDEPENDENT) =====");
    eprintln!("total_cases={}", all_cases.len());
    eprintln!(
        "cei_positive={} (reentrancy-class exploits)",
        cei_positive.len()
    );
    eprintln!();
    eprintln!("CEI-positive cases (independent reentrancy labels):");
    let mut sorted_cei: Vec<_> = cei_positive.iter().collect();
    sorted_cei.sort();
    for case in &sorted_cei {
        let vclass = categories
            .get(*case)
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        eprintln!("  {} (class={})", case, vclass);
    }

    eprintln!();
    eprintln!("REENTRANCY CLASSES USED: {:?}", REENTRANCY_CLASSES);
    eprintln!("NOTE: these labels are from exploit vulnerability_class (historical),");
    eprintln!("NOT from operation ordering. Anti-circularity preserved.");
}
