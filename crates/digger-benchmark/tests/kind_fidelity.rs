/// C4.7 Phase A — Kind-fidelity harness (permanent, corpus-gated).
///
/// Compares GEN2 (analyze_compat) against the FROZEN legacy golden fixture
/// (`fixtures/legacy_golden.json`) and corpus expected_findings.
/// The "LEGACY" column is now the frozen golden, not the live crate.
use digger_benchmark::loader::normalize_finding;
use digger_graph::build_system_ir;
use digger_parser::parse_program;
use std::collections::{BTreeSet, HashMap};
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

fn build_ir(source: &str, lang: &str) -> digger_ir::SystemIR {
    let raw = parse_program(source, lang);
    build_system_ir(raw)
}

fn kinds_gen2(ir: &digger_ir::SystemIR) -> BTreeSet<String> {
    digger_hypothesis::analyze_compat(ir)
        .into_iter()
        .map(|h| normalize_finding(&h.kind))
        .collect()
}

fn sorted_set(s: &BTreeSet<String>) -> Vec<&str> {
    let mut v: Vec<&str> = s.iter().map(|s| s.as_str()).collect();
    v.sort();
    v
}

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn kind_fidelity_measurement() {
    let root = workspace_root();

    // Load frozen golden fixture
    let golden_path = root.join("crates/digger-benchmark/fixtures/legacy_golden.json");
    let golden_str = std::fs::read_to_string(&golden_path)
        .expect("legacy_golden.json not found — run generate_golden first");
    let golden: serde_json::Value = serde_json::from_str(&golden_str).unwrap();
    let golden_cases = golden["cases"].as_array().unwrap();

    let mut total_expected = 0usize;
    let mut golden_matched_total = 0usize;
    let mut gen2_matched_total = 0usize;
    let mut golden_cases_with_match = 0usize;
    let mut gen2_cases_with_match = 0usize;
    let mut gen2_only_missed: HashMap<String, usize> = HashMap::new();
    let mut total_cases = 0usize;

    // Build a map of case_id → golden legacy findings for quick lookup
    let mut golden_map: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut expected_map: HashMap<String, BTreeSet<String>> = HashMap::new();
    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap().to_string();
        let legacy: BTreeSet<String> = gc["legacy"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let expected: BTreeSet<String> = gc["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        golden_map.insert(case_id.clone(), legacy);
        expected_map.insert(case_id.clone(), expected);
    }

    // Build GEN2 outputs for each case
    let mut gen2_map: HashMap<String, BTreeSet<String>> = HashMap::new();

    // 1. known-exploits
    let known = digger_benchmark::load_corpus(root.join("corpus/known-exploits").to_str().unwrap());
    for exploit in &known {
        let ir = build_ir(&exploit.source_code, &exploit.language);
        gen2_map.insert(exploit.meta.exploit_id.clone(), kinds_gen2(&ir));
    }

    // 2. generalization-benchmark
    let gen_dir = root.join("corpus/generalization-benchmark");
    if gen_dir.is_dir() {
        for entry in std::fs::read_dir(&gen_dir).unwrap().flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let mp = p.join("meta.json");
            let sp = p.join("source.sol");
            if !mp.exists() || !sp.exists() {
                continue;
            }
            if let Ok(meta) = serde_json::from_str::<digger_benchmark::models::ExploitMeta>(
                &std::fs::read_to_string(&mp).unwrap(),
            ) {
                let src = std::fs::read_to_string(&sp).unwrap();
                let ir = build_ir(&src, "solidity");
                gen2_map.insert(meta.exploit_id, kinds_gen2(&ir));
            }
        }
    }

    // 3. bugs/
    let bugs_dir = root.join("corpus/bugs");
    if bugs_dir.is_dir() {
        for entry in std::fs::read_dir(&bugs_dir).unwrap().flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let mp = dir.join("meta.json");
            if !mp.exists() {
                continue;
            }
            let meta_val: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&mp).unwrap()).unwrap();
            let category = meta_val["category"].as_str().unwrap_or("unknown");
            if let Some(src_entry) = std::fs::read_dir(&dir).unwrap().flatten().find(|e| {
                e.path()
                    .extension()
                    .map(|x| x == "sol" || x == "rs")
                    .unwrap_or(false)
            }) {
                let src = std::fs::read_to_string(src_entry.path()).unwrap();
                let lang = if src_entry.path().extension().unwrap() == "rs" {
                    "anchor"
                } else {
                    "solidity"
                };
                let ir = build_ir(&src, lang);
                gen2_map.insert(format!("bugs/{}", category), kinds_gen2(&ir));
            }
        }
    }

    // Compare each case in golden order
    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap();
        let golden_kinds = golden_map.get(case_id).cloned().unwrap_or_default();
        let expected_kinds = expected_map.get(case_id).cloned().unwrap_or_default();
        let gen2_kinds = gen2_map.get(case_id).cloned().unwrap_or_default();

        let golden_match: BTreeSet<String> = expected_kinds
            .intersection(&golden_kinds)
            .cloned()
            .collect();
        let gen2_match: BTreeSet<String> =
            expected_kinds.intersection(&gen2_kinds).cloned().collect();
        let golden_missed: BTreeSet<String> =
            expected_kinds.difference(&golden_kinds).cloned().collect();
        let gen2_missed: BTreeSet<String> =
            expected_kinds.difference(&gen2_kinds).cloned().collect();

        total_expected += expected_kinds.len();
        golden_matched_total += golden_match.len();
        gen2_matched_total += gen2_match.len();
        if !golden_match.is_empty() {
            golden_cases_with_match += 1;
        }
        if !gen2_match.is_empty() {
            gen2_cases_with_match += 1;
        }
        total_cases += 1;

        for m in gen2_missed.difference(&golden_missed) {
            *gen2_only_missed.entry(m.clone()).or_insert(0) += 1;
        }

        eprintln!(
            "FIDELITY {} | expected={:?} | GOLDEN matched={}/{} missed={:?} | GEN2 matched={}/{} missed={:?}",
            case_id,
            sorted_set(&expected_kinds),
            golden_match.len(), expected_kinds.len(), sorted_set(&golden_missed),
            gen2_match.len(), expected_kinds.len(), sorted_set(&gen2_missed),
        );
    }

    let golden_recall = golden_matched_total as f64 / total_expected as f64;
    let gen2_recall = gen2_matched_total as f64 / total_expected as f64;
    let golden_case_cov = golden_cases_with_match as f64 / total_cases as f64;
    let gen2_case_cov = gen2_cases_with_match as f64 / total_cases as f64;

    eprintln!();
    eprintln!("SUMMARY:");
    eprintln!("  total_corpus_cases={}", total_cases);
    eprintln!("  total_expected_findings={}", total_expected);
    eprintln!(
        "  GOLDEN (frozen legacy): matched={} recall={:.1}% case_coverage={:.1}%",
        golden_matched_total,
        golden_recall * 100.0,
        golden_case_cov * 100.0
    );
    eprintln!(
        "  GEN2:                   matched={} recall={:.1}% case_coverage={:.1}%",
        gen2_matched_total,
        gen2_recall * 100.0,
        gen2_case_cov * 100.0
    );
    eprintln!(
        "  DELTA (GEN2 vs GOLDEN): recall={:+.1}% case_coverage={:+.1}%",
        (gen2_recall - golden_recall) * 100.0,
        (gen2_case_cov - golden_case_cov) * 100.0
    );
    eprintln!();
    eprintln!("  GEN2-UNMATCHABLE legacy-only kinds (total occurrences):");
    let mut sorted_missed: Vec<_> = gen2_only_missed.iter().collect();
    sorted_missed.sort_by(|a, b| b.1.cmp(a.1));
    for (kind, count) in &sorted_missed {
        eprintln!("    {}: {} occurrences", kind, count);
    }
}
