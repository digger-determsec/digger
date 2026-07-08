/// C4.7 Phase A — Permanent corpus engine-parity harness (corpus-gated).
///
/// Compares GEN2 (analyze_compat) against the FROZEN legacy golden fixture.
/// Pure measurement — asserts nothing.
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

fn sorted_vec(s: &BTreeSet<String>) -> Vec<&str> {
    let mut v: Vec<&str> = s.iter().map(|s| s.as_str()).collect();
    v.sort();
    v
}

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn engine_parity_across_corpus() {
    let root = workspace_root();

    // Load frozen golden fixture
    let golden_path = root.join("crates/digger-benchmark/fixtures/legacy_golden.json");
    let golden_str = std::fs::read_to_string(&golden_path)
        .expect("legacy_golden.json not found — run generate_golden first");
    let golden: serde_json::Value = serde_json::from_str(&golden_str).unwrap();
    let golden_cases = golden["cases"].as_array().unwrap();

    // Build golden map
    let mut golden_map: HashMap<String, BTreeSet<String>> = HashMap::new();
    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap().to_string();
        let kinds: BTreeSet<String> = gc["legacy"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        golden_map.insert(case_id, kinds);
    }

    // Build GEN2 map
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
    let mut detected_count = 0usize;
    let mut lost_count = 0usize;
    let mut lost_paths: Vec<String> = Vec::new();

    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap();
        let golden_kinds = golden_map.get(case_id).cloned().unwrap_or_default();
        let gen2_kinds = gen2_map.get(case_id).cloned().unwrap_or_default();

        let verdict = if gen2_kinds.is_empty() && !golden_kinds.is_empty() {
            lost_count += 1;
            lost_paths.push(case_id.to_string());
            "LOST"
        } else if !gen2_kinds.is_empty() {
            detected_count += 1;
            "DETECTED"
        } else {
            "BOTH_EMPTY"
        };

        eprintln!(
            "PARITY {} | GOLDEN={:?} | GEN2={:?} | VERDICT={}",
            case_id,
            sorted_vec(&golden_kinds),
            sorted_vec(&gen2_kinds),
            verdict
        );
    }

    eprintln!();
    eprintln!(
        "SUMMARY: total={}, DETECTED={}, LOST={}, BOTH_EMPTY={}",
        golden_cases.len(),
        detected_count,
        lost_count,
        golden_cases.len() - detected_count - lost_count
    );
    if !lost_paths.is_empty() {
        eprintln!("LOST CASES:");
        for p in &lost_paths {
            eprintln!("  {}", p);
        }
    }
}
