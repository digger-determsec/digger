/// C5.4c — Real bytecode vs source fidelity measurement (EXPERIMENTAL, corpus-gated).
///
/// For each compiled corpus case, runs the C5.2 EVM recoverer on the
/// real solc-compiled runtime bytecode and compares against source-path
/// ground-truth operations. This is an EXPERIMENTAL measurement — the
/// bytecode recoverer achieves ~12.8% recall on optimized bytecode (ADR-0029).
/// Source-path body recovery (100% recall) is the first-class path.
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

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn count_ops(body: &digger_reconstruct::RecoveredBodyGraph) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for body_entry in &body.bodies {
        for op in &body_entry.operations {
            *counts.entry(format!("{:?}", op.kind)).or_insert(0) += 1;
        }
    }
    counts
}

/// Source-path ground truth from RawProgram.operations.
fn source_gt(source: &str, lang: &str) -> (usize, BTreeMap<String, usize>) {
    let raw = parse_program(source, lang);
    let mut counts = BTreeMap::new();
    let total = raw.operations.len();
    for op in &raw.operations {
        *counts.entry(format!("{:?}", op.kind)).or_insert(0) += 1;
    }
    (total, counts)
}

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn compiled_bytecode_vs_source_fidelity() {
    let root = workspace_root();
    let compiled_dir = root.join("crates/digger-benchmark/fixtures/bytecode/evm_compiled");
    if !compiled_dir.is_dir() {
        eprintln!("COMPILED FIXTURES: directory not found, skipping");
        return;
    }

    // Build source map from known-exploits
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

    // Per-case comparison
    let mut total_gt = 0usize;
    let mut total_rec = 0usize;
    let mut cases_compared = 0usize;
    let mut per_kind_gt_total: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_kind_rec_total: BTreeMap<String, usize> = BTreeMap::new();
    let mut cases_with_divergence = 0usize;

    for entry in std::fs::read_dir(&compiled_dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("hex") {
            continue;
        }
        let case_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        let hex_str = std::fs::read_to_string(&path).unwrap();
        let bytecode = hex_decode(&hex_str);

        // Lift + recover
        let lifter = digger_reconstruct::EvmBytecodeLifter::new();
        let program = match digger_reconstruct::lift_with(&lifter, &bytecode) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("SKIP {} — lift failed: {:?}", case_id, e);
                continue;
            }
        };
        let body_graph = digger_reconstruct::recover_evm_body_graph(&program);
        let rec_ops = body_graph.as_ref().map(count_ops).unwrap_or_default();
        let rec_total: usize = rec_ops.values().sum();

        // Source ground truth
        if let Some((src, lang)) = source_map.get(&case_id) {
            let (gt_total, gt_ops) = source_gt(src, lang);

            // Aggregate
            total_gt += gt_total;
            total_rec += rec_total;
            cases_compared += 1;
            for (k, v) in &gt_ops {
                *per_kind_gt_total.entry(k.clone()).or_insert(0) += v;
            }
            for (k, v) in &rec_ops {
                *per_kind_rec_total.entry(k.clone()).or_insert(0) += v;
            }

            let has_divergence = gt_total != rec_total;
            if has_divergence {
                cases_with_divergence += 1;
            }

            let verdict = if rec_total == 0 && gt_total > 0 {
                "NO-OPS"
            } else if rec_total == gt_total {
                "MATCH"
            } else {
                "DIVERGE"
            };

            eprintln!(
                "FIDELITY {} | gt_ops={} rec_ops={} verdict={} gt_kinds={:?} rec_kinds={:?}",
                case_id, gt_total, rec_total, verdict, gt_ops, rec_ops,
            );
        } else {
            eprintln!("SKIP {} — no source in corpus", case_id);
        }
    }

    // Summary
    eprintln!();
    eprintln!("COMPILED BYTECODE vs SOURCE SUMMARY:");
    eprintln!("  cases_compared={}", cases_compared);
    eprintln!("  cases_with_divergence={}", cases_with_divergence);
    eprintln!("  total_gt_ops={}", total_gt);
    eprintln!("  total_rec_ops={}", total_rec);
    let recall = if total_gt > 0 {
        total_rec as f64 / total_gt as f64 * 100.0
    } else {
        0.0
    };
    eprintln!("  bytecode_recall={:.1}%", recall);
    eprintln!();
    eprintln!("  per-kind (gt / rec):");
    let all_kinds: BTreeSet<String> = per_kind_gt_total
        .keys()
        .chain(per_kind_rec_total.keys())
        .cloned()
        .collect();
    for kind in &all_kinds {
        let gt = per_kind_gt_total.get(kind).unwrap_or(&0);
        let rec = per_kind_rec_total.get(kind).unwrap_or(&0);
        let pct = if *gt > 0 {
            *rec as f64 / *gt as f64 * 100.0
        } else {
            0.0
        };
        eprintln!("    {}: gt={} rec={} ({:.0}%)", kind, gt, rec, pct);
    }
}

/// Source-path regression check (unchanged from C5.3).
#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn source_path_no_regression() {
    let root = workspace_root();
    let golden_path = root.join("crates/digger-benchmark/fixtures/legacy_golden.json");
    let golden_str = std::fs::read_to_string(&golden_path).expect("legacy_golden.json not found");
    let golden: serde_json::Value = serde_json::from_str(&golden_str).unwrap();
    let golden_cases = golden["cases"].as_array().unwrap();

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
                if ext == "sol" || ext == "rs" {
                    let src = std::fs::read_to_string(&ep).unwrap_or_default();
                    let lang = if ext == "rs" { "anchor" } else { "solidity" };
                    source_map.insert(case_id.clone(), (src, lang.to_string()));
                    break;
                }
            }
        }
    }

    let mut total_gt = 0usize;
    let mut total_rec = 0usize;
    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap();
        if let Some((src, lang)) = source_map.get(case_id) {
            let raw = parse_program(src, lang);
            let gt = raw.operations.len();
            let body = digger_reconstruct::recover_source_body_graph(&raw);
            let rec = body
                .as_ref()
                .map(|b| b.bodies.iter().map(|b| b.operations.len()).sum::<usize>())
                .unwrap_or(0);
            total_gt += gt;
            total_rec += rec;
        }
    }
    assert_eq!(total_gt, total_rec, "source-path recall must remain 100%");
    eprintln!("SOURCE PATH REGRESSION: {}/{} = 100%", total_rec, total_gt);
}
