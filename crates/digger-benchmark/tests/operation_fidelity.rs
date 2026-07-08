/// C5.3 — Operation-fidelity harness (corpus-gated, chain-segmented).
///
/// Invokes the reconstruction pipeline per corpus case, pulls facts.body,
/// and compares recovered vs ground-truth ops (per function + per kind).
///
/// IMPORTANT: source-parse operations are a HEURISTIC proxy. Bytecode-recovered
/// operations may legitimately diverge (optimizer/inlining, dead-code elimination).
/// operation_fidelity measures agreement-with-proxy, not absolute truth.
use digger_parser::parse_program;
use std::collections::BTreeMap;
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

/// Count ground-truth operations from RawProgram.
fn ground_truth_ops(
    program: &digger_parser::model::RawProgram,
) -> (usize, usize, BTreeMap<String, usize>) {
    let fn_count = program.functions.len();
    let mut total_ops = 0usize;
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();
    for op in &program.operations {
        total_ops += 1;
        *per_kind.entry(format!("{:?}", op.kind)).or_insert(0) += 1;
    }
    (fn_count, total_ops, per_kind)
}

/// Count recovered operations from a RecoveredBodyGraph.
#[allow(dead_code)] // used when source-path body is wired in commit 2
fn recovered_ops(
    body: &digger_reconstruct::RecoveredBodyGraph,
) -> (usize, BTreeMap<String, usize>) {
    let mut total = 0usize;
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();
    for body_entry in &body.bodies {
        for op in &body_entry.operations {
            total += 1;
            *per_kind.entry(format!("{:?}", op.kind)).or_insert(0) += 1;
        }
    }
    (total, per_kind)
}

struct ChainStats {
    cases: usize,
    cases_with_source_ops: usize,
    cases_with_recovered_body: usize,
    ground_truth_fns: usize,
    ground_truth_ops: usize,
    recovered_ops: usize,
    per_kind_gt: BTreeMap<String, usize>,
    per_kind_recovered: BTreeMap<String, usize>,
    ingestion_path: BTreeMap<String, usize>,
    ordering_matches: usize,
    ordering_total: usize,
    cei_matches: usize,
    cei_total: usize,
}

impl ChainStats {
    fn new() -> Self {
        Self {
            cases: 0,
            cases_with_source_ops: 0,
            cases_with_recovered_body: 0,
            ground_truth_fns: 0,
            ground_truth_ops: 0,
            recovered_ops: 0,
            per_kind_gt: BTreeMap::new(),
            per_kind_recovered: BTreeMap::new(),
            ingestion_path: BTreeMap::new(),
            ordering_matches: 0,
            ordering_total: 0,
            cei_matches: 0,
            cei_total: 0,
        }
    }

    fn operation_recall(&self) -> f64 {
        if self.ground_truth_ops == 0 {
            0.0
        } else {
            self.recovered_ops as f64 / self.ground_truth_ops as f64
        }
    }
}

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[test]
fn operation_fidelity_by_chain() {
    let root = workspace_root();

    let golden_path = root.join("crates/digger-benchmark/fixtures/legacy_golden.json");
    let golden_str = std::fs::read_to_string(&golden_path).expect("legacy_golden.json not found");
    let golden: serde_json::Value = serde_json::from_str(&golden_str).unwrap();
    let golden_cases = golden["cases"].as_array().unwrap();

    let mut source_map: BTreeMap<String, (String, String)> = BTreeMap::new();

    // Collect source from all corpus trees
    let known_dir = root.join("corpus/known-exploits");
    if known_dir.is_dir() {
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
                let meta_val: serde_json::Value =
                    serde_json::from_str(&meta_str).unwrap_or_default();
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
    }

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
            let meta_str = std::fs::read_to_string(&mp).unwrap_or_default();
            let meta_val: serde_json::Value = serde_json::from_str(&meta_str).unwrap_or_default();
            let case_id = meta_val["exploit_id"].as_str().unwrap_or("").to_string();
            if case_id.is_empty() {
                continue;
            }
            let src = std::fs::read_to_string(&sp).unwrap_or_default();
            source_map.insert(case_id, (src, "solidity".to_string()));
        }
    }

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
            let meta_str = std::fs::read_to_string(&mp).unwrap_or_default();
            let meta_val: serde_json::Value = serde_json::from_str(&meta_str).unwrap_or_default();
            let category = meta_val["category"].as_str().unwrap_or("unknown");
            let case_id = format!("bugs/{}", category);
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

    // Measure per case, invoking the pipeline
    let mut chains: BTreeMap<String, ChainStats> = BTreeMap::new();

    for gc in golden_cases {
        let case_id = gc["case_id"].as_str().unwrap();

        if let Some((src, lang)) = source_map.get(case_id) {
            let chain = if lang == "solidity" {
                "evm"
            } else if lang == "anchor" || lang == "rust" {
                "solana"
            } else {
                lang.as_str()
            };
            let stats = chains
                .entry(chain.to_string())
                .or_insert_with(ChainStats::new);
            stats.cases += 1;

            // Ground truth from source
            let raw = parse_program(src, lang);
            let (fn_count, total_ops, kind_counts) = ground_truth_ops(&raw);
            stats.ground_truth_fns += fn_count;
            stats.ground_truth_ops += total_ops;
            for (k, v) in &kind_counts {
                *stats.per_kind_gt.entry(k.clone()).or_insert(0) += v;
            }
            if total_ops > 0 {
                stats.cases_with_source_ops += 1;
            }

            // Invoke source-path body recovery
            let path_taken = "source_graph";
            *stats
                .ingestion_path
                .entry(path_taken.to_string())
                .or_insert(0) += 1;

            // Recover ops from source-parse operations
            let body_graph = digger_reconstruct::recover_source_body_graph(&raw);
            let rec_ops = body_graph
                .as_ref()
                .map(|bg| {
                    let (count, _) = recovered_ops(bg);
                    count
                })
                .unwrap_or(0);
            let rec_kind = body_graph
                .as_ref()
                .map(|bg| recovered_ops(bg).1)
                .unwrap_or_default();
            stats.recovered_ops += rec_ops;
            for (k, v) in &rec_kind {
                *stats.per_kind_recovered.entry(k.clone()).or_insert(0) += v;
            }
            if rec_ops > 0 {
                stats.cases_with_recovered_body += 1;
            }

            // Ordering fidelity: compare per-function operation sequences
            // Group ground truth ops by function
            let mut gt_by_fn: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for op in &raw.operations {
                gt_by_fn
                    .entry(op.function.clone())
                    .or_default()
                    .push(format!("{:?}", op.kind));
            }
            // Group recovered ops by function
            let mut rec_by_fn: BTreeMap<String, Vec<String>> = BTreeMap::new();
            if let Some(bg) = &body_graph {
                for body_entry in &bg.bodies {
                    rec_by_fn
                        .entry(body_entry.function_id.clone())
                        .or_default()
                        .extend(
                            body_entry
                                .operations
                                .iter()
                                .map(|o| format!("{:?}", o.kind)),
                        );
                }
            }

            // Compare ordering per function
            for (fn_name, gt_seq) in &gt_by_fn {
                let rec_seq = rec_by_fn.get(fn_name).cloned().unwrap_or_default();
                stats.ordering_total += 1;
                if gt_seq == &rec_seq {
                    stats.ordering_matches += 1;
                }

                // CEI: ExternalCall before StateWrite
                let gt_has_ext = gt_seq.iter().position(|k| k == "ExternalCall");
                let gt_has_sw = gt_seq.iter().position(|k| k == "StateWrite");
                let rec_has_ext = rec_seq.iter().position(|k| k == "ExternalCall");
                let rec_has_sw = rec_seq.iter().position(|k| k == "StateWrite");
                if gt_has_ext.is_some() || gt_has_sw.is_some() {
                    stats.cei_total += 1;
                    let gt_cei = gt_has_ext.zip(gt_has_sw).map(|(e, s)| e < s);
                    let rec_cei = rec_has_ext.zip(rec_has_sw).map(|(e, s)| e < s);
                    if gt_cei == rec_cei {
                        stats.cei_matches += 1;
                    }
                }
            }

            eprintln!(
                "OPS {} | chain={} gt_ops={} gt_fns={} rec_ops={} path={}",
                case_id, chain, total_ops, fn_count, rec_ops, path_taken,
            );
        }
    }

    // Per-chain summary
    eprintln!();
    eprintln!("OPERATION_FIDELITY SUMMARY:");
    for (chain, stats) in &chains {
        eprintln!();
        eprintln!("  === {} ===", chain.to_uppercase());
        eprintln!("  cases={}", stats.cases);
        eprintln!("  cases_with_source_ops={}", stats.cases_with_source_ops);
        eprintln!(
            "  cases_with_recovered_body={}",
            stats.cases_with_recovered_body
        );
        eprintln!("  ground_truth_functions={}", stats.ground_truth_fns);
        eprintln!("  ground_truth_operations={}", stats.ground_truth_ops);
        eprintln!("  recovered_operations={}", stats.recovered_ops);
        eprintln!(
            "  operation_recall={:.1}%",
            stats.operation_recall() * 100.0
        );
        eprintln!("  ingestion_paths: {:?}", stats.ingestion_path);
        if stats.ordering_total > 0 {
            eprintln!(
                "  ordering_fidelity={:.1}% ({}/{} functions match)",
                stats.ordering_matches as f64 / stats.ordering_total as f64 * 100.0,
                stats.ordering_matches,
                stats.ordering_total
            );
        }
        if stats.cei_total > 0 {
            eprintln!(
                "  cei_ordering={:.1}% ({}/{} functions with ExternalCall+StateWrite agree)",
                stats.cei_matches as f64 / stats.cei_total as f64 * 100.0,
                stats.cei_matches,
                stats.cei_total
            );
        }
        eprintln!("  ground_truth ops by kind:");
        let mut sorted_gt: Vec<_> = stats.per_kind_gt.iter().collect();
        sorted_gt.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in &sorted_gt {
            let rec = stats.per_kind_recovered.get(*kind).copied().unwrap_or(0);
            let pct = if **count > 0 {
                rec as f64 / **count as f64 * 100.0
            } else {
                0.0
            };
            eprintln!(
                "    {}: {} (recovered: {}, recall: {:.0}%)",
                kind, count, rec, pct
            );
        }
    }

    eprintln!();
    eprintln!("  SOURCE vs BYTECODE: corpus cases use source-based ingestion.");
    eprintln!("  Source-path body recovery provides ~100% agreement (same data).");
    eprintln!("  The EVM bytecode recoverer (C5.2) is for compiled-bytecode targets only.");
}
