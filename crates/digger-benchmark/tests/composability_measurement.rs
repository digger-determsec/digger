/// C6.13-C -- Read-only reentrancy measurement harness (detector wired).
///
/// Per-case: recovered ops, ExternalCall->StateRead pattern, guard, finding, verdict.
/// Reports in-sample (5 pos + 5 neg) and held-out (2 pos) separately.
use digger_parser::parse_program;
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

const IN_SAMPLE_IDS: &[&str] = &[
    "sentiment-2023",
    "conic-finance-2023",
    "dforce-2023",
    "sturdy-finance-2023",
    "midas-capital-2023",
    "safe-benign-call-then-read-2023",
    "safe-callback-no-state-read-2023",
    "safe-checks-effects-2023",
    "safe-view-only-callback-2023",
    "safe-view-reentrancy-check-2023",
];

const HELD_OUT_IDS: &[&str] = &["harvest-finance-2020", "rari-fuse-2022"];

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[allow(clippy::print_literal)]
#[test]
fn composability_per_case_measurement() {
    let root = workspace_root();
    let comp_dir = root.join("corpus/composability/read-only-reentrancy");

    let mut in_sample_tp = 0usize;
    let mut in_sample_fn = 0usize;
    let mut in_sample_fp = 0usize;
    let mut in_sample_tn = 0usize;
    let mut held_out_tp = 0usize;
    let mut held_out_fn = 0usize;

    let mut results: Vec<CaseRow> = Vec::new();

    for entry in std::fs::read_dir(&comp_dir).unwrap().flatten() {
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

        let is_negative = meta_val["vulnerability_class"]
            .as_str()
            .map(|s| s == "NEGATIVE")
            .unwrap_or(false);

        let mut src_path = None;
        for src_entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let ep = src_entry.path();
            let ext = ep.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "sol" {
                src_path = Some(ep);
                break;
            }
        }

        let src_file = match src_path {
            Some(p) => p,
            None => continue,
        };

        let src = std::fs::read_to_string(&src_file).unwrap_or_default();
        let raw_prog = parse_program(&src, "solidity");

        let ext_calls: usize = raw_prog
            .operations
            .iter()
            .filter(|o| o.kind == digger_parser::model::OperationKind::ExternalCall)
            .count();
        let state_reads: usize = raw_prog
            .operations
            .iter()
            .filter(|o| o.kind == digger_parser::model::OperationKind::StateRead)
            .count();

        let findings = digger_reconstruct::detect_readonly_reentrancy(&raw_prog);
        let has_finding = !findings.is_empty();

        // Diagnostic: print operations per function
        for func in &raw_prog.functions {
            let func_ops: Vec<_> = raw_prog
                .operations
                .iter()
                .filter(|o| o.function == func.name)
                .collect();
            if !func_ops.is_empty() {
                let ops_str: Vec<String> = func_ops
                    .iter()
                    .map(|o| format!("{:?}({})", o.kind, o.target))
                    .collect();
                if case_id.starts_with("sentiment")
                    || case_id.starts_with("conic")
                    || case_id.starts_with("dforce")
                    || case_id.starts_with("harvest")
                    || case_id.starts_with("safe-benign")
                {
                    eprintln!("  DIAG {}::{} ops={:?}", case_id, func.name, ops_str);
                }
            }
        }

        let is_in_sample = IN_SAMPLE_IDS.contains(&case_id.as_str());
        let is_held_out = HELD_OUT_IDS.contains(&case_id.as_str());

        if is_in_sample {
            match (is_negative, has_finding) {
                (false, true) => in_sample_tp += 1,
                (false, false) => in_sample_fn += 1,
                (true, true) => in_sample_fp += 1,
                (true, false) => in_sample_tn += 1,
            }
        } else if is_held_out && !is_negative {
            if has_finding {
                held_out_tp += 1;
            } else {
                held_out_fn += 1;
            }
        }

        let set = if is_in_sample {
            "IN"
        } else if is_held_out {
            "OO"
        } else {
            "??"
        };
        let guard = if src.contains("nonReentrant") || src.contains("_locked") {
            "nonReentrant".into()
        } else if src.contains("_status") || src.contains("ENTERED") {
            "lock_check".into()
        } else if src.contains("if (_status") || src.contains("revert") {
            "view_lock".into()
        } else {
            "(none)".into()
        };

        results.push(CaseRow {
            case_id,
            is_negative,
            is_in_sample,
            ext_calls,
            state_reads,
            guard,
            has_finding,
            set: set.to_string(),
        });
    }

    results.sort_by(|a, b| a.case_id.cmp(&b.case_id));

    eprintln!();
    eprintln!("===== READ-ONLY REENTRANCY DETECTOR MEASUREMENT =====");
    eprintln!();
    eprintln!(
        "  {:<35} {:<6} {:<4} {:<5} {:<5} {:<20} {:<8} {}",
        "case_id", "set", "type", "ext", "srd", "guard", "finding", "verdict"
    );
    eprintln!("  {}", "-".repeat(100));

    for r in &results {
        let vclass = if r.is_negative { "NEG" } else { "POS" };
        let verdict = match (r.is_negative, r.has_finding) {
            (false, true) => "TP",
            (false, false) => "FN",
            (true, true) => "FP",
            (true, false) => "TN",
        };
        eprintln!(
            "  {:<35} {:<6} {:<4} {:<5} {:<5} {:<20} {:<8} {}",
            r.case_id,
            r.set,
            vclass,
            r.ext_calls,
            r.state_reads,
            r.guard,
            if r.has_finding { "YES" } else { "no" },
            verdict
        );
    }

    eprintln!();
    eprintln!("===== IN-SAMPLE (5 pos + 5 neg) =====");
    eprintln!(
        "  TP={} FN={} FP={} TN={} | P={:.1}% R={:.1}%",
        in_sample_tp,
        in_sample_fn,
        in_sample_fp,
        in_sample_tn,
        if in_sample_tp + in_sample_fp > 0 {
            in_sample_tp as f64 / (in_sample_tp + in_sample_fp) as f64 * 100.0
        } else {
            0.0
        },
        if in_sample_tp + in_sample_fn > 0 {
            in_sample_tp as f64 / (in_sample_tp + in_sample_fn) as f64 * 100.0
        } else {
            0.0
        }
    );

    eprintln!();
    eprintln!("===== HELD-OUT (2 pos, first contact) =====");
    eprintln!("  TP={} FN={}", held_out_tp, held_out_fn);
}

#[allow(dead_code)]
struct CaseRow {
    case_id: String,
    is_negative: bool,
    is_in_sample: bool,
    ext_calls: usize,
    state_reads: usize,
    guard: String,
    has_finding: bool,
    set: String,
}
