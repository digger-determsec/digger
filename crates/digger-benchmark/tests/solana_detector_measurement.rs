/// C6.5-2 — Per-case Solana access-control detection measurement.
///
/// Runs ALL Solana account-model cases through both detectors:
/// 1. access_control: TP/FN/FP/TN for MissingAuthorityCheck violations
/// 2. unvalidated_cpi: TP/FN/FP/TN for UnvalidatedCpi violations
use digger_benchmark::loader::normalize_finding;
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

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[allow(clippy::print_literal)]
#[test]
fn solana_per_case_measurement() {
    let root = workspace_root();
    let solana_dir = root.join("corpus/solana-account-model");

    // Collect all cases
    let mut cases: BTreeMap<String, CaseResult> = BTreeMap::new();

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

        let is_negative = meta_val["known_limitations"]
            .as_str()
            .map(|s| s.contains("NEGATIVE"))
            .unwrap_or(false);

        // Find source file
        let mut src_path = None;
        for src_entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let ep = src_entry.path();
            let ext = ep.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "rs" {
                src_path = Some(ep);
                break;
            }
        }

        let src_file = match src_path {
            Some(p) => p,
            None => continue,
        };

        let src = std::fs::read_to_string(&src_file).unwrap_or_default();
        let raw_prog = parse_program(&src, "anchor");

        let mut result = CaseResult {
            case_id: case_id.clone(),
            is_negative,
            ops_emitted: raw_prog.operations.len(),
            state_write: raw_prog
                .operations
                .iter()
                .any(|o| o.kind == digger_parser::model::OperationKind::StateWrite),
            external_call: raw_prog
                .operations
                .iter()
                .any(|o| o.kind == digger_parser::model::OperationKind::ExternalCall),
            value_transfer: raw_prog
                .operations
                .iter()
                .any(|o| o.kind == digger_parser::model::OperationKind::ValueTransfer),
            authority_check: raw_prog
                .operations
                .iter()
                .any(|o| o.kind == digger_parser::model::OperationKind::AuthorityCheck),
            state_read: raw_prog
                .operations
                .iter()
                .any(|o| o.kind == digger_parser::model::OperationKind::StateRead),
            detected_violations: vec![],
            unvalidated_cpi_detected: false,
            type_cosplay_detected: false,
            unchecked_owner_detected: false,
        };

        if let Some(body) = digger_reconstruct::recover_source_body_graph(&raw_prog) {
            let violations = digger_reconstruct::detect_solana_access_violations(&body);
            result.detected_violations = violations
                .iter()
                .map(|v| normalize_finding(&v.violation_kind))
                .collect();

            let cpi_violations = digger_reconstruct::detect_unvalidated_cpi(&body);
            result.unvalidated_cpi_detected = !cpi_violations.is_empty();

            let tc_violations = digger_reconstruct::detect_type_cosplay(&body);
            result.type_cosplay_detected = !tc_violations.is_empty();

            let uo_violations = digger_reconstruct::detect_unchecked_owner(&body);
            result.unchecked_owner_detected = !uo_violations.is_empty();
        }

        cases.insert(case_id, result);
    }

    // Report per-case
    eprintln!();
    eprintln!("===== SOLANA PER-CASE DETECTION TABLE =====");
    eprintln!();
    eprintln!(
        "  {:<35} {:<10} {:<5} {:<8} {:<7} {:<8} {:<8} {:<15} {}",
        "case_id",
        "type",
        "ops",
        "swrite",
        "extcall",
        "valxfer",
        "authchk",
        "violations",
        "verdict"
    );
    eprintln!("  {}", "-".repeat(120));

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut fn_count = 0usize;
    let mut tn = 0usize;

    for (case_id, r) in &cases {
        let detected = !r.detected_violations.is_empty();
        let verdict = match (r.is_negative, detected) {
            (false, true) => {
                tp += 1;
                "TP (correctly flagged)"
            }
            (false, false) => {
                fn_count += 1;
                "FN (missed vulnerability)"
            }
            (true, true) => {
                fp += 1;
                "FP (false alarm on safe program)"
            }
            (true, false) => {
                tn += 1;
                "TN (correctly not flagged)"
            }
        };

        let vclass = if r.is_negative { "NEG" } else { "POS" };
        eprintln!(
            "  {:<35} {:<10} {:<5} {:<8} {:<7} {:<8} {:<8} {:<15} {}",
            case_id,
            vclass,
            r.ops_emitted,
            r.state_write,
            r.external_call,
            r.value_transfer,
            r.authority_check,
            format!("{:?}", r.detected_violations),
            verdict
        );
    }

    let total_positive = tp + fn_count;
    let total_negative = fp + tn;
    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64 * 100.0
    } else {
        0.0
    };
    let recall = if total_positive > 0 {
        tp as f64 / total_positive as f64 * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!("===== SOLANA DETECTOR MEASUREMENT =====");
    eprintln!(
        "  total_cases = {} ({} positive, {} negative)",
        cases.len(),
        total_positive,
        total_negative
    );
    eprintln!("  TP={}  FN={}  FP={}  TN={}", tp, fn_count, fp, tn);
    eprintln!("  precision = {:.1}% (TP / (TP + FP))", precision);
    eprintln!("  recall    = {:.1}% (TP / (TP + FN))", recall);
    eprintln!();

    // Assertions for integrity
    assert!(
        total_negative >= 4,
        "Need at least 4 negative cases for meaningful precision, got {}",
        total_negative
    );
    assert!(
        total_positive >= 8,
        "Need at least 8 positive cases, got {}",
        total_positive
    );
    assert_eq!(
        fp, 0,
        "FALSE POSITIVE: {} safe programs were incorrectly flagged",
        fp
    );

    // ── Unvalidated CPI Measurement ──
    let mut cpi_tp = 0usize;
    let mut cpi_fp = 0usize;
    let mut cpi_fn = 0usize;
    let mut cpi_tn = 0usize;

    eprintln!();
    eprintln!("===== UNVALIDATED CPI DETECTOR MEASUREMENT =====");
    eprintln!();
    eprintln!(
        "  {:<35} {:<10} {:<8} {:<10}",
        "case_id", "type", "extcall", "cpi_viol"
    );
    eprintln!("  {}", "-".repeat(70));

    for (case_id, r) in &cases {
        let detected = r.unvalidated_cpi_detected;
        let verdict = match (r.is_negative, detected) {
            (false, true) => {
                cpi_tp += 1;
                "TP"
            }
            (false, false) => {
                cpi_fn += 1;
                "FN"
            }
            (true, true) => {
                cpi_fp += 1;
                "FP"
            }
            (true, false) => {
                cpi_tn += 1;
                "TN"
            }
        };
        let vclass = if r.is_negative { "NEG" } else { "POS" };
        eprintln!(
            "  {:<35} {:<10} {:<8} {:<10}",
            case_id, vclass, r.external_call, verdict
        );
    }

    let cpi_total_pos = cpi_tp + cpi_fn;
    let cpi_total_neg = cpi_fp + cpi_tn;
    let cpi_precision = if cpi_tp + cpi_fp > 0 {
        cpi_tp as f64 / (cpi_tp + cpi_fp) as f64 * 100.0
    } else {
        0.0
    };
    let cpi_recall = if cpi_total_pos > 0 {
        cpi_tp as f64 / cpi_total_pos as f64 * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!(
        "  total_cases = {} ({} positive, {} negative)",
        cases.len(),
        cpi_total_pos,
        cpi_total_neg
    );
    eprintln!(
        "  TP={}  FN={}  FP={}  TN={}",
        cpi_tp, cpi_fn, cpi_fp, cpi_tn
    );
    eprintln!("  precision = {:.1}% (TP / (TP + FP))", cpi_precision);
    eprintln!("  recall    = {:.1}% (TP / (TP + FN))", cpi_recall);
    eprintln!();

    assert_eq!(
        cpi_fp, 0,
        "UNVALIDATED CPI FALSE POSITIVE: {} safe programs incorrectly flagged",
        cpi_fp
    );

    // ── Type Cosplay Measurement ──
    let mut tc_tp = 0usize;
    let mut tc_fp = 0usize;
    let mut tc_fn = 0usize;
    let mut tc_tn = 0usize;

    eprintln!();
    eprintln!("===== TYPE COSPLAY DETECTOR MEASUREMENT =====");
    eprintln!();
    eprintln!(
        "  {:<35} {:<10} {:<8} {:<10}",
        "case_id", "type", "sread", "tc_viol"
    );
    eprintln!("  {}", "-".repeat(70));

    for (case_id, r) in &cases {
        let detected = r.type_cosplay_detected;
        let verdict = match (r.is_negative, detected) {
            (false, true) => {
                tc_tp += 1;
                "TP"
            }
            (false, false) => {
                tc_fn += 1;
                "FN"
            }
            (true, true) => {
                tc_fp += 1;
                "FP"
            }
            (true, false) => {
                tc_tn += 1;
                "TN"
            }
        };
        let vclass = if r.is_negative { "NEG" } else { "POS" };
        eprintln!(
            "  {:<35} {:<10} {:<8} {:<10}",
            case_id, vclass, r.state_read, verdict
        );
    }

    let tc_total_pos = tc_tp + tc_fn;
    let tc_total_neg = tc_fp + tc_tn;
    let tc_precision = if tc_tp + tc_fp > 0 {
        tc_tp as f64 / (tc_tp + tc_fp) as f64 * 100.0
    } else {
        0.0
    };
    let tc_recall = if tc_total_pos > 0 {
        tc_tp as f64 / tc_total_pos as f64 * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!(
        "  total_cases = {} ({} positive, {} negative)",
        cases.len(),
        tc_total_pos,
        tc_total_neg
    );
    eprintln!("  TP={}  FN={}  FP={}  TN={}", tc_tp, tc_fn, tc_fp, tc_tn);
    eprintln!("  precision = {:.1}% (TP / (TP + FP))", tc_precision);
    eprintln!("  recall    = {:.1}% (TP / (TP + FN))", tc_recall);
    eprintln!();

    assert_eq!(
        tc_fp, 0,
        "TYPE COSPLAY FALSE POSITIVE: {} safe programs incorrectly flagged",
        tc_fp
    );

    // ── Unchecked Owner Measurement ──
    let mut uo_tp = 0usize;
    let mut uo_fp = 0usize;
    let mut uo_fn = 0usize;
    let mut uo_tn = 0usize;

    eprintln!();
    eprintln!("===== UNCHECKED OWNER DETECTOR MEASUREMENT =====");
    eprintln!();
    eprintln!(
        "  {:<35} {:<10} {:<8} {:<10}",
        "case_id", "type", "sread", "uo_viol"
    );
    eprintln!("  {}", "-".repeat(70));

    for (case_id, r) in &cases {
        let detected = r.unchecked_owner_detected;
        let verdict = match (r.is_negative, detected) {
            (false, true) => {
                uo_tp += 1;
                "TP"
            }
            (false, false) => {
                uo_fn += 1;
                "FN"
            }
            (true, true) => {
                uo_fp += 1;
                "FP"
            }
            (true, false) => {
                uo_tn += 1;
                "TN"
            }
        };
        let vclass = if r.is_negative { "NEG" } else { "POS" };
        eprintln!(
            "  {:<35} {:<10} {:<8} {:<10}",
            case_id, vclass, r.state_read, verdict
        );
    }

    let uo_total_pos = uo_tp + uo_fn;
    let uo_total_neg = uo_fp + uo_tn;
    let uo_precision = if uo_tp + uo_fp > 0 {
        uo_tp as f64 / (uo_tp + uo_fp) as f64 * 100.0
    } else {
        0.0
    };
    let uo_recall = if uo_total_pos > 0 {
        uo_tp as f64 / uo_total_pos as f64 * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!(
        "  total_cases = {} ({} positive, {} negative)",
        cases.len(),
        uo_total_pos,
        uo_total_neg
    );
    eprintln!("  TP={}  FN={}  FP={}  TN={}", uo_tp, uo_fn, uo_fp, uo_tn);
    eprintln!("  precision = {:.1}% (TP / (TP + FP))", uo_precision);
    eprintln!("  recall    = {:.1}% (TP / (TP + FN))", uo_recall);
    eprintln!();

    assert_eq!(
        uo_fp, 0,
        "UNCHECKED OWNER FALSE POSITIVE: {} safe programs incorrectly flagged",
        uo_fp
    );
}

#[allow(dead_code)]
struct CaseResult {
    case_id: String,
    is_negative: bool,
    ops_emitted: usize,
    state_write: bool,
    external_call: bool,
    value_transfer: bool,
    authority_check: bool,
    state_read: bool,
    detected_violations: Vec<String>,
    unvalidated_cpi_detected: bool,
    type_cosplay_detected: bool,
    unchecked_owner_detected: bool,
}
