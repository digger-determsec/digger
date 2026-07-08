/// C6.8 — Per-case EVM price-manipulation detection measurement (with detector).
///
/// Runs ALL price-manipulation cases through parser + detector.
/// Reports per-case: price source, resistance marker, critical action, verdict.
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

#[cfg_attr(
    not(feature = "corpus"),
    ignore = "requires corpus data; run with --features corpus"
)]
#[allow(clippy::print_literal)]
#[test]
fn evm_price_per_case_measurement() {
    let root = workspace_root();
    let price_dir = root.join("corpus/price-manipulation");

    let mut tp = 0usize;
    let mut fn_count = 0usize;
    let mut fp = 0usize;
    let mut tn = 0usize;
    let mut total_cases = 0usize;

    let mut results: Vec<CaseRow> = Vec::new();

    for entry in std::fs::read_dir(&price_dir).unwrap().flatten() {
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

        let findings = digger_reconstruct::detect_price_manipulation(&src, &raw_prog);
        let has_unfiltered = findings.iter().any(|f| !f.suppressed);

        match (is_negative, has_unfiltered) {
            (false, true) => tp += 1,
            (false, false) => fn_count += 1,
            (true, true) => fp += 1,
            (true, false) => tn += 1,
        }
        total_cases += 1;

        let price_source = findings
            .first()
            .map(|f| f.price_source.clone())
            .unwrap_or_else(|| "(no price read)".into());
        let resistance = findings
            .first()
            .and_then(|f| f.resistance_marker.clone())
            .unwrap_or_else(|| {
                if findings.is_empty() {
                    "-".into()
                } else {
                    "(none)".into()
                }
            });
        let action = findings
            .first()
            .map(|f| f.critical_action.clone())
            .unwrap_or_else(|| "-".into());

        results.push(CaseRow {
            case_id,
            is_negative,
            price_source,
            resistance,
            action,
            has_unfiltered,
        });
    }

    results.sort_by(|a, b| a.case_id.cmp(&b.case_id));

    eprintln!();
    eprintln!("===== EVM PRICE-MANIPULATION PER-CASE DETECTION (WITH DETECTOR) =====");
    eprintln!();
    eprintln!(
        "  {:<35} {:<6} {:<50} {:<40} {:<20} {}",
        "case_id", "type", "price_source", "resistance", "action", "verdict"
    );
    eprintln!("  {}", "-".repeat(170));

    for r in &results {
        let vclass = if r.is_negative { "NEG" } else { "POS" };
        let verdict = match (r.is_negative, r.has_unfiltered) {
            (false, true) => "TP",
            (false, false) => "FN",
            (true, true) => "FP",
            (true, false) => "TN",
        };
        let suppression = if r.has_unfiltered {
            "".into()
        } else if r.resistance != "(none)" && r.resistance != "-" {
            format!("SUPPRESSED(resistance={})", r.resistance)
        } else if r.action == "(none)" {
            "SUPPRESSED(no critical action)".into()
        } else {
            "SUPPRESSED".into()
        };
        eprintln!(
            "  {:<35} {:<6} {:<50} {:<40} {:<20} {:<10} {}",
            r.case_id, vclass, r.price_source, r.resistance, r.action, verdict, suppression
        );
    }

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64 * 100.0
    } else {
        0.0
    };
    let recall = if tp + fn_count > 0 {
        tp as f64 / (tp + fn_count) as f64 * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!("===== MEASUREMENT =====");
    eprintln!(
        "  total_cases = {} ({} positive, {} negative)",
        total_cases,
        tp + fn_count,
        fp + tn
    );
    eprintln!("  TP={}  FN={}  FP={}  TN={}", tp, fn_count, fp, tn);
    eprintln!("  precision = {:.1}%", precision);
    eprintln!("  recall    = {:.1}%", recall);

    assert_eq!(fp, 0, "PRECISION VIOLATION: {} false positives", fp);
}

struct CaseRow {
    case_id: String,
    is_negative: bool,
    price_source: String,
    resistance: String,
    action: String,
    has_unfiltered: bool,
}
