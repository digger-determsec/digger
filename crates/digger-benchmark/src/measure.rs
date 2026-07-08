/// Measurement producer — runs real detectors over real corpus dirs,
/// producing per-detector DetectorMeasurements for the eval gate.
use crate::gate::DetectorMeasurement;
use crate::models::DetectorStatus;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Locked recall floors — per-class, set just below measured recall so losing
/// exactly one more TP trips the gate. Ratchet UP only: these values may
/// only rise in future commits.
const RECALL_FLOORS: &[(&str, f64)] = &[
    // access_control 9/10=0.90 → floor in (0.80, 0.90]
    ("solana_access_control", 0.89),
    // unvalidated_cpi 5/5=1.00 → floor in (0.80, 1.00] (one miss = 4/5=0.80)
    ("solana_unvalidated_cpi", 0.81),
    // unchecked_owner 3/5=0.60 → floor in (0.40, 0.60]
    ("solana_unchecked_account_owner", 0.59),
    // type_cosplay 3/4=0.75 → floor in (0.50, 0.75]
    ("solana_type_cosplay", 0.74),
    ("evm_price_oracle", 0.818), // unchanged — single-class, already correct
    // op_unverified_attestation 1/1=1.00 → floor in (0.90, 1.00]
    ("op_unverified_attestation", 0.99),
    // op_control_plane_authority 1/1=1.00 → floor in (0.90, 1.00]
    ("op_control_plane_authority", 0.99),
    // op_fail_open_bootstrap 1/1=1.00 → floor in (0.90, 1.00]
    ("op_fail_open_bootstrap", 0.99),
    // op_silent_failover 1/1=1.00 → floor in (0.90, 1.00]
    ("op_silent_failover", 0.99),
];

fn recall_floor_for(detector: &str) -> f64 {
    RECALL_FLOORS
        .iter()
        .find(|(d, _)| *d == detector)
        .map(|(_, f)| *f)
        .unwrap_or(0.0)
}

fn detector_status_for(detector: &str) -> DetectorStatus {
    if detector == "solana_access_control" {
        DetectorStatus::Frozen
    } else {
        DetectorStatus::Experimental
    }
}

/// Run real detectors over labeled + held-out corpus directories.
/// Returns per-detector measurements for both corpus types.
pub fn measure_detectors(labeled_dir: &Path, held_out_dir: &Path) -> Vec<DetectorMeasurement> {
    measure_detectors_multi(&[labeled_dir.to_path_buf()], held_out_dir)
}

/// Run real detectors over multiple labeled corpus dirs + a held-out dir.
pub fn measure_detectors_multi(
    labeled_dirs: &[PathBuf],
    held_out_dir: &Path,
) -> Vec<DetectorMeasurement> {
    let mut results = Vec::new();
    for dir in labeled_dirs {
        if dir.exists() {
            results.extend(measure_corpus(dir, "labeled"));
        }
    }
    if held_out_dir.exists() {
        results.extend(measure_corpus(held_out_dir, "held-out"));
    }
    results.sort_by(|a, b| {
        a.detector
            .cmp(&b.detector)
            .then(a.corpus_type.cmp(&b.corpus_type))
    });
    results
}

struct DetectorAccumulator {
    tp: usize,
    fp: usize,
    fn_count: usize,
    tn: usize,
}

impl DetectorAccumulator {
    fn new() -> Self {
        Self {
            tp: 0,
            fp: 0,
            fn_count: 0,
            tn: 0,
        }
    }

    fn record(&mut self, is_negative: bool, detected: bool) {
        match (is_negative, detected) {
            (false, true) => self.tp += 1,
            (false, false) => self.fn_count += 1,
            (true, true) => self.fp += 1,
            (true, false) => self.tn += 1,
        }
    }

    fn measurement(&self, detector: &str, corpus_type: &str) -> DetectorMeasurement {
        let precision = if self.tp + self.fp > 0 {
            self.tp as f64 / (self.tp + self.fp) as f64
        } else {
            0.0
        };
        let recall = if self.tp + self.fn_count > 0 {
            self.tp as f64 / (self.tp + self.fn_count) as f64
        } else {
            0.0
        };
        DetectorMeasurement {
            detector: detector.to_string(),
            corpus_type: corpus_type.to_string(),
            tp: self.tp,
            fp: self.fp,
            fn_count: self.fn_count,
            tn: self.tn,
            precision,
            recall,
            status: detector_status_for(detector),
            precision_floor: 1.0,
            recall_floor: recall_floor_for(detector),
        }
    }
}

fn measure_corpus(dir: &Path, corpus_type: &str) -> Vec<DetectorMeasurement> {
    let mut accumulators: BTreeMap<String, DetectorAccumulator> = BTreeMap::new();

    let detectors = [
        "solana_access_control",
        "solana_unvalidated_cpi",
        "solana_type_cosplay",
        "solana_unchecked_account_owner",
    ];
    for d in &detectors {
        accumulators.insert(d.to_string(), DetectorAccumulator::new());
    }
    accumulators.insert("evm_price_oracle".to_string(), DetectorAccumulator::new());
    accumulators.insert(
        "op_unverified_attestation".to_string(),
        DetectorAccumulator::new(),
    );

    let mut total_cases = 0usize;
    let mut swallowed_cases = 0usize;

    let entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.flatten().collect(),
        Err(_) => return Vec::new(),
    };

    for entry in entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let meta_path = path.join("meta.json");
        if !meta_path.exists() {
            continue;
        }
        let meta_str = match std::fs::read_to_string(&meta_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let meta: serde_json::Value = match serde_json::from_str(&meta_str) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let is_negative = meta
            .get("known_limitations")
            .and_then(|v| v.as_str())
            .map(|s| s.contains("NEGATIVE"))
            .or_else(|| {
                meta.get("expected_findings")
                    .and_then(|v| v.as_array())
                    .map(|a| a.is_empty())
            })
            .unwrap_or(false);

        let inner: Vec<_> = match std::fs::read_dir(&path) {
            Ok(rd) => rd.flatten().collect(),
            Err(_) => continue,
        };
        let src_file = inner.iter().find(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|e| e == "rs" || e == "sol" || e == "ts")
                .unwrap_or(false)
        });
        let src_path = match src_file {
            Some(e) => e.path(),
            None => continue,
        };
        let is_solana = src_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "rs")
            .unwrap_or(false);
        let is_oplayer = src_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "ts")
            .unwrap_or(false);

        let src = match std::fs::read_to_string(&src_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let recovered = if is_oplayer {
            let target = case_target_detectors(&meta);
            measure_op_case(&src, is_negative, &target, &mut accumulators);
            true
        } else if is_solana {
            let target = case_target_detectors(&meta);
            measure_solana_case(&src, is_negative, &target, &mut accumulators)
        } else {
            measure_evm_case(&src, is_negative, &mut accumulators)
        };
        total_cases += 1;
        if !recovered {
            swallowed_cases += 1;
        }
    }

    if swallowed_cases > 0 {
        eprintln!(
            "  WARNING: {}/{} cases in {} had recover_source_body_graph return None (swallowed)",
            swallowed_cases, total_cases, corpus_type
        );
    }

    accumulators
        .into_iter()
        .filter(|(_, acc)| acc.tp + acc.fp + acc.fn_count + acc.tn > 0)
        .map(|(det, acc)| acc.measurement(&det, corpus_type))
        .collect()
}

/// Run all four Solana detectors over one case, attributing results PER CLASS.
/// - Negative (benign) case: every detector is scored for precision/0-FP
///   (FP if it fires, TN otherwise).
/// - Positive case: scored for RECALL only against the detector(s) in
///   `target_detectors` (TP if fires, FN otherwise). Positives of a DIFFERENT
///   class are intentionally NOT counted for this detector.
///
/// Returns `false` if the body did not recover (so the caller can track swallows).
fn measure_solana_case(
    src: &str,
    is_negative: bool,
    target_detectors: &std::collections::BTreeSet<String>,
    accumulators: &mut BTreeMap<String, DetectorAccumulator>,
) -> bool {
    let raw = digger_parser::parse_program(src, "anchor");
    let body = match digger_reconstruct::recover_source_body_graph(&raw) {
        Some(b) => b,
        None => return false,
    };

    let fired: [(&str, bool); 4] = [
        (
            "solana_access_control",
            !digger_reconstruct::detect_solana_access_violations(&body).is_empty(),
        ),
        (
            "solana_unvalidated_cpi",
            !digger_reconstruct::detect_unvalidated_cpi(&body).is_empty(),
        ),
        (
            "solana_type_cosplay",
            !digger_reconstruct::detect_type_cosplay(&body).is_empty(),
        ),
        (
            "solana_unchecked_account_owner",
            !digger_reconstruct::detect_unchecked_owner(&body).is_empty(),
        ),
    ];

    for (detector, detected) in fired {
        if is_negative {
            accumulators
                .entry(detector.into())
                .or_insert_with(DetectorAccumulator::new)
                .record(true, detected);
        } else if target_detectors.contains(detector) {
            accumulators
                .entry(detector.into())
                .or_insert_with(DetectorAccumulator::new)
                .record(false, detected);
        }
        // positive case, non-target detector → not applicable, not counted.
    }
    true
}

fn measure_evm_case(
    src: &str,
    is_negative: bool,
    accumulators: &mut BTreeMap<String, DetectorAccumulator>,
) -> bool {
    let raw = digger_parser::parse_program(src, "solidity");
    let findings = digger_reconstruct::detect_price_manipulation(src, &raw);
    let detected = findings.iter().any(|f| !f.suppressed);
    accumulators
        .entry("evm_price_oracle".into())
        .or_insert_with(DetectorAccumulator::new)
        .record(is_negative, detected);
    true
}

/// Run op-layer detectors on a TS source case, scoring each per-class.
fn measure_op_case(
    src: &str,
    is_negative: bool,
    target_detectors: &std::collections::BTreeSet<String>,
    accumulators: &mut BTreeMap<String, DetectorAccumulator>,
) -> bool {
    let program = digger_oplayer::parse_op_program(src);

    let fired: [(&str, bool); 4] = [
        (
            "op_unverified_attestation",
            !digger_oplayer::detect_unverified_attestation(&program).is_empty(),
        ),
        (
            "op_control_plane_authority",
            !digger_oplayer::detect_control_plane_authority(&program).is_empty(),
        ),
        (
            "op_fail_open_bootstrap",
            !digger_oplayer::detect_fail_open_bootstrap(&program).is_empty(),
        ),
        (
            "op_silent_failover",
            !digger_oplayer::detect_silent_failover(&program).is_empty(),
        ),
    ];

    for (detector, detected) in fired {
        if is_negative {
            accumulators
                .entry(detector.into())
                .or_insert_with(DetectorAccumulator::new)
                .record(true, detected);
        } else if target_detectors.contains(detector) {
            accumulators
                .entry(detector.into())
                .or_insert_with(DetectorAccumulator::new)
                .record(false, detected);
        }
    }
    true
}

/// Map a case's meta.json to the set of detector ids it is a POSITIVE for.
/// Benign/unmapped cases return an empty set (scored for FP/TN only, never recall).
pub fn case_target_detectors(meta: &serde_json::Value) -> std::collections::BTreeSet<String> {
    let mut set = std::collections::BTreeSet::new();
    if let Some(arr) = meta.get("expected_findings").and_then(|v| v.as_array()) {
        for f in arr {
            let id = f
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| {
                    f.get("detector")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .or_else(|| {
                    f.get("rule")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .or_else(|| {
                    f.get("class")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                });
            if let Some(id) = id {
                if let Some(det) = normalize_detector_id(&id) {
                    set.insert(det.to_string());
                }
            }
        }
    }
    set
}

/// Canonicalize a class/rule label to a detector id.
/// Order matters — check the most specific substrings first.
pub fn normalize_detector_id(raw: &str) -> Option<&'static str> {
    let r = raw.to_lowercase();
    if r.contains("price") || r.contains("oracle") || r.contains("twap") {
        Some("evm_price_oracle")
    } else if r.contains("fail_open") || r.contains("bootstrap") || r.contains("fail_closed") {
        Some("op_fail_open_bootstrap")
    } else if r.contains("failover") || r.contains("silent_failover") {
        Some("op_silent_failover")
    } else if r.contains("unverified_attestation") || r.contains("attestation") {
        Some("op_unverified_attestation")
    } else if r.contains("control_plane")
        || r.contains("routing")
        || r.contains("allowlist")
        || r.contains("unauthorized_control")
    {
        Some("op_control_plane_authority")
    } else if r.contains("unvalidated_cpi") || r.contains("cpi") {
        Some("solana_unvalidated_cpi")
    } else if r.contains("unchecked_owner") || r.contains("owner") {
        Some("solana_unchecked_account_owner")
    } else if r.contains("type_cosplay") || r.contains("cosplay") || r.contains("discriminator") {
        Some("solana_type_cosplay")
    } else if r.contains("access") || r.contains("signer") || r.contains("authority") {
        Some("solana_access_control")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_detectors_are_per_class() {
        let cpi = serde_json::json!({ "expected_findings": ["UnvalidatedCpi"] });
        let t = case_target_detectors(&cpi);
        assert!(
            t.contains("solana_unvalidated_cpi"),
            "CPI case maps to CPI detector"
        );
        assert!(
            !t.contains("solana_access_control"),
            "CPI case must NOT map to access-control"
        );
        assert_eq!(t.len(), 1);

        let owner = serde_json::json!({ "expected_findings": ["UncheckedAccountOwner"] });
        let t2 = case_target_detectors(&owner);
        assert!(t2.contains("solana_unchecked_account_owner"));
        assert!(!t2.contains("solana_unvalidated_cpi"));

        let cosplay = serde_json::json!({ "expected_findings": ["TypeCosplay"] });
        let t3 = case_target_detectors(&cosplay);
        assert!(t3.contains("solana_type_cosplay"));
        assert_eq!(t3.len(), 1);

        let access = serde_json::json!({ "expected_findings": ["MissingAuthorityCheck"] });
        let t4 = case_target_detectors(&access);
        assert!(t4.contains("solana_access_control"));
        assert_eq!(t4.len(), 1);

        assert!(case_target_detectors(&serde_json::json!({ "expected_findings": [] })).is_empty());
    }

    #[test]
    fn corpus_positive_counts_only_its_own_class() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let dir = root.join("corpus/solana-account-model");
        if !dir.exists() {
            return;
        }
        let mut checked = 0usize;
        for case in std::fs::read_dir(&dir)
            .into_iter()
            .flat_map(|rd| rd.into_iter().filter_map(|e| e.ok()))
        {
            let p = case.path();
            if !p.is_dir() {
                continue;
            }
            let mp = p.join("meta.json");
            if !mp.exists() {
                continue;
            }
            let meta: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&mp).unwrap_or_default())
                    .unwrap_or_default();
            let is_neg = meta
                .get("expected_findings")
                .and_then(|v| v.as_array())
                .map(|a| a.is_empty())
                .unwrap_or(false);
            let target = case_target_detectors(&meta);
            if is_neg || target.is_empty() {
                continue;
            }
            let sf = std::fs::read_dir(&p)
                .into_iter()
                .flat_map(|rd| rd.into_iter().filter_map(|e| e.ok()))
                .find(|e| e.path().extension().map(|x| x == "rs").unwrap_or(false));
            let src = match sf {
                Some(s) => std::fs::read_to_string(s.path()).unwrap(),
                None => continue,
            };
            let mut acc: BTreeMap<String, DetectorAccumulator> = BTreeMap::new();
            if !measure_solana_case(&src, false, &target, &mut acc) {
                continue;
            }
            let counted: std::collections::BTreeSet<String> = acc
                .iter()
                .filter(|(_, a)| a.tp + a.fp + a.fn_count + a.tn > 0)
                .map(|(k, _)| k.clone())
                .collect();
            assert_eq!(
                counted,
                target,
                "case {:?}: counted {:?} must equal its target class {:?}",
                p.file_name(),
                counted,
                target
            );
            checked += 1;
        }
        assert!(checked > 0, "must check >=1 positive (non-vacuous)");
    }
}
