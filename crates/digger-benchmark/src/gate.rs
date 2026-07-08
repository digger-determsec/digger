use crate::models::DetectorStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorMeasurement {
    pub detector: String,
    pub corpus_type: String,
    pub tp: usize,
    pub fp: usize,
    pub fn_count: usize,
    pub tn: usize,
    pub precision: f64,
    pub recall: f64,
    pub status: DetectorStatus,
    pub precision_floor: f64,
    pub recall_floor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalGateReport {
    pub measurements: Vec<DetectorMeasurement>,
    pub held_out_fp_violations: Vec<String>,
    pub precision_violations: Vec<String>,
    pub recall_violations: Vec<String>,
    pub gate_passed: bool,
}

pub fn evaluate_gate(
    labeled: &[DetectorMeasurement],
    held_out: &[DetectorMeasurement],
) -> EvalGateReport {
    let mut held_out_fp = Vec::new();
    let mut precision_violations = Vec::new();
    let mut recall_violations = Vec::new();
    let mut all_measurements = Vec::new();

    for m in held_out {
        all_measurements.push(m.clone());
        if m.fp > 0 {
            held_out_fp.push(format!("{}: {} FP on held-out", m.detector, m.fp));
            precision_violations.push(format!(
                "{}: {} FP on held-out corpus (precision {:.1}% < floor {:.1}%)",
                m.detector,
                m.fp,
                m.precision * 100.0,
                m.precision_floor * 100.0
            ));
        }
    }
    for m in labeled {
        all_measurements.push(m.clone());
        if m.recall < m.recall_floor {
            recall_violations.push(format!(
                "{}: recall {:.1}% < floor {:.1}%",
                m.detector,
                m.recall * 100.0,
                m.recall_floor * 100.0
            ));
        }
        if m.fp > 0 {
            precision_violations.push(format!(
                "{}: {} FP on labeled corpus (precision {:.1}% < floor {:.1}%)",
                m.detector,
                m.fp,
                m.precision * 100.0,
                m.precision_floor * 100.0
            ));
        }
    }

    let gate_passed =
        held_out_fp.is_empty() && precision_violations.is_empty() && recall_violations.is_empty();
    EvalGateReport {
        measurements: all_measurements,
        held_out_fp_violations: held_out_fp,
        precision_violations,
        recall_violations,
        gate_passed,
    }
}
