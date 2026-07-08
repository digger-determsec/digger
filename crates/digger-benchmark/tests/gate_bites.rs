use digger_benchmark::{evaluate_gate, DetectorMeasurement, DetectorStatus};

fn clean_measurement(detector: &str) -> DetectorMeasurement {
    DetectorMeasurement {
        detector: detector.into(),
        corpus_type: "labeled".into(),
        tp: 10,
        fp: 0,
        fn_count: 2,
        tn: 10,
        precision: 1.0,
        recall: 0.833,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.4,
    }
}

#[test]
fn test_gate_passes_clean() {
    let labeled = vec![clean_measurement("solana_access_control")];
    let held_out = vec![DetectorMeasurement {
        detector: "solana_access_control".into(),
        corpus_type: "held-out".into(),
        tp: 0,
        fp: 0,
        fn_count: 0,
        tn: 8,
        precision: 1.0,
        recall: 0.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.0,
    }];
    let report = evaluate_gate(&labeled, &held_out);
    assert!(report.gate_passed, "clean run must pass");
}

#[test]
fn test_gate_catches_planted_fp() {
    let labeled = vec![clean_measurement("solana_access_control")];
    let held_out = vec![DetectorMeasurement {
        detector: "solana_access_control".into(),
        corpus_type: "held-out".into(),
        tp: 0,
        fp: 1,
        fn_count: 0,
        tn: 7,
        precision: 0.0,
        recall: 0.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.0,
    }];
    let report = evaluate_gate(&labeled, &held_out);
    assert!(!report.gate_passed, "must FAIL when held-out has FP");
    assert_eq!(report.held_out_fp_violations.len(), 1);
}

#[test]
fn test_gate_catches_recall_drop() {
    let labeled = vec![DetectorMeasurement {
        detector: "solana_access_control".into(),
        corpus_type: "labeled".into(),
        tp: 3,
        fp: 0,
        fn_count: 14,
        tn: 10,
        precision: 1.0,
        recall: 0.176,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.4,
    }];
    let held_out = vec![];
    let report = evaluate_gate(&labeled, &held_out);
    assert!(
        !report.gate_passed,
        "must FAIL when recall drops below floor"
    );
    assert_eq!(report.recall_violations.len(), 1);
}

#[test]
fn test_gate_catches_planted_fp_on_labeled() {
    let mut m = clean_measurement("solana_unvalidated_cpi");
    m.fp = 1;
    m.tn = 9;
    m.precision = m.tp as f64 / (m.tp + m.fp) as f64;
    let report = evaluate_gate(&[m], &[]);
    assert!(!report.gate_passed, "must FAIL on a labeled-corpus FP");
    assert_eq!(report.precision_violations.len(), 1);
    assert!(
        report.held_out_fp_violations.is_empty(),
        "a labeled FP is a precision violation, not a held-out FP"
    );
}

#[test]
fn test_gate_clean_has_no_precision_violations() {
    let report = evaluate_gate(&[clean_measurement("solana_access_control")], &[]);
    assert!(report.gate_passed);
    assert!(report.precision_violations.is_empty());
}

#[test]
fn test_op_layer_floor_bites() {
    let m = DetectorMeasurement {
        detector: "op_unverified_attestation".into(),
        corpus_type: "labeled".into(),
        tp: 1,
        fp: 0,
        fn_count: 0,
        tn: 1,
        precision: 1.0,
        recall: 1.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.99,
    };
    let report = evaluate_gate(std::slice::from_ref(&m), &[]);
    assert!(report.gate_passed, "op-layer 1/1 recall must pass floor");

    let mut m_fail = m.clone();
    m_fail.recall = 0.0;
    m_fail.fn_count = 1;
    let report_fail = evaluate_gate(&[m_fail], &[]);
    assert!(
        !report_fail.gate_passed,
        "op-layer floor must bite when recall drops to 0"
    );
    assert!(!report_fail.recall_violations.is_empty());
}

#[test]
fn test_op_layer_fp_lock() {
    let labeled = vec![DetectorMeasurement {
        detector: "op_unverified_attestation".into(),
        corpus_type: "labeled".into(),
        tp: 1,
        fp: 0,
        fn_count: 0,
        tn: 1,
        precision: 1.0,
        recall: 1.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.99,
    }];
    let held_out = vec![DetectorMeasurement {
        detector: "op_unverified_attestation".into(),
        corpus_type: "held-out".into(),
        tp: 0,
        fp: 1,
        fn_count: 0,
        tn: 0,
        precision: 0.0,
        recall: 0.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.0,
    }];
    let report = evaluate_gate(&labeled, &held_out);
    assert!(
        !report.gate_passed,
        "op-layer gate must FAIL when held-out has FP"
    );
    assert!(!report.held_out_fp_violations.is_empty());
}

#[test]
fn test_op_cp_floor_bites() {
    let m = DetectorMeasurement {
        detector: "op_control_plane_authority".into(),
        corpus_type: "labeled".into(),
        tp: 1,
        fp: 0,
        fn_count: 0,
        tn: 1,
        precision: 1.0,
        recall: 1.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.99,
    };
    let report = evaluate_gate(std::slice::from_ref(&m), &[]);
    assert!(report.gate_passed, "op_cp 1/1 recall must pass floor");

    let mut m_fail = m.clone();
    m_fail.recall = 0.0;
    m_fail.fn_count = 1;
    let report_fail = evaluate_gate(&[m_fail], &[]);
    assert!(
        !report_fail.gate_passed,
        "op_cp floor must bite when recall drops to 0"
    );
    assert!(!report_fail.recall_violations.is_empty());
}

#[test]
fn test_op_cp_fp_lock() {
    let labeled = vec![DetectorMeasurement {
        detector: "op_control_plane_authority".into(),
        corpus_type: "labeled".into(),
        tp: 1,
        fp: 0,
        fn_count: 0,
        tn: 1,
        precision: 1.0,
        recall: 1.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.99,
    }];
    let held_out = vec![DetectorMeasurement {
        detector: "op_control_plane_authority".into(),
        corpus_type: "held-out".into(),
        tp: 0,
        fp: 1,
        fn_count: 0,
        tn: 0,
        precision: 0.0,
        recall: 0.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.0,
    }];
    let report = evaluate_gate(&labeled, &held_out);
    assert!(
        !report.gate_passed,
        "op_cp gate must FAIL when held-out has FP"
    );
    assert!(!report.held_out_fp_violations.is_empty());
}

#[test]
fn test_op_fob_floor_bites() {
    let m = DetectorMeasurement {
        detector: "op_fail_open_bootstrap".into(),
        corpus_type: "labeled".into(),
        tp: 1,
        fp: 0,
        fn_count: 0,
        tn: 1,
        precision: 1.0,
        recall: 1.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.99,
    };
    let report = evaluate_gate(std::slice::from_ref(&m), &[]);
    assert!(report.gate_passed, "op_fob 1/1 recall must pass floor");

    let mut m_fail = m.clone();
    m_fail.recall = 0.0;
    m_fail.fn_count = 1;
    let report_fail = evaluate_gate(&[m_fail], &[]);
    assert!(
        !report_fail.gate_passed,
        "op_fob floor must bite when recall drops to 0"
    );
    assert!(!report_fail.recall_violations.is_empty());
}

#[test]
fn test_op_fob_fp_lock() {
    let labeled = vec![DetectorMeasurement {
        detector: "op_fail_open_bootstrap".into(),
        corpus_type: "labeled".into(),
        tp: 1,
        fp: 0,
        fn_count: 0,
        tn: 1,
        precision: 1.0,
        recall: 1.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.99,
    }];
    let held_out = vec![DetectorMeasurement {
        detector: "op_fail_open_bootstrap".into(),
        corpus_type: "held-out".into(),
        tp: 0,
        fp: 1,
        fn_count: 0,
        tn: 0,
        precision: 0.0,
        recall: 0.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.0,
    }];
    let report = evaluate_gate(&labeled, &held_out);
    assert!(
        !report.gate_passed,
        "op_fob gate must FAIL when held-out has FP"
    );
    assert!(!report.held_out_fp_violations.is_empty());
}

#[test]
fn test_op_failover_floor_bites() {
    let m = DetectorMeasurement {
        detector: "op_silent_failover".into(),
        corpus_type: "labeled".into(),
        tp: 1,
        fp: 0,
        fn_count: 0,
        tn: 1,
        precision: 1.0,
        recall: 1.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.99,
    };
    let report = evaluate_gate(std::slice::from_ref(&m), &[]);
    assert!(report.gate_passed, "op_failover 1/1 recall must pass floor");

    let mut m_fail = m.clone();
    m_fail.recall = 0.0;
    m_fail.fn_count = 1;
    let report_fail = evaluate_gate(&[m_fail], &[]);
    assert!(
        !report_fail.gate_passed,
        "op_failover floor must bite when recall drops to 0"
    );
    assert!(!report_fail.recall_violations.is_empty());
}

#[test]
fn test_op_failover_fp_lock() {
    let labeled = vec![DetectorMeasurement {
        detector: "op_silent_failover".into(),
        corpus_type: "labeled".into(),
        tp: 1,
        fp: 0,
        fn_count: 0,
        tn: 1,
        precision: 1.0,
        recall: 1.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.99,
    }];
    let held_out = vec![DetectorMeasurement {
        detector: "op_silent_failover".into(),
        corpus_type: "held-out".into(),
        tp: 0,
        fp: 1,
        fn_count: 0,
        tn: 0,
        precision: 0.0,
        recall: 0.0,
        status: DetectorStatus::Experimental,
        precision_floor: 1.0,
        recall_floor: 0.0,
    }];
    let report = evaluate_gate(&labeled, &held_out);
    assert!(
        !report.gate_passed,
        "op_failover gate must FAIL when held-out has FP"
    );
    assert!(!report.held_out_fp_violations.is_empty());
}
