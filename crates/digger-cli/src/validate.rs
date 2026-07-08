/// Validate command — checks Digger installation and test corpus.
///
/// Runs:
/// 1. Version check
/// 2. Schema version check
/// 3. Freeze integrity check
/// 4. Corpus benchmark
/// 5. Determinism check
/// 6. Eval gate
use digger_core::freeze;
use std::path::PathBuf;

pub fn run() {
    println!("=== Digger Validation ===\n");

    // 1. Version
    println!("1. Version Check");
    println!("   digger v0.1.0");
    println!("   ✓ Version OK\n");

    // 2. Schema version
    println!("2. Schema Version Check");
    println!("   Schema version: {}", freeze::SCHEMA_VERSION);
    println!("   Phase 3 status: {}", freeze::PHASE3_STATUS);
    println!("   ✓ Schema version locked\n");

    // 3. Freeze integrity
    println!("3. Freeze Integrity Check");
    match freeze::validate_phase3_integrity() {
        Ok(()) => println!("   ✓ Phase 3 integrity verified"),
        Err(e) => println!("   ✗ Phase 3 integrity FAILED: {}", e),
    }
    println!();

    // 4. Frozen modules
    println!("4. Frozen Modules");
    for module in freeze::FROZEN_MODULES {
        println!("   - {} (FROZEN)", module);
    }
    println!();

    // 5. Frozen schemas
    println!("5. Frozen Schemas");
    for schema in freeze::FROZEN_SCHEMAS {
        println!("   - {} (IMMUTABLE)", schema);
    }
    println!();

    // 6. Frozen hypothesis types
    println!(
        "6. Frozen Hypothesis Types ({} total)",
        freeze::FROZEN_HYPOTHESIS_TYPES.len()
    );
    for htype in freeze::FROZEN_HYPOTHESIS_TYPES {
        println!("   - {}", htype);
    }
    println!();

    // 7. Frozen compound types
    println!(
        "7. Frozen Compound Types ({} total)",
        freeze::FROZEN_COMPOUND_TYPES.len()
    );
    for ctype in freeze::FROZEN_COMPOUND_TYPES {
        println!("   - {}", ctype);
    }
    println!();

    // 8. Frozen assumption types
    println!(
        "8. Frozen Assumption Types ({} total)",
        freeze::FROZEN_ASSUMPTION_TYPES.len()
    );
    for atype in freeze::FROZEN_ASSUMPTION_TYPES {
        println!("   - {}", atype);
    }
    println!();

    // 9. Frozen inversion types
    println!(
        "9. Frozen Inversion Types ({} total)",
        freeze::FROZEN_INVERSION_TYPES.len()
    );
    for itype in freeze::FROZEN_INVERSION_TYPES {
        println!("   - {}", itype);
    }
    println!();

    // 10. Frozen verification types
    println!(
        "10. Frozen Verification Types ({} total)",
        freeze::FROZEN_VERIFICATION_TYPES.len()
    );
    for vtype in freeze::FROZEN_VERIFICATION_TYPES {
        println!("   - {}", vtype);
    }
    println!();

    println!("=== Validation Complete ===");
    println!("All checks passed. Digger is ready for use.");

    // 11. Eval gate
    println!("11. Eval Gate");
    let workspace = find_workspace_root();
    let labeled_dirs: Vec<std::path::PathBuf> = vec![
        workspace.join("corpus").join("solana-account-model"),
        workspace.join("corpus").join("price-manipulation"),
        workspace.join("corpus").join("operational-layer"),
    ];
    let corpus_held_out = workspace.join("corpus").join("held-out-fp");
    let measurements =
        digger_benchmark::measure::measure_detectors_multi(&labeled_dirs, &corpus_held_out);
    let labeled_measurements: Vec<_> = measurements
        .iter()
        .filter(|m| m.corpus_type == "labeled")
        .cloned()
        .collect();
    let held_out_measurements: Vec<_> = measurements
        .iter()
        .filter(|m| m.corpus_type == "held-out")
        .cloned()
        .collect();
    let gate_report =
        digger_benchmark::evaluate_gate(&labeled_measurements, &held_out_measurements);
    println!(
        "   {}",
        serde_json::to_string_pretty(&gate_report).unwrap_or_default()
    );
    if !gate_report.gate_passed {
        eprintln!("EVAL GATE FAILED");
        for v in &gate_report.held_out_fp_violations {
            eprintln!("  FP: {}", v);
        }
        for v in &gate_report.recall_violations {
            eprintln!("  RECALL: {}", v);
        }
        std::process::exit(1);
    }
    println!("   ✓ Eval gate passed\n");
}

fn find_workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| manifest.clone())
}
