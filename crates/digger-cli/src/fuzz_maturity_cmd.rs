/// Fuzzing maturity report CLI command.
///
/// Static filesystem inspection of an EVM repository for fuzzing infrastructure.
/// This is a maturity signal — NOT a vulnerability detector and NOT fuzz execution.
/// Per ADR-0038: harness presence is not evidence of a bug.
pub fn run(path: &str, chain: &str, json: bool) {
    // 1. Validate chain (only EVM supported)
    if chain != "evm" {
        eprintln!(
            "Error: fuzz-maturity currently only supports --chain evm. \
             Solana fuzz maturity scanning is planned for a future release."
        );
        std::process::exit(1);
    }

    // 2. Validate path
    let dir = std::path::Path::new(path);
    if !dir.exists() {
        eprintln!("Error: Path not found: {}", path);
        std::process::exit(1);
    }

    // 3. Run the maturity scanner (static filesystem analysis — no execution)
    let report = digger_fuzz_maturity::scan_fuzzing_maturity(dir);

    // 4. Output
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("Error: failed to serialize report: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        print_human_report(&report);
    }
}

fn print_human_report(report: &digger_fuzz_maturity::MaturityReport) {
    println!("═══════════════════════════════════════════════");
    println!("  Digger Fuzzing Maturity Report");
    println!("═══════════════════════════════════════════════");
    println!();
    println!("  Chain:            {}", report.chain);
    println!("  Report type:      {}", report.report_type);
    println!("  Vulnerability:    {}", report.is_vulnerability_finding);
    println!("  Maturity score:   {}/100", report.maturity_score);
    println!("  Confidence:       {}", report.confidence_ceiling);
    println!("  Scanned path:     {}", report.scanned_path);
    println!();

    println!("── Signals Present ──");
    if report.signals_present.is_empty() {
        println!("  (none)");
    } else {
        for s in &report.signals_present {
            println!("  ✓ {}", s);
        }
    }
    println!();

    println!("── Signals Missing ──");
    for s in &report.signals_missing {
        println!("  · {}", s);
    }
    println!();

    if !report.vacuity_warnings.is_empty() {
        println!("── Vacuity Warnings ──");
        for w in &report.vacuity_warnings {
            println!("  ⚠ [{}] {}", w.category, w.message);
        }
        println!();
    }

    if !report.recommended_next_steps.is_empty() {
        println!("── Recommended Next Steps ──");
        for (i, step) in report.recommended_next_steps.iter().enumerate() {
            println!("  {}. {}", i + 1, step);
        }
        println!();
    }

    println!("── Limitations ──");
    for l in &report.limitations {
        println!("  • {}", l);
    }
    println!();
    println!("This is a static maturity report — not a vulnerability scan.");
    println!("It does not run fuzzers or ingest failure outputs.");
}
