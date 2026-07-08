/// Fuzz evidence report CLI command.
///
/// Read-only parsing of existing fuzz invariant failure artifacts.
/// No fuzz execution, no vulnerability findings emitted.
/// Per ADR-0038: fuzz failure becomes evidence only when artifact-backed.
pub fn run(tool: &str, chain: &str, artifact: &str, json: bool) {
    let evm_tools = ["foundry", "echidna", "medusa"];
    let solana_tools = ["crucible"];

    let is_evm_tool = evm_tools.contains(&tool);
    let is_solana_tool = solana_tools.contains(&tool);

    if !is_evm_tool && !is_solana_tool {
        eprintln!(
            "Error: fuzz-evidence supports --tool foundry, echidna, medusa (EVM), or crucible (Solana)."
        );
        std::process::exit(1);
    }

    // Validate chain matches tool family
    if is_evm_tool && chain != "evm" {
        eprintln!(
            "Error: --tool {} requires --chain evm. Got --chain {}.",
            tool, chain
        );
        std::process::exit(1);
    }
    if is_solana_tool && chain != "solana" {
        eprintln!(
            "Error: --tool {} requires --chain solana. Got --chain {}.",
            tool, chain
        );
        std::process::exit(1);
    }

    // Parse the artifact
    let path = std::path::Path::new(artifact);
    let report = match tool {
        "echidna" => match digger_fuzz_maturity::parse_echidna_failure_file(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        "medusa" => match digger_fuzz_maturity::parse_medusa_failure_file(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        "crucible" => match digger_fuzz_maturity::parse_crucible_failure_file(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        _ => match digger_fuzz_maturity::parse_foundry_failure_file(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
    };

    // Output
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("Error: failed to serialize report: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("═══════════════════════════════════════════════");
        println!("  Digger Fuzz Evidence Report");
        println!("═══════════════════════════════════════════════");
        println!();
        println!("  Tool:            {}", report.tool);
        println!("  Chain:           {}", report.chain);
        println!("  Report type:     {}", report.report_type);
        println!("  Vulnerability:   {}", report.is_vulnerability_finding);
        println!("  Confidence:      {}", report.confidence_ceiling);
        if let Some(ref name) = report.invariant_name {
            println!("  Invariant:       {}", name);
        }
        if let Some(ref name) = report.test_name {
            println!("  Test:            {}", name);
        }
        if let Some(ref ce) = report.counterexample {
            println!("  Counterexample:  {}", ce);
        }
        if let Some(ref rc) = report.replay_command {
            println!("  Replay command:  {}", rc);
        }
        println!();
        println!("── Limitations ──");
        for l in &report.limitations {
            println!("  • {}", l);
        }
        println!();
        println!("Fuzz evidence report, not a confirmed vulnerability finding.");
    }
}
