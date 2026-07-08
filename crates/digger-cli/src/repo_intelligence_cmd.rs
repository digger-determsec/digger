use std::path::Path;

pub fn run(path: &str, chain: &str, json: bool) {
    let root = Path::new(path);
    if !root.exists() {
        eprintln!("Error: path does not exist: {}", path);
        std::process::exit(1);
    }

    let chain_enum = match chain {
        "evm" => digger_repo_intelligence::Chain::Evm,
        "solana" => digger_repo_intelligence::Chain::Solana,
        _ => {
            eprintln!(
                "Error: unsupported chain '{}'. Supported: evm, solana.",
                chain
            );
            std::process::exit(1);
        }
    };

    let input = digger_repo_intelligence::RepoIntelligenceInput {
        root: root.to_path_buf(),
        chain: chain_enum,
    };

    let report = match digger_repo_intelligence::scan_repo(input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

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
        println!("  Digger Repository Intelligence Report");
        println!("═══════════════════════════════════════════════");
        println!();
        println!("  Schema version:  {}", report.schema_version);
        println!("  Digger version:  {}", report.digger_version);
        println!("  Chain:           {}", report.chain);
        println!("  Surfaces:        {}", report.summary.surface_count);
        println!("  Unknowns:        {}", report.summary.unknown_count);
        println!();
        println!("Fuzz evidence report, not a confirmed vulnerability finding.");
    }
}
