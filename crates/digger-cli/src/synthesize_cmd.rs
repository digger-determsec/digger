/// Synthesize command — runs the Gen 3 exploit synthesis engine.
use digger_graph::build_system_ir_with_language;
use digger_parser::parse_program;
use digger_synthesis::engine::{synthesize, SynthesisConfig, SynthesisInputs};

pub fn run(path: String, lang: String, json_output: bool, output_path: Option<String>) {
    // 1. Read source
    let code = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot read '{}': {}", path, e);
            std::process::exit(1);
        }
    };

    if code.trim().is_empty() {
        eprintln!("error: file '{}' is empty", path);
        std::process::exit(1);
    }

    if !json_output {
        eprintln!(
            "  parsing {} ({:.1} KB) ...",
            path,
            code.len() as f64 / 1024.0
        );
    }

    // 2. Parse
    let raw = parse_program(&code, &lang);

    // 3. Build IR
    let language = match lang.as_str() {
        "solidity" | "sol" => digger_ir::Language::Solidity,
        "anchor" => digger_ir::Language::Anchor,
        "rust" | "rs" => digger_ir::Language::Rust,
        _ => digger_ir::Language::Unknown,
    };
    let ir = build_system_ir_with_language(raw, language);

    if !json_output {
        eprintln!(
            "  systemir: {} functions, {} state vars, {} edges",
            ir.functions.len(),
            ir.state.len(),
            ir.edges.len()
        );
        eprintln!("  synthesizing exploit chains ...");
    }

    // 4. Run Gen 3 synthesis
    let inputs = SynthesisInputs {
        ir: Some(&ir),
        expansion: None,
        transitions: None,
        lifecycles: None,
        temporal: None,
        actors: None,
        economics: None,
        verification: None,
        adversarial: None,
        protocol: None,
        surface: None,
    };

    let config = SynthesisConfig::default();
    let report = synthesize(&inputs, &config);

    if !json_output {
        eprintln!(
            "  synthesized {} chains, {} viable, {} confirmed",
            report.total_chains,
            report.viable_chains,
            report.confirmations.len()
        );
    }

    // 5. Output
    if json_output {
        let json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into());
        if let Some(path) = output_path {
            match std::fs::write(&path, &json) {
                Ok(_) => println!("Report exported to: {}", path),
                Err(e) => eprintln!("Error writing report: {}", e),
            }
        } else {
            println!("{}", json);
        }
    } else {
        print_report(&report);
    }
}

fn print_report(report: &digger_synthesis::ExploitSearchReport) {
    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("  DIGGER GEN 3 — EXPLOIT SYNTHESIS REPORT");
    println!("═══════════════════════════════════════════════════════════");
    println!("Protocol: {}", report.protocol_id);
    println!("Chains synthesized: {}", report.total_chains);
    println!("Viable chains: {}", report.viable_chains);
    println!("Eliminated: {}", report.eliminated_chains);
    println!();

    if report.rankings.is_empty() {
        println!("No viable exploit chains found.");
    } else {
        println!("─── Ranked Exploit Chains ───────────────────────────────");
        for ranking in &report.rankings {
            println!(
                "  #{} [score: {:.3}] Chain: {}",
                ranking.rank, ranking.score, ranking.chain_id
            );
        }

        println!();
        println!("─── Explanations ───────────────────────────────────────");
        for explanation in &report.explanations {
            println!("  Chain: {}", explanation.chain_id);
            println!("  Summary: {}", explanation.summary);
            println!("  Steps:");
            for step in &explanation.step_explanations {
                println!("    {}. {}", step.step + 1, step.explanation);
                println!("       Reason: {}", step.success_reason);
            }
            println!("  Mitigation: {}", explanation.mitigation);
            println!();
        }

        println!("─── Simulations ────────────────────────────────────────");
        for sim in &report.simulations {
            println!(
                "  Chain: {} — {}",
                sim.chain_id,
                if sim.success { "SUCCESS" } else { "FAILED" }
            );
            println!("  Steps simulated: {}", sim.step_states.len());
            println!(
                "  Invariant violations: {}",
                sim.final_state.violated_invariants.len()
            );
            if !sim.final_state.violated_invariants.is_empty() {
                for inv in &sim.final_state.violated_invariants {
                    println!("    - {}", inv);
                }
            }
            println!(
                "  Economic impact: {} asset(s) affected",
                sim.economic_impact.assets_lost.len()
            );
            println!("  {}", sim.explanation);
            println!();
        }
    }

    println!("═══════════════════════════════════════════════════════════");
}
