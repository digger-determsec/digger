use digger_hypothesis::HypothesisResult;

pub fn print(result: &HypothesisResult) {
    print_with_suspicions(result, None);
}

pub fn print_with_suspicions(
    result: &HypothesisResult,
    suspensions: Option<&digger_hypothesis::suspicion::SuspicionResult>,
) {
    println!();
    println!("==============================");
    println!("      DIGGER SECURITY REPORT   ");
    println!("==============================");
    println!();

    if result.hypotheses.is_empty() {
        println!("No hypotheses generated.");
    } else {
        for (i, h) in result.hypotheses.iter().enumerate() {
            let severity_str = match h.severity {
                digger_ir::Severity::Critical => "CRITICAL",
                digger_ir::Severity::High => "HIGH",
                digger_ir::Severity::Medium => "MEDIUM",
                digger_ir::Severity::Low => "LOW",
                digger_ir::Severity::Info => "INFO",
            };

            println!("{}. [{}] {}", i + 1, severity_str, h.hypothesis_type);
            println!("   Function: {}", h.primary_function);
            println!("   Description: {}", h.description);
            println!("   Evidence:");
            for e in &h.evidence {
                for fact in &e.graph_facts {
                    println!(
                        "     - [{}] {}: {}",
                        fact.fact_type, fact.function, fact.detail
                    );
                }
            }
            println!("   Explanation: {}", h.structural_explanation);
            println!();
        }
    }

    if let Some(sus) = suspensions {
        if !sus.suspicions.is_empty() {
            println!("==============================");
            println!("UNPROVEN SUSPICIONS (knowledge-informed -- investigate, not findings)");
            println!("==============================");
            println!();
            for (i, s) in sus.suspicions.iter().enumerate() {
                println!(
                    "{}. [SUSPICION] {} on {}",
                    i + 1,
                    s.class,
                    s.primary_function
                );
                println!("   Reason: {}", s.structural_reason);
                println!(
                    "   Corpus prior: {} findings of class '{}'",
                    s.corpus_prior.finding_count, s.corpus_prior.matched_key
                );
                println!("   is_finding: {} (always false)", s.is_finding);
                println!();
            }
        }
    }

    println!("==============================");
    println!("Total Hypotheses: {}", result.hypotheses.len());
    println!(
        "Summary: {} reentrancy, {} authority_bypass, {} cpi_trust, {} state_corruption, {} economic, {} adversarial",
        result.summary.reentrancy_count,
        result.summary.authority_bypass_count,
        result.summary.cpi_trust_count,
        result.summary.state_corruption_count,
        result.summary.economic_invariant_violation_count,
        result.summary.adversarial_path_count,
    );
}
