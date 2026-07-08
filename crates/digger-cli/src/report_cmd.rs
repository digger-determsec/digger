use digger_graph::build_system_ir;
use digger_hypothesis::derive;
use digger_parser::parse_program;
use digger_surface::SecurityIntelligenceOutput;
/// Report command — generates a detailed triage report (JSON + Markdown).
///
/// Produces:
/// - digger-report.json (SecurityIntelligenceOutput)
/// - digger-report.md (human-readable Markdown report)
use std::path::Path;

pub fn run(path: String, lang: String, output_dir: String) {
    let code = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Cannot read file '{}': {}", path, e);
            std::process::exit(1);
        }
    };

    if code.trim().is_empty() {
        eprintln!("Error: File '{}' is empty", path);
        std::process::exit(1);
    }

    let raw = parse_program(&code, &lang);
    let ir = build_system_ir(raw);
    let result = derive(&ir);
    let surface = SecurityIntelligenceOutput::build(&ir);

    // Validate
    let errors = surface.validate();
    if !errors.is_empty() {
        eprintln!("Warning: Surface output validation issues:");
        for err in &errors {
            eprintln!("  - {}", err);
        }
    }

    // Write JSON report
    let json_path = Path::new(&output_dir).join("digger-report.json");
    let json = surface.to_json();
    match std::fs::write(&json_path, &json) {
        Ok(_) => println!("JSON report: {}", json_path.display()),
        Err(e) => eprintln!("Error writing JSON report: {}", e),
    }

    // Write Markdown report
    let md_path = Path::new(&output_dir).join("digger-report.md");
    let md = generate_markdown_report(&surface, &result, &path);
    match std::fs::write(&md_path, &md) {
        Ok(_) => println!("Markdown report: {}", md_path.display()),
        Err(e) => eprintln!("Error writing Markdown report: {}", e),
    }

    // Print summary
    println!();
    println!("=== Digger Audit Report ===");
    println!("Source: {}", path);
    println!("Language: {}", lang);
    println!("Functions: {}", surface.metadata.total_functions);
    println!("Edges: {}", surface.metadata.total_edges);
    println!("Hypotheses: {}", result.hypotheses.len());
    println!(
        "Entry Points: {}",
        surface.attack_surface.summary.total_entry_points
    );
    println!(
        "Unguarded: {}",
        surface.attack_surface.summary.unguarded_entry_points
    );
    println!(
        "Enforcement Rate: {:.0}%",
        surface.attack_surface.summary.enforcement_rate * 100.0
    );
}

fn generate_markdown_report(
    surface: &SecurityIntelligenceOutput,
    result: &digger_hypothesis::HypothesisResult,
    source_path: &str,
) -> String {
    let mut md = String::new();

    md.push_str("# Digger Security Audit Report\n\n");
    md.push_str(&format!("**Source:** `{}`\n", source_path));
    md.push_str(&format!("**Schema Version:** {}\n", surface.version));
    md.push_str(&format!(
        "**Analysis Depth:** {}\n",
        surface.metadata.analysis_depth
    ));
    md.push_str("\n---\n\n");

    // Summary
    md.push_str("## Summary\n\n");
    md.push_str(&format!("| Metric | Value |\n"));
    md.push_str(&format!("|--------|-------|\n"));
    md.push_str(&format!(
        "| Functions | {} |\n",
        surface.metadata.total_functions
    ));
    md.push_str(&format!("| Edges | {} |\n", surface.metadata.total_edges));
    md.push_str(&format!("| Hypotheses | {} |\n", result.hypotheses.len()));
    md.push_str(&format!(
        "| Entry Points | {} |\n",
        surface.attack_surface.summary.total_entry_points
    ));
    md.push_str(&format!(
        "| Unguarded Entry Points | {} |\n",
        surface.attack_surface.summary.unguarded_entry_points
    ));
    md.push_str(&format!(
        "| Enforcement Rate | {:.0}% |\n",
        surface.attack_surface.summary.enforcement_rate * 100.0
    ));
    md.push_str("\n");

    // Attack Surface
    md.push_str("## Attack Surface\n\n");
    md.push_str("### Entry Points\n\n");
    md.push_str("| Function | Authority | Writes State | External Calls |\n");
    md.push_str("|----------|-----------|--------------|----------------|\n");
    for ep in &surface.attack_surface.entry_points {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            ep.function,
            if ep.has_authority { "✓" } else { "✗" },
            if ep.writes_state { "✓" } else { "—" },
            if ep.makes_external_calls {
                "✓"
            } else {
                "—"
            },
        ));
    }
    md.push_str("\n");

    // Hypotheses
    md.push_str("## Hypotheses\n\n");
    if result.hypotheses.is_empty() {
        md.push_str("No hypotheses generated.\n\n");
    } else {
        for (i, h) in result.hypotheses.iter().enumerate() {
            let severity = match h.severity {
                digger_ir::Severity::Critical => "🔴 CRITICAL",
                digger_ir::Severity::High => "🟠 HIGH",
                digger_ir::Severity::Medium => "🟡 MEDIUM",
                digger_ir::Severity::Low => "🔵 LOW",
                digger_ir::Severity::Info => "⚪ INFO",
            };
            md.push_str(&format!(
                "### {}. [{}] {}\n\n",
                i + 1,
                severity,
                h.hypothesis_type
            ));
            md.push_str(&format!("**Function:** `{}`\n\n", h.primary_function));
            md.push_str(&format!("**Description:** {}\n\n", h.description));
            md.push_str(&format!(
                "**Explanation:** {}\n\n",
                h.structural_explanation
            ));
            if !h.evidence.is_empty() {
                md.push_str("**Evidence:**\n");
                for e in &h.evidence {
                    for fact in &e.graph_facts {
                        md.push_str(&format!(
                            "- [{}] {}: {}\n",
                            fact.fact_type, fact.function, fact.detail
                        ));
                    }
                }
                md.push_str("\n");
            }
        }
    }

    // Vulnerability Paths
    md.push_str("## Vulnerability Paths\n\n");
    if surface.paths.paths.is_empty() {
        md.push_str("No vulnerability paths detected.\n\n");
    } else {
        for path in &surface.paths.paths {
            md.push_str(&format!("### {} [{}]\n\n", path.id, path.severity));
            md.push_str(&format!("**Type:** {}\n\n", path.path_type));
            md.push_str(&format!("**Description:** {}\n\n", path.description));
            md.push_str("**Steps:**\n");
            for step in &path.steps {
                md.push_str(&format!(
                    "{}. `{}` → {} ({})\n",
                    step.step, step.function, step.action, step.detail
                ));
            }
            md.push_str("\n");
        }
    }

    // Evidence Chains
    md.push_str("## Evidence Chains\n\n");
    for evidence in &surface.evidence {
        md.push_str(&format!(
            "### {} [{}]\n\n",
            evidence.finding_id, evidence.severity
        ));
        md.push_str(&format!("{}\n\n", evidence.summary));
        md.push_str("**Steps:**\n");
        for step in &evidence.steps {
            md.push_str(&format!(
                "- `{}` → {:?} → {}\n",
                step.function, step.action, step.detail
            ));
        }
        md.push_str("\n");
    }

    md.push_str("---\n\n");
    md.push_str("*Generated by Digger — deterministic blockchain security research platform*\n");

    md
}
