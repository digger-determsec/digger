use digger_knowledge::dashboard_analytics::*;

#[derive(Debug, thiserror::Error)]
enum DashboardError {
    #[error("Corpus directory not found: {0}")]
    CorpusNotFound(String),
    #[error("Cannot read '{path}': {source}")]
    ReadDir {
        path: String,
        source: std::io::Error,
    },
    #[error("Cannot read entry: {0}")]
    ReadEntry(String),
}

pub fn run(corpus_dir: &str, json_output: bool, output_path: Option<String>) {
    // Load normalized knowledge from corpus
    let items = match load_corpus(corpus_dir) {
        Ok(items) => items,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if items.is_empty() {
        eprintln!("Error: No knowledge items found in '{}'", corpus_dir);
        std::process::exit(1);
    }

    // Run analytics
    let analytics = digger_knowledge::analytics::compute_analytics(&items);
    let dashboard = digger_knowledge::dashboard::compute_dashboard(&items, &analytics);
    let density = compute_evidence_density(&items);
    let snapshot = create_snapshot(&items);
    let velocity = compute_velocity(&[snapshot]);
    let saturation = compute_saturation(&velocity.snapshots, &items);
    let roi = compute_knowledge_roi(&items);
    let next_actions = compute_next_best_actions(&items, &density, &saturation, &roi);

    let report = FullDashboardReport {
        dashboard,
        density,
        velocity,
        saturation,
        roi,
        next_actions,
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
        );
    } else {
        print_report(&report);
    }

    if let Some(out_path) = output_path {
        let json = match serde_json::to_string_pretty(&report) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Error: failed to serialize report: {}", e);
                std::process::exit(1);
            }
        };
        match std::fs::write(&out_path, &json) {
            Ok(_) => eprintln!("Dashboard report exported to: {}", out_path),
            Err(e) => {
                eprintln!("Error: Cannot write to '{}': {}", out_path, e);
                std::process::exit(1);
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FullDashboardReport {
    dashboard: digger_knowledge::dashboard::KnowledgeDashboard,
    density: EvidenceDensityReport,
    velocity: CoverageVelocityReport,
    saturation: SaturationReport,
    roi: KnowledgeROIReport,
    next_actions: NextBestActionReport,
}

fn load_corpus(
    dir: &str,
) -> Result<Vec<digger_knowledge_models::NormalizedKnowledge>, DashboardError> {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.exists() {
        return Err(DashboardError::CorpusNotFound(dir.to_string()));
    }

    let mut items = Vec::new();

    // Load meta.json files from known-exploits and bugs directories
    load_meta_json_files(dir_path, &mut items)?;

    // Also try loading NormalizedKnowledge JSON directly
    load_normalized_json_files(dir_path, &mut items)?;

    Ok(items)
}

fn load_meta_json_files(
    dir: &std::path::Path,
    items: &mut Vec<digger_knowledge_models::NormalizedKnowledge>,
) -> Result<(), DashboardError> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir).map_err(|e| DashboardError::ReadDir {
        path: dir.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| DashboardError::ReadEntry(e.to_string()))?;
        let path = entry.path();

        if path.is_dir() {
            // Recurse into subdirectories
            load_meta_json_files(&path, items)?;
        } else if path.file_name().and_then(|n| n.to_str()) == Some("meta.json") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(knowledge) = meta_to_normalized(&meta, &path) {
                        items.push(knowledge);
                    }
                }
            }
        }
    }

    Ok(())
}

fn meta_to_normalized(
    meta: &serde_json::Value,
    path: &std::path::Path,
) -> Option<digger_knowledge_models::NormalizedKnowledge> {
    let exploit_id = meta.get("exploit_id")?.as_str()?;
    let vuln_class = meta.get("vulnerability_class")?.as_str()?;
    let protocol = meta.get("protocol")?.as_str()?;
    let chain = meta.get("chain")?.as_str()?;
    let _expected_hypotheses: Vec<String> = meta
        .get("expected_hypotheses")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Map vulnerability class to VulnerabilityClass enum
    let vulnerability_class = match vuln_class {
        "reentrancy" => digger_knowledge_models::VulnerabilityClass::Reentrancy,
        "access_control" | "access-control" => {
            digger_knowledge_models::VulnerabilityClass::MissingAccessControl
        }
        "flash_loan" | "flash-loan" => digger_knowledge_models::VulnerabilityClass::FlashLoanAttack,
        "oracle_manipulation" | "oracle-manipulation" => {
            digger_knowledge_models::VulnerabilityClass::OracleManipulation
        }
        "upgradeability" => digger_knowledge_models::VulnerabilityClass::UpgradeabilityRisk,
        "initialization" => digger_knowledge_models::VulnerabilityClass::UnprotectedInitialization,
        "delegatecall" => digger_knowledge_models::VulnerabilityClass::ComposabilityRisk,
        "storage_collision" | "storage-collision" => {
            digger_knowledge_models::VulnerabilityClass::StorageCollision
        }
        "missing_validation" | "missing-validation" => {
            digger_knowledge_models::VulnerabilityClass::MissingValidation
        }
        "cross_function" | "cross-function" => {
            digger_knowledge_models::VulnerabilityClass::CrossFunctionReentrancy
        }
        "cross_contract" | "cross-contract" => {
            digger_knowledge_models::VulnerabilityClass::CrossContractReentrancy
        }
        "state_desync" | "state-desync" => {
            digger_knowledge_models::VulnerabilityClass::StateCorruption
        }
        "unsafe_external_call" | "unsafe-external-call" => {
            digger_knowledge_models::VulnerabilityClass::BusinessLogicFlaw
        }
        "governance" => digger_knowledge_models::VulnerabilityClass::GovernanceAttack,
        _ => digger_knowledge_models::VulnerabilityClass::Other(vuln_class.to_string()),
    };

    // Map chain to ProtocolDomain
    let protocol_domain = match chain.to_lowercase().as_str() {
        "ethereum" | "evm" => digger_knowledge_models::ProtocolDomain::Generic,
        "solana" => digger_knowledge_models::ProtocolDomain::Generic,
        _ => digger_knowledge_models::ProtocolDomain::Generic,
    };

    // Build findings from expected_findings
    let expected_findings: Vec<String> = meta
        .get("expected_findings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let findings: Vec<digger_knowledge_models::NormalizedFinding> = expected_findings
        .iter()
        .enumerate()
        .map(
            |(i, finding_name)| digger_knowledge_models::NormalizedFinding {
                finding_id: format!("{}-{}", exploit_id, i),
                original_finding_id: finding_name.clone(),
                report_id: exploit_id.to_string(),
                protocol_name: protocol.to_string(),
                protocol_category: digger_knowledge_models::ProtocolCategory::Unknown,
                protocol_domain: protocol_domain.clone(),
                protocol_pattern: None,
                vulnerability_class: vulnerability_class.clone(),
                attack_goal: "drain_assets".into(),
                capability_pattern: vec![],
                violated_invariant: digger_knowledge_models::ViolatedInvariant {
                    kind: "conservation".into(),
                    description: format!("Protocol invariant violated in {}", protocol),
                    affected_state_vars: vec![],
                },
                attack_technique: digger_knowledge_models::AttackTechnique::Other(
                    vuln_class.to_string(),
                ),
                mitigation_pattern: None,
                security_assumptions: vec![],
                severity: digger_ir::Severity::Critical,
                root_cause: digger_knowledge_models::StructuralRootCause::Other(
                    vuln_class.to_string(),
                ),
                impact_text: format!("Exploit of {} on {}", protocol, chain),
                description_text: format!("{} vulnerability in {}", vuln_class, protocol),
                remediation_text: String::new(),
                impacted_contracts: vec![],
                impacted_functions: vec![],
                confidence: 1.0,
            },
        )
        .collect();

    // Determine source kind from path
    let path_str = path.to_string_lossy();
    let source_kind = if path_str.contains("known-exploits") {
        digger_knowledge_models::KnowledgeSourceKind::ExploitPostmortem
    } else if path_str.contains("bugs") {
        digger_knowledge_models::KnowledgeSourceKind::RegressionCorpus
    } else if path_str.contains("protocols") {
        digger_knowledge_models::KnowledgeSourceKind::ProtocolDocumentation
    } else {
        digger_knowledge_models::KnowledgeSourceKind::Other
    };

    // Determine source_id from path
    let source_id = if path_str.contains("known-exploits") {
        "known-exploits"
    } else if path_str.contains("bugs") {
        "bugs"
    } else if path_str.contains("protocols") {
        "protocols"
    } else {
        "corpus"
    };

    Some(digger_knowledge_models::NormalizedKnowledge {
        knowledge_id: format!("meta:{}", exploit_id),
        source_id: source_id.to_string(),
        source_kind,
        source_identifier: path.to_string_lossy().to_string(),
        subject: protocol.to_string(),
        subject_category: "exploit".to_string(),
        findings,
        evidence: vec![],
        invariants: vec![],
        architectural_patterns: vec![],
        mitigation_patterns: vec![],
        references: vec![],
        claims: vec![],
        raw_sections: std::collections::BTreeMap::new(),
    })
}

fn load_normalized_json_files(
    dir: &std::path::Path,
    items: &mut Vec<digger_knowledge_models::NormalizedKnowledge>,
) -> Result<(), DashboardError> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir).map_err(|e| DashboardError::ReadDir {
        path: dir.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| DashboardError::ReadEntry(e.to_string()))?;
        let path = entry.path();

        if path.is_dir() {
            load_normalized_json_files(&path, items)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if fname != "meta.json" {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(mut knowledge_items) = serde_json::from_str::<
                        Vec<digger_knowledge_models::NormalizedKnowledge>,
                    >(&content)
                    {
                        items.append(&mut knowledge_items);
                    } else if let Ok(item) = serde_json::from_str::<
                        digger_knowledge_models::NormalizedKnowledge,
                    >(&content)
                    {
                        items.push(item);
                    }
                }
            }
        }
    }

    Ok(())
}

fn print_report(report: &FullDashboardReport) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           DIGGER KNOWLEDGE COVERAGE DASHBOARD              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Inventory
    let inv = &report.dashboard.inventory;
    println!("── Corpus Inventory ──");
    println!("  Reports:            {}", inv.total_reports);
    println!("  Findings:           {}", inv.total_findings);
    println!("  Exploits:           {}", inv.total_exploits);
    println!("  Protocols:          {}", inv.total_protocols);
    println!("  Standards:          {}", inv.total_standards);
    println!("  Graph Nodes:        {}", inv.total_graph_nodes);
    println!("  Graph Edges:        {}", inv.total_graph_edges);
    println!();

    // Evidence Density
    println!("── Evidence Density ──");
    println!("  Top 10 Categories by Evidence Strength:");
    for (i, cat) in report.density.categories.iter().take(10).enumerate() {
        println!(
            "    {}. {} [{}] — {} findings, {} exploits, {} protocols, strength: {:.3}",
            i + 1,
            cat.category,
            cat.kind,
            cat.total_findings,
            cat.total_exploits,
            cat.total_protocols,
            cat.evidence_strength,
        );
    }
    println!("  Weak Concepts: {}", report.density.weak_concepts.len());
    for weak in &report.density.weak_concepts {
        println!("    ⚠ {} ({}) — {}", weak.name, weak.kind, weak.reason);
    }
    println!();

    // Coverage Dimensions
    println!("── Coverage Dimensions ──");
    let cov = &report.dashboard.coverage;
    print_dimension("Vulnerability Classes", &cov.vulnerability_class_coverage);
    print_dimension("Root Causes", &cov.root_cause_coverage);
    print_dimension("Protocol Domains", &cov.protocol_domain_coverage);
    print_dimension("Attack Techniques", &cov.attack_technique_coverage);
    print_dimension("Broken Invariants", &cov.broken_invariant_coverage);
    print_dimension("Mitigations", &cov.mitigation_coverage);
    println!("  Parser Success Rate:   {:.1}%", cov.parser_success_rate);
    println!(
        "  Extraction Quality:    {:.1}%",
        cov.extraction_quality * 100.0
    );
    println!(
        "  Normalization Quality: {:.1}%",
        cov.normalization_quality * 100.0
    );
    println!();

    // Coverage Velocity
    println!("── Coverage Velocity ──");
    if report.velocity.dimensions.is_empty() {
        println!("  No velocity data (need multiple snapshots)");
    } else {
        for dim in &report.velocity.dimensions {
            println!(
                "  {}: {:.1}% (Δ{:+.2}, accel: {:+.3}, {})",
                dim.dimension,
                dim.current_value,
                dim.absolute_change,
                dim.acceleration,
                if dim.is_slowing { "SLOWING" } else { "growing" },
            );
        }
        if !report.velocity.rapidly_improving.is_empty() {
            println!(
                "  Rapidly improving: {}",
                report.velocity.rapidly_improving.join(", ")
            );
        }
        if !report.velocity.plateaued.is_empty() {
            println!("  Plateaued: {}", report.velocity.plateaued.join(", "));
        }
    }
    println!();

    // Saturation
    println!("── Saturation Analysis ──");
    if report.saturation.dimensions.is_empty() {
        println!("  No saturation data (need multiple snapshots)");
    } else {
        for dim in &report.saturation.dimensions {
            println!(
                "  {}: {:.1}% — {} (score: {:.2})",
                dim.dimension, dim.current_coverage, dim.classification, dim.saturation_score,
            );
        }
        if !report.saturation.approaching_saturation.is_empty() {
            println!(
                "  Approaching saturation: {}",
                report.saturation.approaching_saturation.join(", ")
            );
        }
        if !report.saturation.room_for_growth.is_empty() {
            println!(
                "  Room for growth: {}",
                report.saturation.room_for_growth.join(", ")
            );
        }
    }
    println!();

    // Knowledge ROI
    println!("── Knowledge ROI ──");
    println!("  Sources ranked by ROI:");
    for (i, source) in report.roi.sources.iter().enumerate() {
        println!(
            "    {}. {} — {} reports, {} findings, {} new concepts, {} reinforced, score: {:.3}",
            i + 1,
            source.source_id,
            source.total_reports,
            source.total_findings,
            source.new_concepts_introduced,
            source.existing_concepts_reinforced,
            source.roi_score,
        );
    }
    println!();

    // Next Best Actions
    println!("── Next Best Actions ──");
    for action in report.next_actions.actions.iter().take(10) {
        println!(
            "  {}. [{}] {}",
            action.rank, action.kind, action.description
        );
        println!("     Target: {}", action.target_dimensions.join(", "));
        println!(
            "     Expected: +{:.1}pp coverage, {} new concepts, {} new protocols",
            action.expected_coverage_improvement,
            action.expected_new_concepts,
            action.expected_new_protocols,
        );
        println!("     Rationale: {}", action.rationale);
    }
    println!();

    // Summary
    let imp = &report.next_actions.expected_improvement;
    println!("── Expected Improvement ──");
    println!(
        "  Total coverage:   +{:.1}pp",
        imp.total_coverage_improvement
    );
    println!("  New concepts:     {}", imp.total_new_concepts);
    println!("  New protocols:    {}", imp.total_new_protocols);
    println!(
        "  Most impacted:    {}",
        imp.most_impacted_dimensions.join(", ")
    );
    println!();
}

fn print_dimension(label: &str, dim: &digger_knowledge::dashboard::CoverageDimension) {
    println!(
        "  {:<24} {:>5}/{} ({:.1}%)",
        label, dim.covered, dim.total_canonical, dim.coverage_pct
    );
    if !dim.uncovered.is_empty() {
        println!("    Missing: {}", dim.uncovered.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_corpus_nonexistent_dir_returns_typed_error() {
        let result = load_corpus("/nonexistent/path/that/does/not/exist");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DashboardError::CorpusNotFound(_)));
        assert!(err.to_string().contains("Corpus directory not found"));
    }
}
