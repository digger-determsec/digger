/// Pattern extractor — identifies reusable reasoning patterns from findings.
use digger_knowledge_models::*;

/// Extract reasoning patterns from normalized findings.
///
/// A pattern emerges when multiple findings share the same
/// vulnerability class and attack goal.
pub fn extract_patterns(findings: &[NormalizedFinding]) -> Vec<ReasoningPattern> {
    // Group findings by (vulnerability_class, attack_goal)
    let mut groups: std::collections::BTreeMap<(String, String), Vec<&NormalizedFinding>> =
        std::collections::BTreeMap::new();

    for finding in findings {
        let key = (
            finding.vulnerability_class.to_string(),
            finding.attack_goal.clone(),
        );
        groups.entry(key).or_default().push(finding);
    }

    let mut patterns = Vec::new();

    for ((class, goal), group) in &groups {
        // Only create patterns for classes with 2+ findings
        if group.len() < 2 {
            continue;
        }

        let pattern_id = format!("pattern:{}:{}", class, goal);

        // Collect unique protocols
        let mut protocols: Vec<String> = group.iter().map(|f| f.protocol_name.clone()).collect();
        protocols.sort();
        protocols.dedup();

        // Collect unique capabilities
        let mut capabilities: Vec<String> = group
            .iter()
            .flat_map(|f| f.capability_pattern.clone())
            .collect();
        capabilities.sort();
        capabilities.dedup();

        // Collect finding IDs
        let finding_ids: Vec<String> = group.iter().map(|f| f.finding_id.clone()).collect();

        // Collect sources
        let mut sources: Vec<String> = group.iter().map(|_| "pashov/audits".into()).collect();
        sources.sort();
        sources.dedup();

        patterns.push(ReasoningPattern {
            pattern_id,
            name: format!("{} pattern", class),
            description: format!(
                "Reusable pattern for {} vulnerabilities affecting {} protocols",
                class,
                protocols.len()
            ),
            vulnerability_class: class.clone(),
            attack_goal: goal.clone(),
            required_capabilities: capabilities,
            structural_indicators: vec![],
            violated_invariants: group
                .iter()
                .map(|f| f.violated_invariant.kind.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
            evidence_sources: vec!["HistoricalFinding".into()],
            historical_findings: finding_ids,
            confidence_baseline: 0.5,
            provenance: PatternProvenance {
                source: "pashov/audits".into(),
                finding_count: group.len(),
                protocol_count: protocols.len(),
                first_seen: None,
                last_seen: None,
            },
        });
    }

    patterns.sort_by(|a, b| a.pattern_id.cmp(&b.pattern_id));
    patterns
}
