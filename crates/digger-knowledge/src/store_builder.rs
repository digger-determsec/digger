/// Store builder — constructs the historical finding store.
use digger_knowledge_models::*;

/// Build a historical finding store from normalized findings and patterns.
pub fn build_store(
    findings: Vec<NormalizedFinding>,
    patterns: Vec<ReasoningPattern>,
) -> HistoricalFindingStore {
    let mut by_class: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut by_protocol: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut by_technique: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut by_severity: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();

    for finding in &findings {
        by_class
            .entry(finding.vulnerability_class.to_string())
            .or_default()
            .push(finding.finding_id.clone());

        by_protocol
            .entry(finding.protocol_name.clone())
            .or_default()
            .push(finding.finding_id.clone());

        by_technique
            .entry(finding.attack_technique.to_string())
            .or_default()
            .push(finding.finding_id.clone());

        by_severity
            .entry(finding.severity.to_string())
            .or_default()
            .push(finding.finding_id.clone());
    }

    HistoricalFindingStore {
        findings,
        by_class,
        by_protocol,
        by_technique,
        by_severity,
        patterns,
    }
}
