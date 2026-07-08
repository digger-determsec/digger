/// Continuous corpus intelligence — gap analysis and coverage metrics.
///
/// Automatically measures corpus quality and identifies gaps.
/// Generates deterministic recommendations for highest-ROI knowledge sources.
use digger_knowledge_models::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Corpus intelligence report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusIntelligence {
    /// Report timestamp.
    pub generated_at: String,
    /// Total artifacts in corpus.
    pub total_artifacts: usize,
    /// Total findings.
    pub total_findings: usize,
    /// Coverage metrics.
    pub coverage: CoverageMetrics,
    /// Gaps identified.
    pub gaps: Vec<CorpusGap>,
    /// Recommendations ordered by ROI.
    pub recommendations: Vec<Recommendation>,
}

/// Coverage metrics across the taxonomy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMetrics {
    /// Vulnerability classes covered vs total.
    pub vulnerability_class_coverage: f64,
    /// Root causes covered vs total.
    pub root_cause_coverage: f64,
    /// Protocol domains covered vs total.
    pub protocol_domain_coverage: f64,
    /// Attack techniques covered vs total.
    pub attack_technique_coverage: f64,
    /// Number of unique protocols.
    pub unique_protocols: usize,
    /// Protocols with >1 finding.
    pub well_represented_protocols: usize,
    /// Protocols with exactly 1 finding.
    pub underrepresented_protocols: usize,
    /// Findings per source.
    pub findings_by_source: BTreeMap<String, usize>,
}

/// A gap identified in the corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusGap {
    /// Gap kind.
    pub kind: GapKind,
    /// What is missing.
    pub item: String,
    /// Current count (0 if missing).
    pub current_count: usize,
    /// Severity (critical, warning, info).
    pub severity: String,
    /// Description.
    pub description: String,
}

/// Kind of gap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GapKind {
    /// Missing vulnerability class.
    VulnerabilityClass,
    /// Missing root cause.
    RootCause,
    /// Missing protocol domain.
    ProtocolDomain,
    /// Missing attack technique.
    AttackTechnique,
    /// Underrepresented protocol.
    UnderrepresentedProtocol,
    /// Missing chain coverage.
    ChainCoverage,
}

/// Recommendation for improving corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority (1=highest).
    pub priority: usize,
    /// Action to take.
    pub action: String,
    /// Expected impact.
    pub impact: String,
    /// Estimated findings gained.
    pub estimated_findings: usize,
    /// Source to ingest.
    pub source: String,
}

/// Analyze the corpus and generate an intelligence report.
pub fn analyze_corpus(corpus_dir: &str) -> CorpusIntelligence {
    let corpus_path = Path::new(corpus_dir);
    let mut all_findings = Vec::new();
    let mut total_artifacts = 0usize;
    let mut findings_by_source: BTreeMap<String, usize> = BTreeMap::new();

    // Load all corpus data
    if let Ok(entries) = std::fs::read_dir(corpus_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(items) = serde_json::from_str::<Vec<NormalizedKnowledge>>(&content) {
                        let count = items.len();
                        total_artifacts += count;
                        for item in &items {
                            let finding_count = item.findings.len();
                            *findings_by_source
                                .entry(item.source_id.clone())
                                .or_insert(0) += finding_count;
                            all_findings.extend(item.findings.clone());
                        }
                    }
                }
            }
        }
    }

    let total_findings = all_findings.len();

    // Compute coverage
    let coverage = compute_coverage(&all_findings, total_artifacts, &findings_by_source);

    // Identify gaps
    let gaps = identify_gaps(&all_findings);

    // Generate recommendations
    let recommendations = generate_recommendations(&gaps, &coverage);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = now_secs / 86400;
    let tod = now_secs % 86400;
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;
    let mut y = 1970u64;
    let mut rem = days;
    loop {
        let diy = if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) {
            366
        } else {
            365
        };
        if rem < diy {
            break;
        }
        rem -= diy;
        y += 1;
    }

    CorpusIntelligence {
        generated_at: format!("{:04}-01-{:02}T{:02}:{:02}:{:02}Z", y, 1 + rem, h, m, s),
        total_artifacts,
        total_findings,
        coverage,
        gaps,
        recommendations,
    }
}

fn compute_coverage(
    findings: &[NormalizedFinding],
    _total_artifacts: usize,
    findings_by_source: &BTreeMap<String, usize>,
) -> CoverageMetrics {
    // Vulnerability classes (exclude Other variants)
    let mut classes_seen = BTreeSet::new();
    let total_classes = 33;
    for f in findings {
        let class = f.vulnerability_class.to_string();
        if !class.starts_with("other(") {
            classes_seen.insert(class);
        }
    }

    // Root causes (exclude Other variants)
    let mut causes_seen = BTreeSet::new();
    let total_causes = 21;
    for f in findings {
        let cause = f.root_cause.to_string();
        if !cause.starts_with("other(") {
            causes_seen.insert(cause);
        }
    }

    // Protocol domains (exclude Generic)
    let mut domains_seen = BTreeSet::new();
    let total_domains = 19;
    for f in findings {
        let domain = f.protocol_domain.to_string();
        if domain != "Generic" {
            domains_seen.insert(domain);
        }
    }

    // Attack techniques (exclude Other variants)
    let mut techniques_seen = BTreeSet::new();
    let total_techniques = 14;
    for f in findings {
        let tech = f.attack_technique.to_string();
        if !tech.starts_with("other(") {
            techniques_seen.insert(tech);
        }
    }

    // Protocol representation
    let mut protocol_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        *protocol_counts.entry(f.protocol_name.clone()).or_insert(0) += 1;
    }
    let unique_protocols = protocol_counts.len();
    let well_represented = protocol_counts.values().filter(|&&c| c > 1).count();
    let underrepresented = protocol_counts.values().filter(|&&c| c == 1).count();

    CoverageMetrics {
        vulnerability_class_coverage: classes_seen.len() as f64 / total_classes as f64,
        root_cause_coverage: causes_seen.len() as f64 / total_causes as f64,
        protocol_domain_coverage: domains_seen.len() as f64 / total_domains as f64,
        attack_technique_coverage: techniques_seen.len() as f64 / total_techniques as f64,
        unique_protocols,
        well_represented_protocols: well_represented,
        underrepresented_protocols: underrepresented,
        findings_by_source: findings_by_source.clone(),
    }
}

fn identify_gaps(findings: &[NormalizedFinding]) -> Vec<CorpusGap> {
    let mut gaps = Vec::new();

    // Check for missing vulnerability classes
    let mut class_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        let class = f.vulnerability_class.to_string();
        if !class.starts_with("other(") {
            *class_counts.entry(class).or_insert(0) += 1;
        }
    }

    for class in &[
        "Reentrancy",
        "FlashLoanAttack",
        "OracleManipulation",
        "PriceManipulation",
        "MissingAccessControl",
        "BusinessLogicFlaw",
        "ComposabilityRisk",
        "SandwichAttack",
        "GovernanceAttack",
        "PrivilegeEscalation",
    ] {
        let count = class_counts.get(*class).copied().unwrap_or(0);
        if count == 0 {
            gaps.push(CorpusGap {
                kind: GapKind::VulnerabilityClass,
                item: class.to_string(),
                current_count: 0,
                severity: "warning".into(),
                description: format!("No findings for vulnerability class: {}", class),
            });
        }
    }

    // Check for missing attack techniques
    let mut technique_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        let tech = f.attack_technique.to_string();
        if !tech.starts_with("other(") {
            *technique_counts.entry(tech).or_insert(0) += 1;
        }
    }

    for technique in &["FlashLoan", "Reentrancy", "Oracle", "AccessControl", "CPI"] {
        let count = technique_counts.get(*technique).copied().unwrap_or(0);
        if count == 0 {
            gaps.push(CorpusGap {
                kind: GapKind::AttackTechnique,
                item: technique.to_string(),
                current_count: 0,
                severity: "info".into(),
                description: format!("No findings for attack technique: {}", technique),
            });
        }
    }

    // Check protocol representation
    let mut protocol_counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        *protocol_counts.entry(f.protocol_name.clone()).or_insert(0) += 1;
    }

    let single_finding_protocols: Vec<String> = protocol_counts
        .iter()
        .filter(|(_, &c)| c == 1)
        .map(|(name, _)| name.clone())
        .take(5)
        .collect();

    if !single_finding_protocols.is_empty() {
        gaps.push(CorpusGap {
            kind: GapKind::UnderrepresentedProtocol,
            item: single_finding_protocols.join(", "),
            current_count: single_finding_protocols.len(),
            severity: "info".into(),
            description: format!(
                "{} protocols with only 1 finding",
                single_finding_protocols.len()
            ),
        });
    }

    gaps
}

fn generate_recommendations(gaps: &[CorpusGap], coverage: &CoverageMetrics) -> Vec<Recommendation> {
    let mut recs = Vec::new();
    let mut priority = 1;

    // Recommend sources that would fill the most gaps
    let class_gaps = gaps
        .iter()
        .filter(|g| g.kind == GapKind::VulnerabilityClass)
        .count();
    let technique_gaps = gaps
        .iter()
        .filter(|g| g.kind == GapKind::AttackTechnique)
        .count();

    if class_gaps > 0 {
        recs.push(Recommendation {
            priority,
            action: "Ingest more Code4rena/Sherlock audit contests".into(),
            impact: format!("Fill {} vulnerability class gaps", class_gaps),
            estimated_findings: class_gaps * 5,
            source: "code4rena, sherlock".into(),
        });
        priority += 1;
    }

    if technique_gaps > 0 {
        recs.push(Recommendation {
            priority,
            action: "Ingest more DeFiHackLabs exploit PoCs".into(),
            impact: format!("Fill {} attack technique gaps", technique_gaps),
            estimated_findings: technique_gaps * 3,
            source: "defihacklabs".into(),
        });
        priority += 1;
    }

    if coverage.vulnerability_class_coverage < 0.5 {
        recs.push(Recommendation {
            priority,
            action: "Expand SlowMist and Rekt News ingestion".into(),
            impact: "Improve vulnerability class coverage".into(),
            estimated_findings: 50,
            source: "slowmist, rekt".into(),
        });
        priority += 1;
    }

    if coverage.underrepresented_protocols > 10 {
        recs.push(Recommendation {
            priority,
            action: "Ingest protocol-specific documentation".into(),
            impact: format!(
                "Improve representation for {} protocols",
                coverage.underrepresented_protocols
            ),
            estimated_findings: 20,
            source: "protocol_docs".into(),
        });
    }

    recs
}

/// Display the corpus intelligence report.
pub fn display(report: &CorpusIntelligence) -> String {
    let mut out = String::new();
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str("  CORPUS INTELLIGENCE REPORT\n");
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str(&format!("Generated: {}\n", report.generated_at));
    out.push_str(&format!(
        "Artifacts: {} | Findings: {}\n",
        report.total_artifacts, report.total_findings
    ));
    out.push('\n');

    out.push_str("─── Coverage ──────────────────────────────────────\n");
    out.push_str(&format!(
        "  Vuln Classes:      {:.0}%\n",
        report.coverage.vulnerability_class_coverage * 100.0
    ));
    out.push_str(&format!(
        "  Root Causes:       {:.0}%\n",
        report.coverage.root_cause_coverage * 100.0
    ));
    out.push_str(&format!(
        "  Protocol Domains:  {:.0}%\n",
        report.coverage.protocol_domain_coverage * 100.0
    ));
    out.push_str(&format!(
        "  Attack Techniques: {:.0}%\n",
        report.coverage.attack_technique_coverage * 100.0
    ));
    out.push_str(&format!(
        "  Unique Protocols:  {}\n",
        report.coverage.unique_protocols
    ));
    out.push_str(&format!(
        "  Well-represented:  {}\n",
        report.coverage.well_represented_protocols
    ));
    out.push_str(&format!(
        "  Under-represented: {}\n",
        report.coverage.underrepresented_protocols
    ));
    out.push('\n');

    out.push_str("─── Findings by Source ────────────────────────────\n");
    for (source, count) in &report.coverage.findings_by_source {
        out.push_str(&format!("  {:<20} {}\n", source, count));
    }
    out.push('\n');

    if !report.gaps.is_empty() {
        out.push_str(&format!(
            "─── Gaps ({}) ────────────────────────────────\n",
            report.gaps.len()
        ));
        for gap in &report.gaps {
            let icon = match gap.severity.as_str() {
                "critical" => "✗",
                "warning" => "~",
                _ => "·",
            };
            out.push_str(&format!(
                "  {} [{}] {}\n",
                icon,
                gap.kind_str(),
                gap.description
            ));
        }
        out.push('\n');
    }

    if !report.recommendations.is_empty() {
        out.push_str("─── Recommendations ───────────────────────────────\n");
        for rec in &report.recommendations {
            out.push_str(&format!(
                "  {}. {} (est. +{} findings)\n",
                rec.priority, rec.action, rec.estimated_findings
            ));
            out.push_str(&format!(
                "     Source: {} | Impact: {}\n",
                rec.source, rec.impact
            ));
        }
    }

    out.push_str("═══════════════════════════════════════════════════\n");
    out
}

impl CorpusGap {
    fn kind_str(&self) -> &str {
        match self.kind {
            GapKind::VulnerabilityClass => "VULN_CLASS",
            GapKind::RootCause => "ROOT_CAUSE",
            GapKind::ProtocolDomain => "PROTOCOL_DOMAIN",
            GapKind::AttackTechnique => "ATTACK_TECH",
            GapKind::UnderrepresentedProtocol => "UNDER_REP",
            GapKind::ChainCoverage => "CHAIN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty_corpus() {
        let report = analyze_corpus("/nonexistent");
        assert_eq!(report.total_artifacts, 0);
        assert_eq!(report.total_findings, 0);
    }

    #[test]
    fn test_display_format() {
        let report = analyze_corpus("/nonexistent");
        let display = display(&report);
        assert!(display.contains("CORPUS INTELLIGENCE REPORT"));
        assert!(display.contains("Coverage"));
    }

    #[test]
    fn test_recommendations_ordering() {
        let report = analyze_corpus("/nonexistent");
        for (i, rec) in report.recommendations.iter().enumerate() {
            assert_eq!(rec.priority, i + 1);
        }
    }
}
