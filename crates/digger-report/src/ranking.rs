use crate::ReportFinding;

/// Confidence filter options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidenceFilter<'a> {
    pub min_confidence: Option<&'a str>,
    pub top_n: Option<usize>,
}

/// Confidence tier ordering (lower = higher priority in output).
fn confidence_rank(confidence: &str) -> u8 {
    match confidence {
        "confirmed" => 0,
        "high" => 1,
        "medium" => 2,
        "experimental" => 3,
        _ => 4,
    }
}

/// Severity ordering (lower = higher priority).
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// Rank and filter findings. Deterministic: BTreeMap-based sort, stable ordering.
pub fn rank_findings<'a>(
    findings: &'a [ReportFinding],
    min_confidence: Option<&str>,
    top_n: Option<usize>,
) -> Vec<&'a ReportFinding> {
    let min_rank = min_confidence.map(confidence_rank).unwrap_or(3);

    let mut ranked: Vec<&ReportFinding> = findings
        .iter()
        .filter(|f| confidence_rank(&f.confidence) <= min_rank)
        .collect();

    ranked.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(confidence_rank(&a.confidence).cmp(&confidence_rank(&b.confidence)))
            .then(a.finding_id.cmp(&b.finding_id))
    });

    if let Some(n) = top_n {
        ranked.truncate(n);
    }

    ranked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(id: &str, severity: &str, confidence: &str) -> ReportFinding {
        ReportFinding {
            finding_id: id.to_string(),
            rule_id: "test_rule".to_string(),
            severity: severity.to_string(),
            confidence: confidence.to_string(),
            component: "TestContract".to_string(),
            file: "test.sol".to_string(),
            line_start: 10,
            line_end: 15,
            description: "test finding".to_string(),
            evidence_lines: vec![],
        }
    }

    #[test]
    fn ranking_orders_by_severity_then_confidence() {
        let findings = vec![
            make_finding("f1", "medium", "high"),
            make_finding("f2", "critical", "experimental"),
            make_finding("f3", "high", "confirmed"),
        ];
        let ranked = rank_findings(&findings, None, None);
        assert_eq!(ranked[0].finding_id, "f2");
        assert_eq!(ranked[1].finding_id, "f3");
        assert_eq!(ranked[2].finding_id, "f1");
    }

    #[test]
    fn confidence_filter_excludes_low() {
        let findings = vec![
            make_finding("f1", "high", "confirmed"),
            make_finding("f2", "high", "experimental"),
        ];
        let ranked = rank_findings(&findings, Some("high"), None);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].finding_id, "f1");
    }

    #[test]
    fn top_n_limits_output() {
        let findings = vec![
            make_finding("f1", "critical", "high"),
            make_finding("f2", "critical", "high"),
            make_finding("f3", "critical", "high"),
        ];
        let ranked = rank_findings(&findings, None, Some(2));
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn deterministic_sort_stable_on_same_rank() {
        let findings = vec![
            make_finding("f2", "high", "high"),
            make_finding("f1", "high", "high"),
            make_finding("f3", "high", "high"),
        ];
        let ranked = rank_findings(&findings, None, None);
        let ids: Vec<_> = ranked.iter().map(|f| &f.finding_id).collect();
        assert_eq!(ids, vec!["f1", "f2", "f3"]);
    }
}
