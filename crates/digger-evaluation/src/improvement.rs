/// Continuous Improvement — auto-generate improvement recommendations for missed findings.
use crate::eval_models::*;
use std::collections::BTreeMap;

/// Analyze missed findings and generate improvement recommendations.
pub fn generate_improvement_analysis(misses: &[MissedFinding]) -> ImprovementAnalysis {
    let mut root_causes: BTreeMap<String, usize> = BTreeMap::new();
    let mut reasoning_gaps: BTreeMap<String, usize> = BTreeMap::new();
    let mut knowledge_gaps: BTreeMap<String, usize> = BTreeMap::new();
    let mut parser_limits: BTreeMap<String, usize> = BTreeMap::new();
    let mut benchmark_gaps: BTreeMap<String, usize> = BTreeMap::new();

    for miss in misses {
        *root_causes
            .entry(miss.root_cause_category.clone())
            .or_insert(0) += 1;
        match miss.miss_category.as_str() {
            "reasoning" => {
                *reasoning_gaps
                    .entry(miss.gap_description.clone())
                    .or_insert(0) += 1;
            }
            "knowledge" => {
                *knowledge_gaps
                    .entry(miss.gap_description.clone())
                    .or_insert(0) += 1;
            }
            "parser" => {
                *parser_limits
                    .entry(miss.gap_description.clone())
                    .or_insert(0) += 1;
            }
            "benchmark" => {
                *benchmark_gaps
                    .entry(miss.gap_description.clone())
                    .or_insert(0) += 1;
            }
            _ => {}
        }
    }

    let mut recommendations = Vec::new();
    let mut priority = 1;

    // Top reasoning gaps
    let mut reasoning_sorted: Vec<_> = reasoning_gaps.iter().collect();
    reasoning_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (gap, count) in reasoning_sorted.iter().take(3) {
        recommendations.push(ImprovementRecommendation {
            priority,
            target: "reasoning".into(),
            action: format!("Add reasoning rule for: {}", gap),
            expected_impact: format!("Address {} missed findings", count),
            effort: if **count > 5 {
                "High".into()
            } else if **count > 2 {
                "Medium".into()
            } else {
                "Low".into()
            },
        });
        priority += 1;
    }

    // Top knowledge gaps
    let mut knowledge_sorted: Vec<_> = knowledge_gaps.iter().collect();
    knowledge_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (gap, count) in knowledge_sorted.iter().take(3) {
        recommendations.push(ImprovementRecommendation {
            priority,
            target: "knowledge".into(),
            action: format!("Expand knowledge for: {}", gap),
            expected_impact: format!("Address {} missed findings", count),
            effort: if **count > 5 {
                "High".into()
            } else if **count > 2 {
                "Medium".into()
            } else {
                "Low".into()
            },
        });
        priority += 1;
    }

    // Top parser limitations
    let mut parser_sorted: Vec<_> = parser_limits.iter().collect();
    parser_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (gap, count) in parser_sorted.iter().take(2) {
        recommendations.push(ImprovementRecommendation {
            priority,
            target: "parser".into(),
            action: format!("Improve parser: {}", gap),
            expected_impact: format!("Address {} missed findings", count),
            effort: "High".into(),
        });
        priority += 1;
    }

    ImprovementAnalysis {
        total_misses: misses.len(),
        root_causes,
        reasoning_gaps,
        knowledge_gaps,
        parser_limits,
        benchmark_gaps,
        recommendations,
    }
}

/// A single missed finding with categorization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MissedFinding {
    pub finding_id: String,
    pub title: String,
    pub protocol: String,
    pub severity: String,
    pub root_cause_category: String,
    pub miss_category: String,
    pub gap_description: String,
    pub explanation: String,
}

/// Improvement analysis result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImprovementAnalysis {
    pub total_misses: usize,
    pub root_causes: BTreeMap<String, usize>,
    pub reasoning_gaps: BTreeMap<String, usize>,
    pub knowledge_gaps: BTreeMap<String, usize>,
    pub parser_limits: BTreeMap<String, usize>,
    pub benchmark_gaps: BTreeMap<String, usize>,
    pub recommendations: Vec<ImprovementRecommendation>,
}

/// Display improvement analysis.
pub fn display_improvement_analysis(analysis: &ImprovementAnalysis) -> String {
    let mut out = format!(
        "═══ Improvement Analysis ═══\nTotal misses: {}\n\n",
        analysis.total_misses
    );
    if !analysis.recommendations.is_empty() {
        out.push_str("─── Recommendations ───────────────────────────────\n");
        for rec in &analysis.recommendations {
            out.push_str(&format!(
                "  #{} [{}] {}: {}\n",
                rec.priority, rec.effort, rec.action, rec.expected_impact
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_improvement_analysis() {
        let misses = vec![
            MissedFinding {
                finding_id: "m1".into(),
                title: "Oracle manipulation".into(),
                protocol: "P1".into(),
                severity: "high".into(),
                root_cause_category: "oracle".into(),
                miss_category: "knowledge".into(),
                gap_description: "No oracle pattern in knowledge base".into(),
                explanation: "Missing".into(),
            },
            MissedFinding {
                finding_id: "m2".into(),
                title: "Flash loan reentrancy".into(),
                protocol: "P2".into(),
                severity: "critical".into(),
                root_cause_category: "reentrancy".into(),
                miss_category: "reasoning".into(),
                gap_description: "No flash loan composition reasoning".into(),
                explanation: "Missing".into(),
            },
        ];
        let analysis = generate_improvement_analysis(&misses);
        assert_eq!(analysis.total_misses, 2);
        assert!(!analysis.recommendations.is_empty());
    }
}
