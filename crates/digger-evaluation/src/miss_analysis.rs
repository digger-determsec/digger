/// Miss Analysis — identify why Digger missed known issues.
use crate::eval_models::*;
use std::collections::BTreeMap;

/// Analyze missed findings and produce improvement recommendations.
pub fn analyze_misses(misses: &[MissInput]) -> DetailedMissAnalysis {
    let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
    let mut single_misses = Vec::new();

    for miss in misses {
        let reason = classify_miss_reason(miss);
        *by_category.entry(reason.category.clone()).or_insert(0) += 1;
        single_misses.push(SingleMiss {
            finding_id: miss.finding_id.clone(),
            expected_finding: miss.expected_finding.clone(),
            miss_reason: reason.reason,
            explanation: reason.explanation,
            severity: miss.severity.clone(),
            category: reason.category,
        });
    }

    let recommendations = generate_recommendations(&by_category, misses);

    DetailedMissAnalysis {
        total_missed: misses.len(),
        misses: single_misses,
        by_category,
        improvement_recommendations: recommendations,
    }
}

struct MissClassification {
    reason: MissReason,
    category: String,
    explanation: String,
}

fn classify_miss_reason(miss: &MissInput) -> MissClassification {
    let lower_expected = miss.expected_finding.to_lowercase();
    let lower_explanation = miss.explanation.to_lowercase();

    if lower_explanation.contains("parser") || lower_explanation.contains("syntax") {
        MissClassification {
            reason: MissReason::ParserLimitation,
            category: "parser".into(),
            explanation: "Parser could not parse the contract structure".into(),
        }
    } else if lower_expected.contains("reentrancy") && !lower_explanation.contains("external call")
    {
        MissClassification {
            reason: MissReason::MissingReasoningRule,
            category: "reasoning".into(),
            explanation: "No reentrancy detection rule for this pattern".into(),
        }
    } else if lower_expected.contains("access control") || lower_expected.contains("authorization")
    {
        MissClassification {
            reason: MissReason::MissingProtocolSemantics,
            category: "knowledge".into(),
            explanation: "Protocol-specific access control semantics missing".into(),
        }
    } else if lower_expected.contains("oracle") || lower_expected.contains("price feed") {
        MissClassification {
            reason: MissReason::MissingKnowledge,
            category: "knowledge".into(),
            explanation: "Oracle manipulation patterns not in knowledge base".into(),
        }
    } else if lower_expected.contains("flash loan") {
        MissClassification {
            reason: MissReason::MissingReasoningRule,
            category: "reasoning".into(),
            explanation: "Flash loan composition reasoning not implemented".into(),
        }
    } else if miss.confidence < 0.3 {
        MissClassification {
            reason: MissReason::ConfidenceTooLow,
            category: "confidence".into(),
            explanation: "Hypothesis existed but confidence too low to report".into(),
        }
    } else if lower_explanation.contains("eliminated") || lower_explanation.contains("validation") {
        MissClassification {
            reason: MissReason::MissingValidationLogic,
            category: "validation".into(),
            explanation: "Valid exploit eliminated by overly strict validation".into(),
        }
    } else {
        MissClassification {
            reason: MissReason::MissingKnowledge,
            category: "knowledge".into(),
            explanation: "Insufficient knowledge to detect this pattern".into(),
        }
    }
}

fn generate_recommendations(
    by_category: &BTreeMap<String, usize>,
    _misses: &[MissInput],
) -> Vec<ImprovementRecommendation> {
    let mut recs = Vec::new();
    let mut sorted: Vec<(&String, &usize)> = by_category.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    for (i, (category, count)) in sorted.iter().enumerate() {
        let (action, impact) = match category.as_str() {
            "knowledge" => (
                "Expand knowledge ingestion to cover more vulnerability patterns",
                "High — directly addresses missing pattern detection",
            ),
            "reasoning" => (
                "Add new reasoning rules for detected gap patterns",
                "High — fills reasoning blind spots",
            ),
            "parser" => (
                "Improve parser coverage for edge case contract patterns",
                "Medium — parser limitations affect detection baseline",
            ),
            "validation" => (
                "Tune validation thresholds to reduce false negatives",
                "Medium — validation was too strict for valid exploits",
            ),
            "confidence" => (
                "Lower confidence thresholds for specific vulnerability classes",
                "Low — hypothesis existed but scored too low",
            ),
            _ => ("Investigate and address the identified gap", "Medium"),
        };
        recs.push(ImprovementRecommendation {
            priority: i + 1,
            target: (*category).clone(),
            action: action.into(),
            expected_impact: impact.into(),
            effort: if **count > 5 {
                "High"
            } else if **count > 2 {
                "Medium"
            } else {
                "Low"
            }
            .into(),
        });
    }
    recs
}

/// Input for a miss analysis.
#[derive(Debug, Clone)]
pub struct MissInput {
    pub finding_id: String,
    pub expected_finding: String,
    pub severity: String,
    pub confidence: f64,
    pub explanation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_miss_analysis() {
        let misses = vec![
            MissInput {
                finding_id: "m1".into(),
                expected_finding: "Reentrancy in withdraw".into(),
                severity: "high".into(),
                confidence: 0.1,
                explanation: "Parser could not parse".into(),
            },
            MissInput {
                finding_id: "m2".into(),
                expected_finding: "Oracle manipulation".into(),
                severity: "critical".into(),
                confidence: 0.2,
                explanation: "No oracle pattern in knowledge".into(),
            },
        ];
        let analysis = analyze_misses(&misses);
        assert_eq!(analysis.total_missed, 2);
        assert!(!analysis.improvement_recommendations.is_empty());
    }
}
