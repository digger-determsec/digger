/// Confidence Audit — explain why every confidence score exists.
use serde::{Deserialize, Serialize};

/// Audit result for a single confidence score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceAudit {
    /// Hypothesis ID.
    pub hypothesis_id: String,
    /// Base confidence.
    pub base_confidence: f64,
    /// Final confidence after adjustments.
    pub final_confidence: f64,
    /// Contributing factors.
    pub factors: Vec<ConfidenceFactor>,
    /// Whether confidence was inflated by duplicated evidence.
    pub inflation_detected: bool,
    /// Inflation details if detected.
    pub inflation_details: Option<InflationDetails>,
}

/// A factor contributing to confidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceFactor {
    /// Factor name.
    pub name: String,
    /// Factor value (0.0–1.0).
    pub value: f64,
    /// Weight in the final score.
    pub weight: f64,
    /// Contribution to final score.
    pub contribution: f64,
    /// Source of this factor.
    pub source: String,
}

/// Details about confidence inflation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InflationDetails {
    /// Number of duplicated evidence items.
    pub duplicated_evidence_count: usize,
    /// Inflation amount.
    pub inflation_amount: f64,
    /// Recommendation.
    pub recommendation: String,
}

/// Audit confidence for a set of hypotheses.
pub fn audit_confidence(
    hypotheses: &[(String, f64, Vec<String>)], // (id, confidence, evidence)
) -> Vec<ConfidenceAudit> {
    hypotheses
        .iter()
        .map(|(id, confidence, evidence)| {
            // Check for duplicated evidence
            let mut seen = std::collections::BTreeSet::new();
            let mut duplicated = 0;
            for e in evidence {
                if !seen.insert(e.clone()) {
                    duplicated += 1;
                }
            }

            let inflation = if duplicated > 0 {
                let inflation_amount = duplicated as f64 * 0.05;
                Some(InflationDetails {
                    duplicated_evidence_count: duplicated,
                    inflation_amount,
                    recommendation: format!(
                        "Remove {} duplicated evidence items to get accurate confidence",
                        duplicated
                    ),
                })
            } else {
                None
            };

            let inflation_detected = duplicated > 0;

            // Build factors
            let mut factors = vec![];

            // Evidence count factor
            let evidence_count = evidence.len() as f64;
            let evidence_factor = (evidence_count.ln_1p() / 10.0_f64.ln_1p()).min(1.0);
            factors.push(ConfidenceFactor {
                name: "evidence_count".into(),
                value: evidence_factor,
                weight: 0.3,
                contribution: evidence_factor * 0.3,
                source: "evidence_analysis".into(),
            });

            // Evidence diversity factor
            let unique_types: std::collections::BTreeSet<String> =
                evidence.iter().map(|e| classify_evidence(e)).collect();
            let diversity_factor = (unique_types.len() as f64 / 6.0).min(1.0);
            factors.push(ConfidenceFactor {
                name: "evidence_diversity".into(),
                value: diversity_factor,
                weight: 0.25,
                contribution: diversity_factor * 0.25,
                source: "evidence_analysis".into(),
            });

            // Severity factor
            let severity_factor = *confidence; // Use original confidence as proxy
            factors.push(ConfidenceFactor {
                name: "base_confidence".into(),
                value: severity_factor,
                weight: 0.35,
                contribution: severity_factor * 0.35,
                source: "hypothesis_engine".into(),
            });

            // Deduplication penalty
            let dedup_penalty = if duplicated > 0 {
                -0.1 * duplicated as f64
            } else {
                0.0
            };
            factors.push(ConfidenceFactor {
                name: "deduplication_penalty".into(),
                value: dedup_penalty,
                weight: 0.1,
                contribution: dedup_penalty,
                source: "audit".into(),
            });

            // Compute final confidence
            let final_confidence = factors
                .iter()
                .map(|f| f.contribution)
                .sum::<f64>()
                .clamp(0.0, 1.0);

            ConfidenceAudit {
                hypothesis_id: id.clone(),
                base_confidence: *confidence,
                final_confidence,
                factors,
                inflation_detected,
                inflation_details: inflation,
            }
        })
        .collect()
}

fn classify_evidence(evidence: &str) -> String {
    let lower = evidence.to_lowercase();
    if lower.contains("authority") || lower.contains("signer") {
        "authority".into()
    } else if lower.contains("state") || lower.contains("write") {
        "state".into()
    } else if lower.contains("external") || lower.contains("call") {
        "external".into()
    } else if lower.contains("cpi") {
        "cpi".into()
    } else {
        "other".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_inflation() {
        let hypotheses = vec![("H1".into(), 0.8, vec!["authority".into(), "state".into()])];
        let audits = audit_confidence(&hypotheses);
        assert!(!audits[0].inflation_detected);
    }

    #[test]
    fn test_inflation_detected() {
        let hypotheses = vec![(
            "H1".into(),
            0.8,
            vec!["authority".into(), "authority".into()],
        )];
        let audits = audit_confidence(&hypotheses);
        assert!(audits[0].inflation_detected);
    }
}
