/// False Positive Analysis — track and classify rejected hypotheses.
use crate::eval_models::*;
use std::collections::BTreeMap;

/// Analyze false positives from rejected hypotheses.
pub fn analyze_false_positives(rejected: &[RejectedHypothesis]) -> FalsePositiveAnalysis {
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_protocol: BTreeMap<String, Vec<&RejectedHypothesis>> = BTreeMap::new();
    let mut by_class: BTreeMap<String, Vec<&RejectedHypothesis>> = BTreeMap::new();

    for h in rejected {
        *reasons.entry(h.reason.clone()).or_insert(0) += 1;
        by_protocol.entry(h.protocol.clone()).or_default().push(h);
        by_class.entry(h.vuln_class.clone()).or_default().push(h);
    }

    let mut protocol_stats: BTreeMap<String, ProtocolFPStats> = BTreeMap::new();
    for (proto, hyps) in &by_protocol {
        let mut proto_reasons: BTreeMap<String, usize> = BTreeMap::new();
        for h in hyps {
            *proto_reasons.entry(h.reason.clone()).or_insert(0) += 1;
        }
        let mut top: Vec<(String, usize)> = proto_reasons.into_iter().collect();
        top.sort_by_key(|item| std::cmp::Reverse(item.1));
        protocol_stats.insert(
            proto.clone(),
            ProtocolFPStats {
                protocol: proto.clone(),
                total_rejected: hyps.len(),
                top_reasons: top.into_iter().take(3).collect(),
            },
        );
    }

    let mut class_stats: BTreeMap<String, VulnClassFPStats> = BTreeMap::new();
    for (cls, hyps) in &by_class {
        let mut cls_reasons: BTreeMap<String, usize> = BTreeMap::new();
        for h in hyps {
            *cls_reasons.entry(h.reason.clone()).or_insert(0) += 1;
        }
        let mut top: Vec<(String, usize)> = cls_reasons.into_iter().collect();
        top.sort_by_key(|item| std::cmp::Reverse(item.1));
        class_stats.insert(
            cls.clone(),
            VulnClassFPStats {
                vuln_class: cls.clone(),
                total_rejected: hyps.len(),
                top_reasons: top.into_iter().take(3).collect(),
            },
        );
    }

    let mut recommendations = Vec::new();
    let top_reason: Option<(&String, &usize)> = reasons.iter().max_by_key(|(_, v)| *v);
    if let Some((reason, count)) = top_reason {
        recommendations.push(format!(
            "Address top rejection reason '{}' ({} occurrences)",
            reason, count
        ));
    }

    FalsePositiveAnalysis {
        total_rejected: rejected.len(),
        rejection_reasons: reasons,
        by_protocol: protocol_stats,
        by_vuln_class: class_stats,
        recommendations,
    }
}

/// A rejected hypothesis.
#[derive(Debug, Clone)]
pub struct RejectedHypothesis {
    pub hypothesis_id: String,
    pub protocol: String,
    pub vuln_class: String,
    pub reason: String,
    pub severity: String,
    pub confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp_analysis() {
        let rejected = vec![
            RejectedHypothesis {
                hypothesis_id: "h1".into(),
                protocol: "P1".into(),
                vuln_class: "Reentrancy".into(),
                reason: "impossible_state".into(),
                severity: "high".into(),
                confidence: 0.3,
            },
            RejectedHypothesis {
                hypothesis_id: "h2".into(),
                protocol: "P1".into(),
                vuln_class: "AccessControl".into(),
                reason: "invalid_authority".into(),
                severity: "medium".into(),
                confidence: 0.2,
            },
            RejectedHypothesis {
                hypothesis_id: "h3".into(),
                protocol: "P2".into(),
                vuln_class: "Reentrancy".into(),
                reason: "impossible_state".into(),
                severity: "high".into(),
                confidence: 0.4,
            },
        ];
        let analysis = analyze_false_positives(&rejected);
        assert_eq!(analysis.total_rejected, 3);
        assert!(analysis.rejection_reasons.contains_key("impossible_state"));
        assert_eq!(analysis.rejection_reasons["impossible_state"], 2);
    }
}
