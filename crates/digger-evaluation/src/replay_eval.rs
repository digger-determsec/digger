/// Historical Exploit Replay — compare Digger output against known exploits.
use crate::eval_models::*;

/// Replay a historical exploit through the Digger pipeline.
#[allow(clippy::too_many_arguments)]
pub fn replay_exploit(
    exploit_id: &str,
    exploit_name: &str,
    protocol: &str,
    chain: &str,
    expected_root_cause: &str,
    expected_affected_components: &[String],
    expected_mitigations: &[String],
    digger_root_cause: &str,
    digger_affected_components: &[String],
    digger_mitigations: &[String],
    digger_synthesis_confidence: f64,
    digger_validation_score: f64,
    digger_execution_status: &str,
) -> ReplayResult {
    let root_cause_match = normalize_string(digger_root_cause)
        == normalize_string(expected_root_cause)
        || fuzzy_match(digger_root_cause, expected_root_cause) > 0.6;

    let expected_set: std::collections::HashSet<String> =
        expected_affected_components.iter().cloned().collect();
    let digger_set: std::collections::HashSet<String> =
        digger_affected_components.iter().cloned().collect();
    let component_overlap: usize = expected_set.intersection(&digger_set).count();
    let components_match = expected_affected_components.is_empty() || component_overlap > 0;

    let expected_mit_set: std::collections::HashSet<String> =
        expected_mitigations.iter().cloned().collect();
    let digger_mit_set: std::collections::HashSet<String> =
        digger_mitigations.iter().cloned().collect();
    let mit_overlap: usize = expected_mit_set.intersection(&digger_mit_set).count();
    let mitigation_match = expected_mitigations.is_empty() || mit_overlap > 0;

    let synthesis_accuracy = digger_synthesis_confidence;
    let validation_accuracy = digger_validation_score;
    let execution_accuracy = if digger_execution_status == "Verified" {
        1.0
    } else if digger_execution_status == "VerifiedWithCaveats" {
        0.8
    } else if digger_execution_status == "PartialSuccess" {
        0.5
    } else {
        0.0
    };

    let overall_accuracy =
        synthesis_accuracy * 0.3 + validation_accuracy * 0.3 + execution_accuracy * 0.4;

    let mut differences = Vec::new();
    if !root_cause_match {
        differences.push(format!(
            "Root cause: expected '{}', got '{}'",
            expected_root_cause, digger_root_cause
        ));
    }
    if !components_match {
        let missing: Vec<String> = expected_set.difference(&digger_set).cloned().collect();
        differences.push(format!("Missing components: {}", missing.join(", ")));
    }
    if !mitigation_match {
        let missing: Vec<String> = expected_mit_set
            .difference(&digger_mit_set)
            .cloned()
            .collect();
        differences.push(format!("Missing mitigations: {}", missing.join(", ")));
    }

    let explanation = if differences.is_empty() {
        format!(
            "Exploit replay matched: accuracy {:.0}%",
            overall_accuracy * 100.0
        )
    } else {
        format!(
            "{} difference(s) found: {}",
            differences.len(),
            differences.join("; ")
        )
    };

    ReplayResult {
        exploit_id: exploit_id.to_string(),
        exploit_name: exploit_name.to_string(),
        protocol: protocol.to_string(),
        chain: chain.to_string(),
        expected_outcome: format!(
            "Root cause: {}, Components: {}",
            expected_root_cause,
            expected_affected_components.join(", ")
        ),
        digger_outcome: format!(
            "Root cause: {}, Components: {}",
            digger_root_cause,
            digger_affected_components.join(", ")
        ),
        synthesis_accuracy,
        validation_accuracy,
        execution_accuracy,
        root_cause_match,
        affected_components_match: components_match,
        mitigation_match,
        overall_accuracy,
        differences,
        explanation,
    }
}

/// Batch replay multiple exploits.
pub fn replay_exploits(exploits: &[ExploitReplayInput]) -> Vec<ReplayResult> {
    exploits
        .iter()
        .map(|e| {
            replay_exploit(
                &e.exploit_id,
                &e.exploit_name,
                &e.protocol,
                &e.chain,
                &e.expected_root_cause,
                &e.expected_affected_components,
                &e.expected_mitigations,
                &e.digger_root_cause,
                &e.digger_affected_components,
                &e.digger_mitigations,
                e.digger_synthesis_confidence,
                e.digger_validation_score,
                &e.digger_execution_status,
            )
        })
        .collect()
}

/// Aggregate replay results.
pub fn aggregate_replay_results(results: &[ReplayResult]) -> String {
    let total = results.len();
    let matched = results.iter().filter(|r| r.overall_accuracy >= 0.7).count();
    let avg_accuracy: f64 =
        results.iter().map(|r| r.overall_accuracy).sum::<f64>() / total.max(1) as f64;
    let rc_match = results.iter().filter(|r| r.root_cause_match).count();

    format!(
        "═══ Replay Summary ═══\nExploits: {} | Matched: {} ({:.0}%) | Avg Accuracy: {:.0}% | Root Cause Match: {}/{}\n",
        total, matched, matched as f64 / total.max(1) as f64 * 100.0,
        avg_accuracy * 100.0, rc_match, total
    )
}

fn normalize_string(s: &str) -> String {
    s.to_lowercase()
        .replace(['-', '_'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn fuzzy_match(a: &str, b: &str) -> f64 {
    let a_norm = normalize_string(a);
    let b_norm = normalize_string(b);
    let a_tokens: std::collections::HashSet<&str> = a_norm.split_whitespace().collect();
    let b_tokens: std::collections::HashSet<&str> = b_norm.split_whitespace().collect();
    let intersection: usize = a_tokens.intersection(&b_tokens).count();
    let union_size = a_tokens.len() + b_tokens.len() - intersection;
    if union_size > 0 {
        intersection as f64 / union_size as f64
    } else {
        0.0
    }
}

/// Input for a single exploit replay.
#[derive(Debug, Clone)]
pub struct ExploitReplayInput {
    pub exploit_id: String,
    pub exploit_name: String,
    pub protocol: String,
    pub chain: String,
    pub expected_root_cause: String,
    pub expected_affected_components: Vec<String>,
    pub expected_mitigations: Vec<String>,
    pub digger_root_cause: String,
    pub digger_affected_components: Vec<String>,
    pub digger_mitigations: Vec<String>,
    pub digger_synthesis_confidence: f64,
    pub digger_validation_score: f64,
    pub digger_execution_status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_replay() {
        let r = replay_exploit(
            "e1",
            "Cashio",
            "Cashio",
            "solana",
            "infinite mint",
            &["mint".into()],
            &["check supply".into()],
            "infinite mint",
            &["mint".into()],
            &["check supply".into()],
            0.9,
            0.9,
            "Verified",
        );
        assert!(r.overall_accuracy > 0.8);
        assert!(r.root_cause_match);
    }

    #[test]
    fn test_partial_replay() {
        let r = replay_exploit(
            "e2",
            "Test",
            "Protocol",
            "evm",
            "reentrancy",
            &["withdraw".into()],
            &["reentrancy guard".into()],
            "access control bypass",
            &["withdraw".into(), "deposit".into()],
            &["require owner".into()],
            0.7,
            0.6,
            "VerifiedWithCaveats",
        );
        assert!(!r.root_cause_match);
        assert!(r.affected_components_match);
        assert!(r.overall_accuracy > 0.0);
    }

    #[test]
    fn test_failed_replay() {
        let r = replay_exploit(
            "e3",
            "Test",
            "P",
            "evm",
            "reentrancy",
            &[],
            &[],
            "other",
            &[],
            &[],
            0.3,
            0.2,
            "Failed",
        );
        assert!(r.overall_accuracy < 0.5);
        assert!(!r.root_cause_match);
    }
}
