/// Synthesis report explanation — translates exploit chain synthesis results into NL.
use crate::templates::*;

#[derive(Debug, Clone)]
pub struct SynthesisReport {
    pub title: String,
    pub summary: String,
    pub chain_count: usize,
    pub viable_count: usize,
    pub eliminated_count: usize,
    pub confirmed_count: usize,
    pub chain_summaries: Vec<ChainSummary>,
}

#[derive(Debug, Clone)]
pub struct ChainSummary {
    pub id: String,
    pub rank: usize,
    pub score: String,
    pub description: String,
    pub step_count: usize,
}

pub fn explain_synthesis(result: &serde_json::Value) -> SynthesisReport {
    let total = result
        .get("total_chains")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let viable = result
        .get("viable_chains")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let eliminated = result
        .get("eliminated_chains")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let confirmed = result
        .get("confirmations")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let summary = if total == 0 {
        "No exploit chains were synthesized. The analysis did not identify viable multi-step attack paths.".into()
    } else if confirmed > 0 {
        format!(
            "Synthesis produced {} exploit chain{}, of which {} {} confirmed as high-confidence. {} were eliminated during feasibility analysis.",
            total, if total == 1 { "" } else { "s" },
            confirmed, if confirmed == 1 { "is" } else { "are" },
            eliminated
        )
    } else {
        format!(
            "Synthesis produced {} exploit chain{} ({} viable, {} eliminated). No chains achieved full confirmation.",
            total, if total == 1 { "" } else { "s" }, viable, eliminated
        )
    };

    let rankings = result
        .get("rankings")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    let explanations = result
        .get("explanations")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let chain_summaries: Vec<ChainSummary> = rankings
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let chain_id = r
                .get("chain_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let score = r.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let explanation = explanations
                .iter()
                .find(|e| e.get("chain_id").and_then(|v| v.as_str()) == Some(chain_id));
            let description = explanation
                .and_then(|e| e.get("summary").and_then(|v| v.as_str()))
                .unwrap_or("Exploit chain");
            let steps = explanation
                .and_then(|e| e.get("step_explanations").and_then(|v| v.as_array()))
                .map(|s| s.len())
                .unwrap_or(0);

            ChainSummary {
                id: chain_id.to_string(),
                rank: i + 1,
                score: format!("{:.1}%", score * 100.0),
                description: description.to_string(),
                step_count: steps,
            }
        })
        .collect();

    SynthesisReport {
        title: "Exploit Chain Synthesis Report".into(),
        summary,
        chain_count: total,
        viable_count: viable,
        eliminated_count: eliminated,
        confirmed_count: confirmed,
        chain_summaries,
    }
}

pub fn render_synthesis_markdown(report: &SynthesisReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", report.title));
    out.push_str(&format!("## Summary\n\n{}\n\n", report.summary));
    out.push_str(&format!(
        "**Chains:** {} total | {} viable | {} eliminated | {} confirmed\n\n",
        report.chain_count, report.viable_count, report.eliminated_count, report.confirmed_count
    ));

    if !report.chain_summaries.is_empty() {
        out.push_str("## Ranked Exploit Chains\n\n");
        for c in &report.chain_summaries {
            out.push_str(&format!(
                "### Rank #{} — {} (Score: {})\n\n",
                c.rank, c.id, c.score
            ));
            out.push_str(&format!("{}\n\n", c.description));
            if c.step_count > 0 {
                out.push_str(&format!(
                    "**Steps:** {}\n\n",
                    count_word(c.step_count, "step", "steps")
                ));
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn synth_input() -> serde_json::Value {
        json!({
            "total_chains": 3,
            "viable_chains": 2,
            "eliminated_chains": 1,
            "confirmations": [{"chain_id": "c1"}],
            "rankings": [
                {"chain_id": "c1", "score": 0.91},
                {"chain_id": "c2", "score": 0.55}
            ],
            "explanations": [
                {"chain_id": "c1", "summary": "Drain via reentrancy", "step_explanations": [{}, {}, {}]}
            ]
        })
    }

    #[test]
    fn explain_synthesis_populated_builds_ranked_summaries() {
        let r = explain_synthesis(&synth_input());
        assert_eq!(r.chain_count, 3);
        assert_eq!(r.viable_count, 2);
        assert_eq!(r.eliminated_count, 1);
        assert_eq!(r.confirmed_count, 1);
        assert_eq!(r.chain_summaries.len(), 2);
        assert_eq!(r.chain_summaries[0].id, "c1");
        assert_eq!(r.chain_summaries[0].rank, 1);
        assert_eq!(r.chain_summaries[0].score, "91.0%");
        assert_eq!(r.chain_summaries[0].description, "Drain via reentrancy");
        assert_eq!(r.chain_summaries[0].step_count, 3);
        assert_eq!(r.chain_summaries[1].description, "Exploit chain");
        assert_eq!(r.chain_summaries[1].step_count, 0);
    }

    #[test]
    fn explain_synthesis_empty_does_not_fabricate() {
        let r = explain_synthesis(&json!({}));
        assert_eq!(r.chain_count, 0);
        assert!(r.chain_summaries.is_empty());
        assert!(r.summary.contains("No exploit chains were synthesized"));
    }

    #[test]
    fn explain_synthesis_flip_no_confirmations_drops_claim() {
        let mut input = synth_input();
        input["confirmations"] = json!([]);
        let r = explain_synthesis(&input);
        assert_eq!(r.confirmed_count, 0);
        assert!(r.summary.contains("No chains achieved full confirmation"));
        assert!(!r
            .summary
            .to_lowercase()
            .contains("confirmed as high-confidence"));
    }

    #[test]
    fn render_synthesis_markdown_preserves_rank_order() {
        let r = explain_synthesis(&synth_input());
        let md = render_synthesis_markdown(&r);
        assert!(md.contains("# Exploit Chain Synthesis Report"));
        let p1 = md.find("Rank #1").expect("rank 1 present");
        let p2 = md.find("Rank #2").expect("rank 2 present");
        assert!(p1 < p2, "input order must be preserved deterministically");
        assert_eq!(md, render_synthesis_markdown(&r));
    }
}
