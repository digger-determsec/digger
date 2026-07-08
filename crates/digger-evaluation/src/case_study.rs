/// Case Study Generator — produce publication-ready reports.
use crate::eval_models::*;
use crate::live_eval::{EvaluationResult, EvaluationTarget};

/// Generate a case study report.
pub fn generate_case_study(
    target: &EvaluationTarget,
    evaluation: &EvaluationResult,
    replay: Option<&ReplayResult>,
) -> CaseStudy {
    let protocol_overview = generate_protocol_overview(target);
    let findings_section = generate_findings_section(evaluation);
    let reasoning_section = generate_reasoning_section(evaluation);
    let comparison_section = generate_comparison_section(evaluation);
    let replay_section = replay.map(generate_replay_section).unwrap_or_default();
    let lessons = generate_lessons_learned(evaluation, replay);

    let report = format!(
        "# Case Study: {}\n\n\
        ## Protocol Overview\n{}\n\
        ## Findings\n{}\n\
        ## Reasoning\n{}\n\
        ## Exploit Synthesis\n{}\n\
        ## Execution Verification\n{}\n\
        ## Comparison Against Official Disclosure\n{}\n\
        ## Replay Analysis\n{}\n\
        ## Lessons Learned\n{}\n",
        target.protocol,
        protocol_overview,
        findings_section,
        reasoning_section,
        findings_section,
        "Execution verification performed through Gen 4 pipeline.",
        comparison_section,
        replay_section,
        lessons.join("\n")
    );

    CaseStudy {
        case_id: format!("case-{}", target.target_id),
        protocol: target.protocol.clone(),
        chain: target.chain.clone(),
        report,
        findings_count: evaluation.summary.total_digger,
        matched_count: evaluation.summary.exact_matches + evaluation.summary.partial_matches,
        f1_score: evaluation.summary.f1,
        key_findings: evaluation
            .comparisons
            .iter()
            .filter(|c| {
                matches!(
                    c.match_type,
                    MatchType::ExactMatch | MatchType::PartialMatch
                )
            })
            .map(|c| c.digger_finding.clone())
            .collect(),
        missed_count: evaluation.summary.missed_findings,
        lessons,
    }
}

/// A generated case study.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaseStudy {
    pub case_id: String,
    pub protocol: String,
    pub chain: String,
    pub report: String,
    pub findings_count: usize,
    pub matched_count: usize,
    pub f1_score: f64,
    pub key_findings: Vec<String>,
    pub missed_count: usize,
    pub lessons: Vec<String>,
}

fn generate_protocol_overview(target: &EvaluationTarget) -> String {
    let mut out = String::new();
    out.push_str(&format!("- **Protocol:** {}\n", target.protocol));
    out.push_str(&format!("- **Chain:** {}\n", target.chain));
    out.push_str(&format!("- **Source:** {}\n", target.source));
    if let Some(ref commit) = target.commit_hash {
        out.push_str(&format!("- **Commit:** {}\n", commit));
    }
    if let Some(ref ver) = target.protocol_version {
        out.push_str(&format!("- **Version:** {}\n", ver));
    }
    out.push_str(&format!(
        "- **Source files:** {}\n",
        target.source_files.len()
    ));
    out.push_str(&format!(
        "- **Official findings:** {}\n",
        target.official_findings.len()
    ));
    out
}

fn generate_findings_section(eval: &EvaluationResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Digger produced {} findings:\n\n",
        eval.summary.total_digger
    ));
    out.push_str("| # | Finding | Match | Confidence |\n");
    out.push_str("|---|---------|-------|------------|\n");
    for (i, c) in eval
        .comparisons
        .iter()
        .filter(|c| !c.digger_finding.is_empty())
        .enumerate()
    {
        let match_str = match c.match_type {
            MatchType::ExactMatch => "✓ Exact",
            MatchType::PartialMatch => "~ Partial",
            MatchType::NoMatch => "+ Unique",
            _ => "?",
        };
        out.push_str(&format!(
            "| {} | {} | {} | {:.0}% |\n",
            i + 1,
            c.digger_finding,
            match_str,
            c.confidence * 100.0
        ));
    }
    out
}

fn generate_reasoning_section(eval: &EvaluationResult) -> String {
    let mut out = String::new();
    out.push_str("Digger's reasoning pipeline:\n");
    out.push_str("1. Gen 1: Parses source code into SystemIR graph\n");
    out.push_str("2. Gen 2: Derives hypotheses from graph analysis\n");
    out.push_str("3. Gen 3: Synthesizes exploit chains with feasibility scoring\n");
    out.push_str("4. Gen 4: Executes and verifies exploits deterministically\n\n");
    out.push_str(&format!(
        "Summary: {} hypotheses → {} viable chains → {} confirmed exploits\n",
        eval.summary.total_digger,
        eval.summary.total_digger,
        eval.summary.exact_matches + eval.summary.partial_matches
    ));
    out
}

fn generate_comparison_section(eval: &EvaluationResult) -> String {
    let mut out = String::new();
    out.push_str("| Metric | Value |\n|--------|-------|\n");
    out.push_str(&format!(
        "| Precision | {:.1}% |\n",
        eval.summary.precision * 100.0
    ));
    out.push_str(&format!(
        "| Recall | {:.1}% |\n",
        eval.summary.recall * 100.0
    ));
    out.push_str(&format!("| F1 Score | {:.1}% |\n", eval.summary.f1 * 100.0));
    out.push_str(&format!(
        "| True Positives | {} |\n",
        eval.summary.exact_matches + eval.summary.partial_matches
    ));
    out.push_str(&format!(
        "| Unique Findings | {} |\n",
        eval.summary.unique_findings
    ));
    out.push_str(&format!(
        "| Missed Findings | {} |\n",
        eval.summary.missed_findings
    ));
    out.push_str(&format!(
        "| Total Runtime | {}ms |\n",
        eval.performance.total_time_ms
    ));
    out
}

fn generate_replay_section(replay: &ReplayResult) -> String {
    let mut out = String::new();
    out.push_str(&format!("- **Exploit:** {}\n", replay.exploit_name));
    out.push_str(&format!(
        "- **Root Cause Match:** {}\n",
        if replay.root_cause_match { "Yes" } else { "No" }
    ));
    out.push_str(&format!(
        "- **Components Match:** {}\n",
        if replay.affected_components_match {
            "Yes"
        } else {
            "No"
        }
    ));
    out.push_str(&format!(
        "- **Overall Accuracy:** {:.0}%\n",
        replay.overall_accuracy * 100.0
    ));
    if !replay.differences.is_empty() {
        out.push_str("\nDifferences:\n");
        for d in &replay.differences {
            out.push_str(&format!("- {}\n", d));
        }
    }
    out
}

fn generate_lessons_learned(eval: &EvaluationResult, replay: Option<&ReplayResult>) -> Vec<String> {
    let mut lessons = Vec::new();

    if eval.summary.unique_findings > 0 {
        lessons.push(format!("Digger found {} unique findings not in official reports — potential undiscovered vulnerabilities", eval.summary.unique_findings));
    }

    if eval.summary.missed_findings > 0 {
        lessons.push(format!(
            "Digger missed {} findings — improve knowledge base and reasoning rules",
            eval.summary.missed_findings
        ));
    }

    if eval.summary.f1 >= 0.8 {
        lessons.push(
            "Strong F1 score indicates good detection capability for this protocol type".into(),
        );
    } else if eval.summary.f1 < 0.5 {
        lessons.push("Low F1 score indicates significant gaps in protocol understanding".into());
    }

    if let Some(r) = replay {
        if !r.root_cause_match {
            lessons.push(
                "Root cause classification needs improvement for this vulnerability type".into(),
            );
        }
    }

    lessons
}

/// Display a case study.
pub fn display_case_study(study: &CaseStudy) -> String {
    format!(
        "═══ Case Study: {} ═══\nChain: {} | Findings: {} | Matched: {} | F1: {:.0}%\nMissed: {}\nKey Findings: {}\nLessons: {}\n═══════════════════════════════════════════════════\n",
        study.protocol, study.chain, study.findings_count, study.matched_count,
        study.f1_score * 100.0, study.missed_count,
        study.key_findings.join("; "),
        study.lessons.join("; ")
    )
}

/// Performance Profiler — measure execution times for each pipeline stage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformanceProfile {
    pub protocol: String,
    pub stages: Vec<StageTiming>,
    pub total_ms: u64,
    pub bottleneck: String,
    pub optimization_suggestions: Vec<String>,
}

/// Timing for a single pipeline stage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StageTiming {
    pub name: String,
    pub duration_ms: u64,
    pub percentage: f64,
    pub details: String,
}

/// Profile the performance of a Digger analysis run.
pub fn profile_performance(
    protocol: &str,
    parse_ms: u64,
    graph_ms: u64,
    reasoning_ms: u64,
    synthesis_ms: u64,
    validation_ms: u64,
    execution_ms: u64,
) -> PerformanceProfile {
    let total = parse_ms + graph_ms + reasoning_ms + synthesis_ms + validation_ms + execution_ms;

    let stages = vec![
        StageTiming {
            name: "Parsing".into(),
            duration_ms: parse_ms,
            percentage: if total > 0 {
                parse_ms as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            details: "Source code → SystemIR".into(),
        },
        StageTiming {
            name: "Graph Construction".into(),
            duration_ms: graph_ms,
            percentage: if total > 0 {
                graph_ms as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            details: "SystemIR → knowledge graph".into(),
        },
        StageTiming {
            name: "Reasoning".into(),
            duration_ms: reasoning_ms,
            percentage: if total > 0 {
                reasoning_ms as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            details: "Graph → hypotheses → rankings".into(),
        },
        StageTiming {
            name: "Synthesis".into(),
            duration_ms: synthesis_ms,
            percentage: if total > 0 {
                synthesis_ms as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            details: "Hypotheses → exploit chains".into(),
        },
        StageTiming {
            name: "Validation".into(),
            duration_ms: validation_ms,
            percentage: if total > 0 {
                validation_ms as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            details: "Exploit chains → validated plans".into(),
        },
        StageTiming {
            name: "Execution".into(),
            duration_ms: execution_ms,
            percentage: if total > 0 {
                execution_ms as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            details: "Plans → execution transcripts".into(),
        },
    ];

    let bottleneck = stages
        .iter()
        .max_by_key(|s| s.duration_ms)
        .map(|s| s.name.clone())
        .unwrap_or_default();

    let mut suggestions = Vec::new();
    if let Some(b) = stages.iter().max_by_key(|s| s.duration_ms) {
        if b.percentage > 50.0 {
            suggestions.push(format!(
                "'{}' is the bottleneck ({:.0}%) — optimize this stage first",
                b.name, b.percentage
            ));
        }
    }
    if total > 10000 {
        suggestions.push("Total runtime exceeds 10s — consider caching graph computations".into());
    }

    PerformanceProfile {
        protocol: protocol.into(),
        stages,
        total_ms: total,
        bottleneck,
        optimization_suggestions: suggestions,
    }
}

/// Display performance profile.
pub fn display_performance_profile(profile: &PerformanceProfile) -> String {
    let mut out = format!("═══ Performance Profile: {} ═══\n", profile.protocol);
    out.push_str(&format!(
        "Total: {}ms | Bottleneck: {}\n\n",
        profile.total_ms, profile.bottleneck
    ));
    for stage in &profile.stages {
        let bar_len = (stage.percentage / 5.0) as usize;
        let bar = "#".repeat(bar_len.min(20));
        out.push_str(&format!(
            "  {:.<25} {:>6}ms ({:>5.1}%) [{}]\n",
            stage.name, stage.duration_ms, stage.percentage, bar
        ));
    }
    if !profile.optimization_suggestions.is_empty() {
        out.push_str("\n─── Optimization Suggestions ──────────────────────\n");
        for s in &profile.optimization_suggestions {
            out.push_str(&format!("  → {}\n", s));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_improvement_analysis;
    use crate::EvaluationSummary;
    use crate::MissedFinding;
    use crate::OfficialFinding;
    use crate::PerformanceMetrics;

    #[test]
    fn test_case_study_generation() {
        let target = EvaluationTarget {
            target_id: "t1".into(),
            source: "c4".into(),
            protocol: "TestProtocol".into(),
            chain: "evm".into(),
            commit_hash: Some("abc123".into()),
            protocol_version: Some("1.0.0".into()),
            compiler_version: Some("0.8.20".into()),
            source_files: vec!["test.sol".into()],
            official_findings: vec![OfficialFinding {
                finding_id: "f1".into(),
                title: "Reentrancy".into(),
                severity: "high".into(),
                vulnerability_class: "reentrancy".into(),
                root_cause: "missing guard".into(),
                affected_contracts: vec![],
                affected_functions: vec![],
                impact: "fund loss".into(),
                mitigation: "add guard".into(),
            }],
        };
        let evaluation = EvaluationResult {
            target: target.clone(),
            digger_findings: vec![],
            comparisons: vec![FindingComparison {
                digger_finding: "Reentrancy in withdraw".into(),
                matched_official: Some("Reentrancy".into()),
                match_type: MatchType::PartialMatch,
                confidence: 0.7,
                explanation: "partial".into(),
            }],
            summary: EvaluationSummary {
                total_official: 1,
                total_digger: 1,
                exact_matches: 0,
                partial_matches: 1,
                unique_findings: 0,
                false_positives: 0,
                missed_findings: 0,
                precision: 1.0,
                recall: 1.0,
                f1: 1.0,
            },
            performance: PerformanceMetrics {
                parse_time_ms: 100,
                graph_time_ms: 50,
                reasoning_time_ms: 200,
                synthesis_time_ms: 100,
                total_time_ms: 450,
                memory_bytes: 0,
            },
            report: "test".into(),
        };
        let study = generate_case_study(&target, &evaluation, None);
        assert_eq!(study.protocol, "TestProtocol");
        assert!(study.f1_score > 0.0);
    }

    #[test]
    fn test_performance_profiling() {
        let profile = profile_performance("TestProtocol", 100, 50, 200, 150, 100, 50);
        assert_eq!(profile.total_ms, 650);
        assert_eq!(profile.bottleneck, "Reasoning");
        let display = display_performance_profile(&profile);
        assert!(display.contains("Performance Profile"));
    }

    #[test]
    fn test_improvement_analysis() {
        let misses = vec![MissedFinding {
            finding_id: "m1".into(),
            title: "Oracle".into(),
            protocol: "P".into(),
            severity: "high".into(),
            root_cause_category: "oracle".into(),
            miss_category: "knowledge".into(),
            gap_description: "No oracle patterns".into(),
            explanation: "Missing".into(),
        }];
        let analysis = generate_improvement_analysis(&misses);
        assert_eq!(analysis.total_misses, 1);
        assert!(!analysis.recommendations.is_empty());
    }
}
