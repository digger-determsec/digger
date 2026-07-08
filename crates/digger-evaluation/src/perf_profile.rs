/// Performance Profiling — instrument every stage of the pipeline.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Comprehensive performance profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullPerformanceProfile {
    pub profile_id: String,
    pub target: String,
    pub stages: Vec<TimedStage>,
    pub total_ms: u64,
    pub memory_peak_bytes: u64,
    pub bottleneck: String,
    pub stage_percentages: BTreeMap<String, f64>,
    pub optimization_hints: Vec<String>,
}

/// A timed pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedStage {
    pub name: String,
    pub category: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub duration_ms: u64,
    pub percentage: f64,
    pub sub_stages: Vec<TimedStage>,
    pub notes: String,
}

/// Profile a complete analysis run.
#[allow(clippy::too_many_arguments)]
pub fn profile_full_run(
    target: &str,
    parse_ms: u64,
    graph_ms: u64,
    knowledge_ms: u64,
    reasoning_ms: u64,
    synthesis_ms: u64,
    validation_ms: u64,
    execution_prep_ms: u64,
    execution_ms: u64,
    differential_ms: u64,
    confirmation_ms: u64,
) -> FullPerformanceProfile {
    let stages = vec![
        TimedStage {
            name: "Parsing".into(),
            category: "Gen 1".into(),
            start_ms: 0,
            end_ms: parse_ms,
            duration_ms: parse_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Source → SystemIR".into(),
        },
        TimedStage {
            name: "Graph Construction".into(),
            category: "Gen 1".into(),
            start_ms: parse_ms,
            end_ms: parse_ms + graph_ms,
            duration_ms: graph_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "SystemIR → graph analysis".into(),
        },
        TimedStage {
            name: "Knowledge Lookup".into(),
            category: "Ingestion".into(),
            start_ms: parse_ms + graph_ms,
            end_ms: parse_ms + graph_ms + knowledge_ms,
            duration_ms: knowledge_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Knowledge graph query".into(),
        },
        TimedStage {
            name: "Reasoning".into(),
            category: "Gen 2".into(),
            start_ms: 0,
            end_ms: reasoning_ms,
            duration_ms: reasoning_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Graph → hypotheses → rankings".into(),
        },
        TimedStage {
            name: "Synthesis".into(),
            category: "Gen 3".into(),
            start_ms: 0,
            end_ms: synthesis_ms,
            duration_ms: synthesis_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Hypotheses → exploit chains".into(),
        },
        TimedStage {
            name: "Validation".into(),
            category: "Gen 3.2".into(),
            start_ms: 0,
            end_ms: validation_ms,
            duration_ms: validation_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Chains → validated plans".into(),
        },
        TimedStage {
            name: "Execution Prep".into(),
            category: "Gen 3.3".into(),
            start_ms: 0,
            end_ms: execution_prep_ms,
            duration_ms: execution_prep_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Plans → execution packages".into(),
        },
        TimedStage {
            name: "Execution".into(),
            category: "Gen 4".into(),
            start_ms: 0,
            end_ms: execution_ms,
            duration_ms: execution_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Packages → transcripts".into(),
        },
        TimedStage {
            name: "Differential".into(),
            category: "Gen 4".into(),
            start_ms: 0,
            end_ms: differential_ms,
            duration_ms: differential_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Transcripts → state diffs".into(),
        },
        TimedStage {
            name: "Confirmation".into(),
            category: "Gen 4".into(),
            start_ms: 0,
            end_ms: confirmation_ms,
            duration_ms: confirmation_ms,
            percentage: 0.0,
            sub_stages: vec![],
            notes: "Diffs → confirmations".into(),
        },
    ];

    let total_ms: u64 = stages.iter().map(|s| s.duration_ms).sum();
    let stages_with_pct: Vec<TimedStage> = stages
        .into_iter()
        .map(|mut s| {
            s.percentage = if total_ms > 0 {
                s.duration_ms as f64 / total_ms as f64 * 100.0
            } else {
                0.0
            };
            s
        })
        .collect();

    let bottleneck = stages_with_pct
        .iter()
        .max_by_key(|s| s.duration_ms)
        .map(|s| s.name.clone())
        .unwrap_or_default();

    let stage_percentages: BTreeMap<String, f64> = stages_with_pct
        .iter()
        .map(|s| (s.name.clone(), s.percentage))
        .collect();

    let mut optimization_hints = Vec::new();
    if let Some(b) = stages_with_pct.iter().max_by_key(|s| s.duration_ms) {
        if b.percentage > 40.0 {
            optimization_hints.push(format!(
                "'{}' is bottleneck ({:.0}%) — optimize first",
                b.name, b.percentage
            ));
        }
    }
    if total_ms > 30000 {
        optimization_hints.push("Total > 30s — consider caching".into());
    }

    FullPerformanceProfile {
        profile_id: format!("perf-{}", now_ts()),
        target: target.into(),
        stages: stages_with_pct,
        total_ms,
        memory_peak_bytes: 0,
        bottleneck,
        stage_percentages,
        optimization_hints,
    }
}

/// Display performance profile.
pub fn display_profile(profile: &FullPerformanceProfile) -> String {
    let mut out = format!("═══ Performance Profile: {} ═══\n", profile.target);
    out.push_str(&format!(
        "Total: {}ms | Bottleneck: {}\n\n",
        profile.total_ms, profile.bottleneck
    ));
    for stage in &profile.stages {
        let bar_len = (stage.percentage / 3.0) as usize;
        let bar = "#".repeat(bar_len.min(25));
        out.push_str(&format!(
            "  {:.<25} {:>6}ms ({:>5.1}%) [{}]\n",
            stage.name, stage.duration_ms, stage.percentage, bar
        ));
    }
    if !profile.optimization_hints.is_empty() {
        out.push_str("\n─── Optimization Hints ────────────────────────────\n");
        for h in &profile.optimization_hints {
            out.push_str(&format!("  → {}\n", h));
        }
    }
    out
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_profile() {
        let p = profile_full_run("test", 100, 50, 30, 200, 150, 80, 60, 120, 40, 30);
        assert_eq!(p.total_ms, 860);
        assert_eq!(p.bottleneck, "Reasoning");
        let display = display_profile(&p);
        assert!(display.contains("Performance Profile"));
    }
}
