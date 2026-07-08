/// Continuous Validation — automatic regression detection on every change.
use crate::eval_models::*;

/// A simple comparison result used by all comparison types.
struct ComparisonResult {
    before: usize,
    after: usize,
    consistency_score: f64,
    regressions: Vec<String>,
}

/// Run a continuous validation check.
#[allow(clippy::too_many_arguments)]
pub fn run_continuous_validation(
    benchmark_cases: usize,
    benchmark_passed: usize,
    prev_benchmark_passed: Option<usize>,
    prev_reasoning_count: Option<usize>,
    current_reasoning_count: usize,
    prev_validated: Option<usize>,
    current_validated: usize,
    prev_executed: Option<usize>,
    current_executed: usize,
) -> ContinuousValidationResult {
    let run_id = format!("cv-{}", now_ts());
    let benchmark_result = benchmark_passed == benchmark_cases;

    // Regression detection: small decrease = Warning, large decrease = Fail
    let regression_result = if let Some(prev) = prev_benchmark_passed {
        let delta = benchmark_passed as i64 - prev as i64;
        if delta < 0 && prev > 0 {
            let pct = (-delta) as f64 / prev as f64;
            if pct < 0.2 {
                RegressionVerdict::Warning
            } else {
                RegressionVerdict::Fail
            }
        } else {
            RegressionVerdict::Pass
        }
    } else {
        RegressionVerdict::Pass
    };

    let rc = compare_counts("reasoning", prev_reasoning_count, current_reasoning_count);
    let vc = compare_counts("validation", prev_validated, current_validated);
    let ec = compare_counts("execution", prev_executed, current_executed);

    let all_regression = regression_result == RegressionVerdict::Pass
        && rc.regressions.is_empty()
        && vc.regressions.is_empty()
        && ec.regressions.is_empty();
    let has_minor_regression = matches!(regression_result, RegressionVerdict::Warning);
    let overall_verdict = if benchmark_result && all_regression {
        RegressionVerdict::Pass
    } else if has_minor_regression {
        RegressionVerdict::Warning
    } else if !all_regression || !benchmark_result {
        RegressionVerdict::Fail
    } else {
        RegressionVerdict::Pass
    };

    ContinuousValidationResult {
        run_id,
        timestamp: now_iso(),
        benchmark_result,
        regression_result,
        reasoning_comparison: ReasoningComparison {
            hypotheses_before: rc.before,
            hypotheses_after: rc.after,
            consistency_score: rc.consistency_score,
            regressions: rc.regressions,
        },
        validation_comparison: ValidationComparison {
            validated_before: vc.before,
            validated_after: vc.after,
            consistency_score: vc.consistency_score,
            regressions: vc.regressions,
        },
        execution_comparison: ExecutionComparison {
            executed_before: ec.before,
            executed_after: ec.after,
            consistency_score: ec.consistency_score,
            regressions: ec.regressions,
        },
        overall_verdict,
        details: format!(
            "Benchmark: {}/{} | R: {:.2} | V: {:.2} | E: {:.2}",
            benchmark_passed,
            benchmark_cases,
            rc.consistency_score,
            vc.consistency_score,
            ec.consistency_score
        ),
    }
}

fn compare_counts(_name: &str, prev: Option<usize>, current: usize) -> ComparisonResult {
    let (prev_count, regressions) = match prev {
        Some(p) => {
            let mut regs = Vec::new();
            if current < p {
                regs.push(format!("Count decreased: {} -> {}", p, current));
            }
            (p, regs)
        }
        None => (0, vec![]),
    };
    let consistency = if prev_count == 0 {
        1.0
    } else {
        (current as f64 / prev_count as f64).min(1.0)
    };
    ComparisonResult {
        before: prev_count,
        after: current,
        consistency_score: consistency,
        regressions,
    }
}

/// Snapshot of corpus state.
#[derive(Debug, Clone)]
pub struct CorpusSnapshot {
    pub total_findings: usize,
    pub total_cases: usize,
    pub passed_cases: usize,
    pub validated_findings: usize,
    pub executed_chains: usize,
    pub timestamp: String,
}

#[allow(dead_code)]
fn read_corpus_stats(corpus_dir: &str) -> CorpusSnapshot {
    let corpus_path = std::path::Path::new(corpus_dir);
    let mut total_findings = 0usize;
    let mut total_cases = 0usize;
    let mut passed_cases = 0usize;

    if let Ok(entries) = std::fs::read_dir(corpus_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                        for item in &items {
                            if let Some(findings) = item.get("findings") {
                                if let Some(arr) = findings.as_array() {
                                    total_findings += arr.len();
                                }
                            }
                        }
                        total_cases += 1;
                        passed_cases += 1;
                    }
                }
            }
        }
    }

    CorpusSnapshot {
        total_findings,
        total_cases,
        passed_cases,
        validated_findings: total_findings,
        executed_chains: 0,
        timestamp: now_iso(),
    }
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs();
    format!("{}s", secs)
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
    fn test_continuous_validation_pass() {
        let result =
            run_continuous_validation(10, 10, Some(10), Some(5), 5, Some(3), 3, Some(2), 2);
        assert_eq!(result.overall_verdict, RegressionVerdict::Pass);
        assert!(result.benchmark_result);
    }

    #[test]
    fn test_continuous_validation_regression() {
        let result = run_continuous_validation(10, 8, Some(10), None, 0, None, 0, None, 0);
        assert_eq!(result.overall_verdict, RegressionVerdict::Fail);
    }

    #[test]
    fn test_continuous_validation_warning() {
        let result = run_continuous_validation(10, 9, Some(10), None, 0, None, 0, None, 0);
        assert_eq!(result.overall_verdict, RegressionVerdict::Warning);
    }
}
