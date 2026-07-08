#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub title: String,
    pub summary: String,
    pub status: String,
    pub gas_used: String,
    pub state_changes: String,
    pub hash: String,
    pub key_observations: Vec<String>,
}

pub fn explain_execution(result: &serde_json::Value) -> ExecutionReport {
    let exec = result.get("execution_result").cloned().unwrap_or_default();
    let status = exec
        .get("confirmation_status")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();
    let entries = exec
        .get("transcript_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let gas = exec.get("total_gas").and_then(|v| v.as_u64()).unwrap_or(0);
    let hash = exec
        .get("execution_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let state_diff = exec.get("state_diff").cloned().unwrap_or_default();
    let storage = state_diff
        .get("storage_changes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let balances = state_diff
        .get("balance_changes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let authority = state_diff
        .get("authority_changes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let summary = if exec.is_null() {
        "No execution was performed. The synthesis phase did not produce an executable exploit chain.".into()
    } else {
        format!(
            "Execution completed with status **{}**. The transcript contains {} entries, consuming {} gas units. State was modified across {} storage slot{}, {} balance{}, and {} authority {}.",
            status,
            entries,
            gas,
            storage, if storage == 1 { "" } else { "s" },
            balances, if balances == 1 { "" } else { "s" },
            authority, if authority == 1 { "entry" } else { "entries" },
        )
    };

    let mut observations = Vec::new();
    if status.contains("Verified") || status.contains("Confirmed") {
        observations.push(
            "The execution was fully verified — all state transitions matched expectations.".into(),
        );
    }
    if gas > 500_000 {
        observations.push(format!("High gas consumption ({}) — this exploit may be economically viable only for large-value targets.", gas));
    }
    if authority > 0 {
        observations.push(format!(
            "{} authority state change{} detected — the exploit demonstrated privilege escalation.",
            authority,
            if authority == 1 { "" } else { "s" }
        ));
    }
    if balances > 0 {
        observations.push(format!(
            "{} balance change{} detected — the exploit demonstrated value extraction.",
            balances,
            if balances == 1 { "" } else { "s" }
        ));
    }

    ExecutionReport {
        title: "Execution & Verification Report".into(),
        summary,
        status,
        gas_used: gas.to_string(),
        state_changes: format!(
            "{} storage, {} balance, {} authority",
            storage, balances, authority
        ),
        hash,
        key_observations: observations,
    }
}

pub fn render_execution_markdown(report: &ExecutionReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", report.title));
    out.push_str(&format!("## Summary\n\n{}\n\n", report.summary));
    out.push_str("## Execution Details\n\n");
    out.push_str("| Metric | Value |\n|--------|-------|\n");
    out.push_str(&format!("| Status | **{}** |\n", report.status));
    out.push_str(&format!("| Gas Used | {} |\n", report.gas_used));
    out.push_str(&format!("| State Changes | {} |\n", report.state_changes));
    out.push_str(&format!("| Hash | `{}` |\n\n", report.hash));

    if !report.key_observations.is_empty() {
        out.push_str("## Key Observations\n\n");
        for obs in &report.key_observations {
            out.push_str(&format!("- {}\n", obs));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn exec_input() -> serde_json::Value {
        json!({
            "execution_result": {
                "confirmation_status": "Verified",
                "transcript_entries": 12,
                "total_gas": 750000,
                "execution_hash": "0xabc",
                "state_diff": {
                    "storage_changes": 3,
                    "balance_changes": 2,
                    "authority_changes": 1
                }
            }
        })
    }

    #[test]
    fn explain_execution_populated_yields_observations() {
        let r = explain_execution(&exec_input());
        assert_eq!(r.status, "Verified");
        assert_eq!(r.gas_used, "750000");
        assert!(r.summary.contains("Verified"));
        assert!(r.summary.contains("12 entries"));
        assert_eq!(r.key_observations.len(), 4);
        assert!(r
            .key_observations
            .iter()
            .any(|o| o.contains("privilege escalation")));
        assert!(r
            .key_observations
            .iter()
            .any(|o| o.contains("value extraction")));
    }

    #[test]
    fn explain_execution_absent_is_neutral_not_success() {
        let r = explain_execution(&json!({}));
        assert!(r.summary.contains("No execution was performed"));
        assert!(r.key_observations.is_empty());
        assert_ne!(r.status, "Verified");
    }

    #[test]
    fn explain_execution_flip_low_signal_drops_observations() {
        let mut input = exec_input();
        input["execution_result"]["total_gas"] = json!(100);
        input["execution_result"]["confirmation_status"] = json!("Pending");
        input["execution_result"]["state_diff"]["authority_changes"] = json!(0);
        input["execution_result"]["state_diff"]["balance_changes"] = json!(0);
        let r = explain_execution(&input);
        assert!(r.key_observations.is_empty());
    }

    #[test]
    fn render_execution_markdown_faithful() {
        let r = explain_execution(&exec_input());
        let md = render_execution_markdown(&r);
        assert!(md.contains("# Execution & Verification Report"));
        assert!(md.contains("| Status | **Verified** |"));
        assert!(md.contains("## Key Observations"));
        assert!(md.contains("`0xabc`"));
    }
}
