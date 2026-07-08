/// Gen 4.2 — Differential State Analysis.
use crate::models::*;
use std::collections::BTreeMap;

pub fn analyze_differential(
    transcript: &ExecutionTranscript,
    pre_storage: &BTreeMap<String, String>,
    pre_balance: &BTreeMap<String, f64>,
    pre_authority: &BTreeMap<String, bool>,
    invariants: &[String],
) -> DifferentialAnalysis {
    let mut post_storage = pre_storage.clone();
    let mut post_balance = pre_balance.clone();
    let mut post_authority = pre_authority.clone();

    for entry in &transcript.entries {
        for change in &entry.state_changes {
            post_storage.insert(change.slot.clone(), change.after.clone());
        }
        for change in &entry.balance_changes {
            *post_balance.entry(change.account.clone()).or_insert(0.0) = change.after;
        }
    }

    for ac in &transcript.state_diff.authority_changes {
        post_authority.insert(ac.account.clone(), ac.new_authority != "none");
    }

    let invariant_status: Vec<InvariantStatus> = invariants
        .iter()
        .map(|inv| {
            let held_before = true;
            let held_after = !transcript.entries.iter().any(|e| {
                e.state_changes
                    .iter()
                    .any(|sc| sc.slot.to_lowercase().contains(&inv.to_lowercase()))
            });
            let violated_by_step = if held_before && !held_after {
                transcript
                    .entries
                    .iter()
                    .find(|e| {
                        e.state_changes
                            .iter()
                            .any(|sc| sc.slot.to_lowercase().contains(&inv.to_lowercase()))
                    })
                    .map(|e| e.step_index)
            } else {
                None
            };
            InvariantStatus {
                invariant_id: format!("inv-{}", inv.replace(' ', "_")),
                description: inv.clone(),
                held_before,
                held_after,
                violated_by_step,
                evidence: if !held_after {
                    vec![format!("'{}' broken", inv)]
                } else {
                    vec![]
                },
            }
        })
        .collect();

    let mutations: Vec<ProtocolMutation> = transcript
        .entries
        .iter()
        .flat_map(|entry| {
            entry.state_changes.iter().map(|sc| ProtocolMutation {
                kind: MutationKind::StateWrite,
                target: sc.slot.clone(),
                before: sc.before.clone(),
                after: sc.after.clone(),
                step_index: entry.step_index,
                expected: true,
            })
        })
        .collect();

    let violated_count = invariant_status
        .iter()
        .filter(|i| !i.held_after && i.held_before)
        .count();
    let mutation_count = mutations.len();
    let verdict = if violated_count > 0 {
        DiffVerdict::ExpectedVulnerability
    } else if mutation_count > 0 {
        DiffVerdict::PartiallyExpected
    } else {
        DiffVerdict::NoChange
    };

    DifferentialAnalysis {
        storage_before: pre_storage.clone(),
        storage_after: post_storage,
        balance_before: pre_balance.clone(),
        balance_after: post_balance,
        ownership_before: BTreeMap::new(),
        ownership_after: BTreeMap::new(),
        authority_before: pre_authority.clone(),
        authority_after: post_authority,
        invariant_status,
        mutations,
        economic_impact: EconomicImpactAnalysis {
            total_extracted: BTreeMap::new(),
            total_deposited: BTreeMap::new(),
            protocol_impact: vec![],
            profit_margin: 0.0,
            roi: 0.0,
        },
        verdict,
        explanation: format!(
            "{} violations, {} mutations",
            violated_count, mutation_count
        ),
    }
}

pub fn generate_replay_report(transcript: &ExecutionTranscript) -> String {
    let mut r = "═══ Replay Report ═══\n".to_string();
    r.push_str(&format!(
        "Status: {:?} | Gas: {} | Steps: {}\n",
        transcript.status,
        transcript.gas_summary.total_gas,
        transcript.entries.len()
    ));
    for e in &transcript.entries {
        r.push_str(&format!(
            "Step {}: {} [{}]\n",
            e.step_index,
            e.function,
            if e.success { "OK" } else { "FAIL" }
        ));
    }
    r.push_str(&format!(
        "Net profit: {:?}\n",
        transcript.economic_outcome.net_profit
    ));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_change_differential() {
        let t = ExecutionTranscript {
            transcript_id: "t".into(),
            chain_id: "t".into(),
            package_id: "t".into(),
            status: ExecutionStatus::Completed,
            entries: vec![],
            state_diff: StateDiff {
                storage_changes: vec![],
                balance_changes: vec![],
                account_creations: vec![],
                account_closures: vec![],
                authority_changes: vec![],
                total_storage_writes: 0,
                total_balance_transfers: 0,
            },
            economic_outcome: EconomicOutcome {
                total_value_extracted: BTreeMap::new(),
                total_value_deposited: BTreeMap::new(),
                net_profit: BTreeMap::new(),
                gas_cost: 0.0,
                protocol_losses: BTreeMap::new(),
                attacker_gains: BTreeMap::new(),
            },
            gas_summary: GasSummary {
                total_gas: 0,
                per_step: vec![],
                average_gas_per_step: 0.0,
                gas_limit: 30_000_000,
                utilization: 0.0,
            },
            total_duration_ms: 0,
            deterministic_hash: "abc".into(),
        };
        let a = analyze_differential(
            &t,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &["test".into()],
        );
        assert_eq!(a.verdict, DiffVerdict::NoChange);
    }

    #[test]
    fn test_replay_report() {
        let t = ExecutionTranscript {
            transcript_id: "t".into(),
            chain_id: "t".into(),
            package_id: "t".into(),
            status: ExecutionStatus::Completed,
            entries: vec![],
            state_diff: StateDiff {
                storage_changes: vec![],
                balance_changes: vec![],
                account_creations: vec![],
                account_closures: vec![],
                authority_changes: vec![],
                total_storage_writes: 0,
                total_balance_transfers: 0,
            },
            economic_outcome: EconomicOutcome {
                total_value_extracted: BTreeMap::new(),
                total_value_deposited: BTreeMap::new(),
                net_profit: BTreeMap::new(),
                gas_cost: 0.0,
                protocol_losses: BTreeMap::new(),
                attacker_gains: BTreeMap::new(),
            },
            gas_summary: GasSummary {
                total_gas: 100_000,
                per_step: vec![],
                average_gas_per_step: 100_000.0,
                gas_limit: 30_000_000,
                utilization: 0.003,
            },
            total_duration_ms: 50,
            deterministic_hash: "abc".into(),
        };
        let r = generate_replay_report(&t);
        assert!(r.contains("Replay Report"));
    }
}
