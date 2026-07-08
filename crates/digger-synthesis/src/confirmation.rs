/// Gen 4.3 — Exploit Confirmation + Knowledge Graph Feedback.
use crate::models::*;

pub fn confirm_exploit(
    transcript: &ExecutionTranscript,
    differential: &DifferentialAnalysis,
    chain: &ExploitChain,
) -> ExecutionConfirmation {
    let (status, confidence, explanation) = classify_execution(transcript, differential);
    let evidence = build_evidence(transcript, differential, chain);
    let knowledge_feedback = if matches!(
        status,
        ConfirmationStatus::Verified | ConfirmationStatus::VerifiedWithCaveats
    ) {
        Some(build_knowledge_feedback(
            chain, &status, confidence, &evidence,
        ))
    } else {
        None
    };
    ExecutionConfirmation {
        confirmation_id: format!("confirm-{}", chain.chain_id),
        chain_id: chain.chain_id.clone(),
        status,
        confidence,
        evidence,
        explanation,
        differential: differential.clone(),
        transcript: transcript.clone(),
        knowledge_feedback,
    }
}

fn classify_execution(
    transcript: &ExecutionTranscript,
    differential: &DifferentialAnalysis,
) -> (ConfirmationStatus, f64, String) {
    let ok = matches!(transcript.status, ExecutionStatus::Completed);
    let violations = differential
        .invariant_status
        .iter()
        .filter(|i| !i.held_after && i.held_before)
        .count();
    let profit = differential
        .economic_impact
        .total_extracted
        .values()
        .any(|v| *v > 0.0);
    let has_unexpected = differential.mutations.iter().any(|m| !m.expected);
    match (ok, violations > 0, profit, has_unexpected) {
        (true, true, _, false) => (
            ConfirmationStatus::Verified,
            0.95,
            format!("{} violations confirmed", violations),
        ),
        (true, _, _, false) => (
            ConfirmationStatus::VerifiedWithCaveats,
            0.80,
            "Completed with caveats".into(),
        ),
        (false, _, _, _) => (
            ConfirmationStatus::Failed,
            0.20,
            format!("Failed: {:?}", transcript.status),
        ),
        _ => (ConfirmationStatus::PartialSuccess, 0.50, "Partial".into()),
    }
}

fn build_evidence(
    transcript: &ExecutionTranscript,
    differential: &DifferentialAnalysis,
    chain: &ExploitChain,
) -> Vec<String> {
    let mut e: Vec<String> = chain
        .evidence_provenance
        .iter()
        .map(|r| format!("{}:{}", r.source, r.ref_id))
        .collect();
    e.push(format!("exec:status:{:?}", transcript.status));
    e.push(format!("exec:gas:{}", transcript.gas_summary.total_gas));
    e.push(format!("diff:verdict:{:?}", differential.verdict));
    e.push(format!(
        "diff:violations:{}",
        differential
            .invariant_status
            .iter()
            .filter(|i| !i.held_after && i.held_before)
            .count()
    ));
    e
}

fn build_knowledge_feedback(
    chain: &ExploitChain,
    status: &ConfirmationStatus,
    confidence: f64,
    evidence: &[String],
) -> KnowledgeFeedback {
    let delta = match status {
        ConfirmationStatus::Verified => 0.2,
        ConfirmationStatus::VerifiedWithCaveats => 0.1,
        _ => 0.0,
    };
    KnowledgeFeedback {
        exploit_id: chain.chain_id.clone(),
        confidence_delta: delta,
        new_evidence: evidence
            .iter()
            .filter(|e| e.starts_with("exec:") || e.starts_with("diff:"))
            .cloned()
            .collect(),
        updated_findings: chain
            .steps
            .iter()
            .map(|s| format!("step:{}", s.index))
            .collect(),
        protocol_relationship_updates: chain
            .violated_invariants
            .iter()
            .map(|inv| ProtocolRelationshipUpdate {
                relationship_type: "violation_confirmed".into(),
                source: chain.goal.clone(),
                target: inv.clone(),
                strength_delta: delta,
                evidence: format!("verified:{}", chain.chain_id),
            })
            .collect(),
        benchmark_metadata_update: Some(BenchmarkMetadataUpdate {
            exploit_id: chain.chain_id.clone(),
            previous_confidence: chain.confidence,
            new_confidence: (chain.confidence + delta).clamp(0.0, 1.0),
            verification_status: format!("{:?}", status),
            execution_count: 1,
        }),
        lineage_update: ExploitLineage {
            exploit_id: chain.chain_id.clone(),
            derived_from: chain
                .evidence_provenance
                .iter()
                .map(|e| e.ref_id.clone())
                .collect(),
            similar_to: chain
                .historical_similarity
                .iter()
                .map(|s| s.exploit_id.clone())
                .collect(),
            generation: 4,
            verification_history: vec![VerificationEntry {
                timestamp: "now".into(),
                status: status.clone(),
                confidence,
                evidence: evidence.to_vec(),
            }],
        },
    }
}

impl ExecutionConfirmation {
    pub fn report(&self) -> String {
        let mut o = format!(
            "═══ Confirmation: {} ═══\nStatus: {:?} | Confidence: {:.0}%\n{}\n",
            self.chain_id,
            self.status,
            self.confidence * 100.0,
            self.explanation
        );
        for e in &self.evidence {
            o.push_str(&format!("  - {}\n", e));
        }
        o.push_str(&format!("Diff: {:?}\n", self.differential.verdict));
        if let Some(ref fb) = self.knowledge_feedback {
            o.push_str(&format!(
                "Feedback: confidence {:+.2}\n",
                fb.confidence_delta
            ));
        }
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_transcript(status: ExecutionStatus) -> ExecutionTranscript {
        ExecutionTranscript {
            transcript_id: "t".into(),
            chain_id: "t".into(),
            package_id: "t".into(),
            status,
            entries: vec![TranscriptEntry {
                step_index: 0,
                transaction_index: 0,
                timestamp_ms: 0,
                kind: TranscriptEntryKind::Transaction,
                contract: "0x1".into(),
                function: "test".into(),
                from: "0x0".into(),
                to: "0x1".into(),
                value: "0".into(),
                input_data: "0x".into(),
                output_data: "0x".into(),
                gas_used: 21000,
                success: true,
                revert_reason: None,
                events: vec![],
                state_changes: vec![],
                balance_changes: vec![],
            }],
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
                gas_cost: 0.01,
                protocol_losses: BTreeMap::new(),
                attacker_gains: BTreeMap::new(),
            },
            gas_summary: GasSummary {
                total_gas: 21000,
                per_step: vec![],
                average_gas_per_step: 21000.0,
                gas_limit: 30_000_000,
                utilization: 0.0007,
            },
            total_duration_ms: 10,
            deterministic_hash: "h".into(),
        }
    }

    #[test]
    fn test_verified() {
        let t = make_transcript(ExecutionStatus::Completed);
        let d = DifferentialAnalysis {
            storage_before: BTreeMap::new(),
            storage_after: BTreeMap::new(),
            balance_before: BTreeMap::new(),
            balance_after: BTreeMap::new(),
            ownership_before: BTreeMap::new(),
            ownership_after: BTreeMap::new(),
            authority_before: BTreeMap::new(),
            authority_after: BTreeMap::new(),
            invariant_status: vec![InvariantStatus {
                invariant_id: "i1".into(),
                description: "test".into(),
                held_before: true,
                held_after: false,
                violated_by_step: Some(0),
                evidence: vec![],
            }],
            mutations: vec![ProtocolMutation {
                kind: MutationKind::StateWrite,
                target: "x".into(),
                before: "0".into(),
                after: "1".into(),
                step_index: 0,
                expected: true,
            }],
            economic_impact: EconomicImpactAnalysis {
                total_extracted: {
                    let mut m = BTreeMap::new();
                    m.insert("USDC".into(), 1000.0);
                    m
                },
                total_deposited: BTreeMap::new(),
                protocol_impact: vec![],
                profit_margin: 100.0,
                roi: 100.0,
            },
            verdict: DiffVerdict::ExpectedVulnerability,
            explanation: "t".into(),
        };
        let chain = ExploitChain {
            chain_id: "t".into(),
            goal: "Drain".into(),
            steps: vec![],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec!["balance".into()],
            evidence_provenance: vec![],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "t".into(),
        };
        let c = confirm_exploit(&t, &d, &chain);
        assert_eq!(c.status, ConfirmationStatus::Verified);
        assert!(c.knowledge_feedback.is_some());
    }

    #[test]
    fn test_failed() {
        let t = make_transcript(ExecutionStatus::Reverted {
            step: 0,
            reason: "r".into(),
        });
        let d = DifferentialAnalysis {
            storage_before: BTreeMap::new(),
            storage_after: BTreeMap::new(),
            balance_before: BTreeMap::new(),
            balance_after: BTreeMap::new(),
            ownership_before: BTreeMap::new(),
            ownership_after: BTreeMap::new(),
            authority_before: BTreeMap::new(),
            authority_after: BTreeMap::new(),
            invariant_status: vec![],
            mutations: vec![],
            economic_impact: EconomicImpactAnalysis {
                total_extracted: BTreeMap::new(),
                total_deposited: BTreeMap::new(),
                protocol_impact: vec![],
                profit_margin: 0.0,
                roi: 0.0,
            },
            verdict: DiffVerdict::NoChange,
            explanation: "t".into(),
        };
        let chain = ExploitChain {
            chain_id: "t".into(),
            goal: "t".into(),
            steps: vec![],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.7,
            severity: digger_ir::Severity::Medium,
            historical_similarity: vec![],
            rank: None,
            explanation: "t".into(),
        };
        let c = confirm_exploit(&t, &d, &chain);
        assert_eq!(c.status, ConfirmationStatus::Failed);
        assert!(c.knowledge_feedback.is_none());
    }
}
