/// Evidence Ranking — quality-based evidence prioritization.
///
/// Ranks evidence by source quality, independence, and relevance.
/// Prefers verified exploits over inferred similarities.
/// Prefers benchmark-confirmed reasoning over historical similarity.
/// Prefers protocol-specific evidence over generic patterns.
/// Prefers multiple independent evidence sources over a single source.
///
/// All ranking is deterministic and explainable.
use serde::{Deserialize, Serialize};

/// Quality tier for evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceTier {
    /// Verified exploit — directly confirmed by real-world exploit data.
    VerifiedExploit,
    /// Benchmark confirmed — validated against known exploit corpus.
    BenchmarkConfirmed,
    /// Protocol-specific — evidence specific to this protocol's architecture.
    ProtocolSpecific,
    /// Cross-protocol — evidence from similar patterns in other protocols.
    CrossProtocol,
    /// Inferred — inferred from structural analysis, not directly confirmed.
    Inferred,
    /// Generic — generic pattern matching, low specificity.
    Generic,
}

impl std::fmt::Display for EvidenceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifiedExploit => write!(f, "verified_exploit"),
            Self::BenchmarkConfirmed => write!(f, "benchmark_confirmed"),
            Self::ProtocolSpecific => write!(f, "protocol_specific"),
            Self::CrossProtocol => write!(f, "cross_protocol"),
            Self::Inferred => write!(f, "inferred"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// A piece of evidence with quality metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankedEvidence {
    /// The evidence text.
    pub text: String,
    /// Quality tier.
    pub tier: EvidenceTier,
    /// Quality score (0.0–1.0).
    pub quality_score: f64,
    /// Source of this evidence.
    pub source: EvidenceSource,
    /// Whether this evidence is independent from other evidence.
    pub is_independent: bool,
    /// Functions involved in this evidence.
    pub involved_functions: Vec<String>,
    /// Explanation of why this score was assigned.
    pub explanation: String,
}

/// Source of evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceSource {
    /// Directly from exploit postmortem.
    ExploitPostmortem,
    /// From benchmark corpus validation.
    BenchmarkCorpus,
    /// From audit report.
    AuditReport,
    /// From protocol documentation.
    ProtocolDocumentation,
    /// From structural analysis of code.
    StructuralAnalysis,
    /// From graph traversal.
    GraphTraversal,
    /// From knowledge base.
    KnowledgeBase,
    /// Unknown source.
    Unknown,
}

impl std::fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExploitPostmortem => write!(f, "exploit_postmortem"),
            Self::BenchmarkCorpus => write!(f, "benchmark_corpus"),
            Self::AuditReport => write!(f, "audit_report"),
            Self::ProtocolDocumentation => write!(f, "protocol_documentation"),
            Self::StructuralAnalysis => write!(f, "structural_analysis"),
            Self::GraphTraversal => write!(f, "graph_traversal"),
            Self::KnowledgeBase => write!(f, "knowledge_base"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Rank evidence by quality.
///
/// Deterministic: same inputs → same ranking.
pub fn rank_evidence(evidence: &[EvidenceInput]) -> Vec<RankedEvidence> {
    let mut ranked: Vec<RankedEvidence> = evidence.iter().map(score_evidence).collect();

    // Sort by quality score descending, then by text for deterministic tiebreaking
    ranked.sort_by(|a, b| {
        b.quality_score
            .partial_cmp(&a.quality_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.text.cmp(&b.text))
    });

    ranked
}

/// Input for evidence ranking.
#[derive(Debug, Clone)]
pub struct EvidenceInput {
    /// Evidence text.
    pub text: String,
    /// Source of evidence.
    pub source: EvidenceSource,
    /// Whether this is from a verified exploit.
    pub is_verified_exploit: bool,
    /// Whether this is benchmark-confirmed.
    pub benchmark_confirmed: bool,
    /// Whether this is protocol-specific.
    pub is_protocol_specific: bool,
    /// Functions involved.
    pub involved_functions: Vec<String>,
}

fn score_evidence(input: &EvidenceInput) -> RankedEvidence {
    // Determine tier
    let tier = if input.is_verified_exploit {
        EvidenceTier::VerifiedExploit
    } else if input.benchmark_confirmed {
        EvidenceTier::BenchmarkConfirmed
    } else if input.is_protocol_specific {
        EvidenceTier::ProtocolSpecific
    } else {
        match input.source {
            EvidenceSource::ExploitPostmortem => EvidenceTier::CrossProtocol,
            EvidenceSource::BenchmarkCorpus => EvidenceTier::BenchmarkConfirmed,
            EvidenceSource::AuditReport => EvidenceTier::CrossProtocol,
            EvidenceSource::ProtocolDocumentation => EvidenceTier::ProtocolSpecific,
            EvidenceSource::StructuralAnalysis => EvidenceTier::Inferred,
            EvidenceSource::GraphTraversal => EvidenceTier::Inferred,
            EvidenceSource::KnowledgeBase => EvidenceTier::CrossProtocol,
            EvidenceSource::Unknown => EvidenceTier::Generic,
        }
    };

    // Base quality score from tier
    let tier_score: f64 = match tier {
        EvidenceTier::VerifiedExploit => 1.0,
        EvidenceTier::BenchmarkConfirmed => 0.85,
        EvidenceTier::ProtocolSpecific => 0.70,
        EvidenceTier::CrossProtocol => 0.55,
        EvidenceTier::Inferred => 0.40,
        EvidenceTier::Generic => 0.20,
    };

    // Source bonus
    let source_bonus: f64 = match input.source {
        EvidenceSource::ExploitPostmortem => 0.10,
        EvidenceSource::BenchmarkCorpus => 0.08,
        EvidenceSource::AuditReport => 0.06,
        EvidenceSource::ProtocolDocumentation => 0.05,
        EvidenceSource::StructuralAnalysis => 0.02,
        EvidenceSource::GraphTraversal => 0.02,
        EvidenceSource::KnowledgeBase => 0.03,
        EvidenceSource::Unknown => 0.0,
    };

    // Independence: evidence from different functions is more valuable
    let is_independent = input.involved_functions.len() <= 2;

    let quality_score = (tier_score + source_bonus).min(1.0);

    let explanation = format!(
        "Tier: {}, Source: {}, Score: {:.3}",
        tier, input.source, quality_score
    );

    RankedEvidence {
        text: input.text.clone(),
        tier,
        quality_score,
        source: input.source.clone(),
        is_independent,
        involved_functions: input.involved_functions.clone(),
        explanation,
    }
}

/// Aggregate evidence quality for a set of ranked evidence.
///
/// Returns a summary of the evidence quality distribution.
pub fn aggregate_evidence_quality(ranked: &[RankedEvidence]) -> EvidenceQualitySummary {
    let total = ranked.len();
    if total == 0 {
        return EvidenceQualitySummary {
            total_evidence: 0,
            avg_quality: 0.0,
            tier_counts: BTreeMap::new(),
            independent_count: 0,
            unique_sources: 0,
            quality_distribution: vec![],
        };
    }

    let avg_quality = ranked.iter().map(|e| e.quality_score).sum::<f64>() / total as f64;

    let mut tier_counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in ranked {
        *tier_counts.entry(e.tier.to_string()).or_insert(0) += 1;
    }

    let independent_count = ranked.iter().filter(|e| e.is_independent).count();

    let unique_sources: std::collections::BTreeSet<String> =
        ranked.iter().map(|e| e.source.to_string()).collect();

    // Quality distribution: [0.0-0.2), [0.2-0.4), [0.4-0.6), [0.6-0.8), [0.8-1.0]
    let mut distribution = vec![0usize; 5];
    for e in ranked {
        let bucket = ((e.quality_score * 5.0).floor() as usize).min(4);
        distribution[bucket] += 1;
    }

    EvidenceQualitySummary {
        total_evidence: total,
        avg_quality,
        tier_counts,
        independent_count,
        unique_sources: unique_sources.len(),
        quality_distribution: distribution,
    }
}

use std::collections::BTreeMap;

/// Summary of evidence quality distribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceQualitySummary {
    pub total_evidence: usize,
    pub avg_quality: f64,
    pub tier_counts: BTreeMap<String, usize>,
    pub independent_count: usize,
    pub unique_sources: usize,
    pub quality_distribution: Vec<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verified_exploit_ranks_highest() {
        let inputs = vec![
            EvidenceInput {
                text: "Inferred pattern".into(),
                source: EvidenceSource::StructuralAnalysis,
                is_verified_exploit: false,
                benchmark_confirmed: false,
                is_protocol_specific: false,
                involved_functions: vec!["fn1".into()],
            },
            EvidenceInput {
                text: "Verified exploit".into(),
                source: EvidenceSource::ExploitPostmortem,
                is_verified_exploit: true,
                benchmark_confirmed: false,
                is_protocol_specific: false,
                involved_functions: vec!["fn1".into()],
            },
        ];

        let ranked = rank_evidence(&inputs);
        assert_eq!(ranked[0].text, "Verified exploit");
        assert_eq!(ranked[0].tier, EvidenceTier::VerifiedExploit);
    }

    #[test]
    fn test_deterministic_ranking() {
        let inputs = vec![
            EvidenceInput {
                text: "A".into(),
                source: EvidenceSource::StructuralAnalysis,
                is_verified_exploit: false,
                benchmark_confirmed: false,
                is_protocol_specific: false,
                involved_functions: vec![],
            },
            EvidenceInput {
                text: "B".into(),
                source: EvidenceSource::ExploitPostmortem,
                is_verified_exploit: false,
                benchmark_confirmed: false,
                is_protocol_specific: false,
                involved_functions: vec![],
            },
        ];

        let r1 = rank_evidence(&inputs);
        let r2 = rank_evidence(&inputs);
        assert_eq!(r1.len(), r2.len());
        for i in 0..r1.len() {
            assert_eq!(r1[i].text, r2[i].text);
            assert_eq!(r1[i].quality_score, r2[i].quality_score);
        }
    }

    #[test]
    fn test_aggregate_summary() {
        let inputs = vec![
            EvidenceInput {
                text: "A".into(),
                source: EvidenceSource::ExploitPostmortem,
                is_verified_exploit: true,
                benchmark_confirmed: false,
                is_protocol_specific: false,
                involved_functions: vec![],
            },
            EvidenceInput {
                text: "B".into(),
                source: EvidenceSource::StructuralAnalysis,
                is_verified_exploit: false,
                benchmark_confirmed: false,
                is_protocol_specific: false,
                involved_functions: vec![],
            },
        ];

        let ranked = rank_evidence(&inputs);
        let summary = aggregate_evidence_quality(&ranked);

        assert_eq!(summary.total_evidence, 2);
        assert!(summary.avg_quality > 0.5);
        assert!(summary.unique_sources >= 1);
    }
}
