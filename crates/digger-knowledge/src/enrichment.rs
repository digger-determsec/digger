/// Knowledge Enrichment — cross-links artifacts with deterministic relationship scoring.
///
/// Every relationship is evidence-backed, deterministic, and traceable.
/// No ML. No heuristics. No invented concepts.
use digger_knowledge_models::*;
use std::collections::BTreeMap;

/// Cross-link artifacts with rich semantic relationships.
pub fn cross_link_artifacts(knowledge_items: &[NormalizedKnowledge]) -> Vec<SemanticLink> {
    let mut links = Vec::new();

    // Build indexes
    let mut findings_by_protocol: BTreeMap<String, Vec<&NormalizedFinding>> = BTreeMap::new();
    let mut findings_by_class: BTreeMap<String, Vec<&NormalizedFinding>> = BTreeMap::new();
    let mut findings_by_root_cause: BTreeMap<String, Vec<&NormalizedFinding>> = BTreeMap::new();
    let mut findings_by_technique: BTreeMap<String, Vec<&NormalizedFinding>> = BTreeMap::new();
    let mut findings_by_domain: BTreeMap<String, Vec<&NormalizedFinding>> = BTreeMap::new();

    for item in knowledge_items {
        for finding in &item.findings {
            findings_by_protocol
                .entry(finding.protocol_name.clone())
                .or_default()
                .push(finding);
            findings_by_class
                .entry(finding.vulnerability_class.to_string())
                .or_default()
                .push(finding);
            findings_by_root_cause
                .entry(finding.root_cause.to_string())
                .or_default()
                .push(finding);
            findings_by_technique
                .entry(finding.attack_technique.to_string())
                .or_default()
                .push(finding);
            findings_by_domain
                .entry(finding.protocol_domain.to_string())
                .or_default()
                .push(finding);
        }
    }

    // ── Exploit ↔ Audit Finding ──
    for item in knowledge_items {
        if item.source_kind == KnowledgeSourceKind::ExploitPostmortem {
            for ef in &item.findings {
                if let Some(audit_findings) = findings_by_protocol.get(&ef.protocol_name) {
                    for af in audit_findings {
                        if af.finding_id != ef.finding_id
                            && af.vulnerability_class == ef.vulnerability_class
                        {
                            links.push(make_link(
                                &ef.finding_id,
                                &af.finding_id,
                                LinkKind::ExploitToAuditFinding,
                                &format!(
                                    "Exploit matches audit (class: {})",
                                    ef.vulnerability_class
                                ),
                                &[
                                    (
                                        "shared_protocol",
                                        0.3,
                                        1.0,
                                        &format!("Protocol: {}", ef.protocol_name),
                                    ),
                                    (
                                        "shared_class",
                                        0.4,
                                        1.0,
                                        &format!("Class: {}", ef.vulnerability_class),
                                    ),
                                    (
                                        "shared_root_cause",
                                        0.2,
                                        if af.root_cause == ef.root_cause {
                                            1.0
                                        } else {
                                            0.0
                                        },
                                        &format!("Root cause: {}", ef.root_cause),
                                    ),
                                    (
                                        "shared_technique",
                                        0.1,
                                        if af.attack_technique == ef.attack_technique {
                                            1.0
                                        } else {
                                            0.0
                                        },
                                        &format!("Technique: {}", ef.attack_technique),
                                    ),
                                ],
                                0.8,
                            ));
                        }
                    }
                }
            }
        }
    }

    // ── Exploit ↔ Root Cause ──
    for item in knowledge_items {
        if item.source_kind == KnowledgeSourceKind::ExploitPostmortem {
            for ef in &item.findings {
                let rc = ef.root_cause.to_string();
                if !rc.starts_with("other(") {
                    if let Some(similar) = findings_by_root_cause.get(&rc) {
                        for sf in similar {
                            if sf.finding_id != ef.finding_id {
                                links.push(make_link(
                                    &ef.finding_id,
                                    &sf.finding_id,
                                    LinkKind::ExploitToRootCause,
                                    &format!("Shared root cause: {}", rc),
                                    &[
                                        (
                                            "shared_root_cause",
                                            0.5,
                                            1.0,
                                            &format!("Root cause: {}", rc),
                                        ),
                                        (
                                            "shared_class",
                                            0.3,
                                            if sf.vulnerability_class == ef.vulnerability_class {
                                                1.0
                                            } else {
                                                0.0
                                            },
                                            &format!("Class: {}", ef.vulnerability_class),
                                        ),
                                        (
                                            "shared_domain",
                                            0.2,
                                            if sf.protocol_domain == ef.protocol_domain {
                                                1.0
                                            } else {
                                                0.0
                                            },
                                            &format!("Domain: {}", ef.protocol_domain),
                                        ),
                                    ],
                                    0.7,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Exploit ↔ Attack Technique ──
    for item in knowledge_items {
        if item.source_kind == KnowledgeSourceKind::ExploitPostmortem {
            for ef in &item.findings {
                let tech = ef.attack_technique.to_string();
                if !tech.starts_with("other(") {
                    if let Some(similar) = findings_by_technique.get(&tech) {
                        for sf in similar {
                            if sf.finding_id != ef.finding_id {
                                links.push(make_link(
                                    &ef.finding_id,
                                    &sf.finding_id,
                                    LinkKind::ExploitToAttackTechnique,
                                    &format!("Shared technique: {}", tech),
                                    &[
                                        (
                                            "shared_technique",
                                            0.5,
                                            1.0,
                                            &format!("Technique: {}", tech),
                                        ),
                                        (
                                            "shared_class",
                                            0.3,
                                            if sf.vulnerability_class == ef.vulnerability_class {
                                                1.0
                                            } else {
                                                0.0
                                            },
                                            &format!("Class: {}", ef.vulnerability_class),
                                        ),
                                        (
                                            "shared_domain",
                                            0.2,
                                            if sf.protocol_domain == ef.protocol_domain {
                                                1.0
                                            } else {
                                                0.0
                                            },
                                            &format!("Domain: {}", ef.protocol_domain),
                                        ),
                                    ],
                                    0.7,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Exploit ↔ Exploit (same domain) ──
    for item in knowledge_items {
        if item.source_kind == KnowledgeSourceKind::ExploitPostmortem {
            for ef in &item.findings {
                let domain = ef.protocol_domain.to_string();
                if let Some(domain_findings) = findings_by_domain.get(&domain) {
                    for df in domain_findings {
                        if df.finding_id != ef.finding_id && df.protocol_name != ef.protocol_name {
                            links.push(make_link(
                                &ef.finding_id,
                                &df.finding_id,
                                LinkKind::ExploitToExploit,
                                &format!(
                                    "Same domain: {} ({} vs {})",
                                    domain, ef.protocol_name, df.protocol_name
                                ),
                                &[
                                    ("shared_domain", 0.3, 1.0, &format!("Domain: {}", domain)),
                                    (
                                        "shared_class",
                                        0.3,
                                        if df.vulnerability_class == ef.vulnerability_class {
                                            1.0
                                        } else {
                                            0.0
                                        },
                                        &format!("Class: {}", ef.vulnerability_class),
                                    ),
                                    (
                                        "shared_root_cause",
                                        0.2,
                                        if df.root_cause == ef.root_cause {
                                            1.0
                                        } else {
                                            0.0
                                        },
                                        &format!("Root cause: {}", ef.root_cause),
                                    ),
                                    (
                                        "cross_protocol",
                                        0.2,
                                        1.0,
                                        &format!(
                                            "Cross-protocol: {} vs {}",
                                            ef.protocol_name, df.protocol_name
                                        ),
                                    ),
                                ],
                                0.5,
                            ));
                        }
                    }
                }
            }
        }
    }

    // ── Protocol ↔ Protocol ──
    let mut protocols_by_domain: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for item in knowledge_items {
        for finding in &item.findings {
            protocols_by_domain
                .entry(finding.protocol_domain.to_string())
                .or_default()
                .push(finding.protocol_name.clone());
        }
    }
    for (domain, protocols) in &protocols_by_domain {
        let unique: Vec<&String> = protocols
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        for i in 0..unique.len() {
            for j in (i + 1)..unique.len() {
                links.push(make_link(
                    &format!("protocol:{}", unique[i]),
                    &format!("protocol:{}", unique[j]),
                    LinkKind::ProtocolToProtocol,
                    &format!("Same domain: {}", domain),
                    &[("shared_domain", 1.0, 1.0, &format!("Domain: {}", domain))],
                    0.3,
                ));
            }
        }
    }

    // ── Violates: exploit violates invariant ──
    for item in knowledge_items {
        if item.source_kind == KnowledgeSourceKind::ExploitPostmortem {
            for finding in &item.findings {
                let inv = &finding.violated_invariant;
                if !inv.kind.is_empty() && inv.kind != "unknown" {
                    links.push(make_link(
                        &finding.finding_id,
                        &format!("invariant:{}", inv.kind),
                        LinkKind::Violates,
                        &format!("Violates invariant: {}", inv.description),
                        &[
                            (
                                "violated_invariant",
                                0.6,
                                1.0,
                                &format!("Invariant: {}", inv.kind),
                            ),
                            (
                                "shared_class",
                                0.2,
                                1.0,
                                &format!("Class: {}", finding.vulnerability_class),
                            ),
                            (
                                "shared_root_cause",
                                0.2,
                                1.0,
                                &format!("Root cause: {}", finding.root_cause),
                            ),
                        ],
                        0.9,
                    ));
                }
            }
        }
    }

    // ── Mitigates: finding has mitigation ──
    for item in knowledge_items {
        for finding in &item.findings {
            if let Some(ref mitigation) = finding.mitigation_pattern {
                links.push(make_link(
                    &finding.finding_id,
                    &format!("mitigation:{}", mitigation.technique),
                    LinkKind::Mitigates,
                    &format!("Mitigated by: {}", mitigation.technique),
                    &[
                        (
                            "has_mitigation",
                            0.5,
                            1.0,
                            &format!("Mitigation: {}", mitigation.technique),
                        ),
                        (
                            "standard_mitigation",
                            0.3,
                            if mitigation.is_standard { 1.0 } else { 0.5 },
                            &format!("Standard: {}", mitigation.is_standard),
                        ),
                        (
                            "shared_class",
                            0.2,
                            1.0,
                            &format!("Class: {}", finding.vulnerability_class),
                        ),
                    ],
                    0.8,
                ));
            }
        }
    }

    // ── DerivesFrom: finding derives from protocol domain ──
    for item in knowledge_items {
        for finding in &item.findings {
            let domain = finding.protocol_domain.to_string();
            if domain != "generic" {
                links.push(make_link(
                    &finding.finding_id,
                    &format!("domain:{}", domain),
                    LinkKind::DerivesFrom,
                    &format!("Derives from {} domain", domain),
                    &[
                        ("protocol_domain", 0.6, 1.0, &format!("Domain: {}", domain)),
                        (
                            "protocol_category",
                            0.4,
                            1.0,
                            &format!("Category: {}", finding.protocol_category),
                        ),
                    ],
                    0.6,
                ));
            }
        }
    }

    // Deduplicate
    links.sort_by(|a, b| {
        a.source_id
            .cmp(&b.source_id)
            .then(a.target_id.cmp(&b.target_id))
            .then(a.kind.to_string().cmp(&b.kind.to_string()))
    });
    links.dedup_by(|a, b| {
        a.source_id == b.source_id && a.target_id == b.target_id && a.kind == b.kind
    });
    links
}

/// Helper to build a SemanticLink with deterministic scoring.
fn make_link(
    source_id: &str,
    target_id: &str,
    kind: LinkKind,
    description: &str,
    factors: &[(&str, f64, f64, &str)],
    base_confidence: f64,
) -> SemanticLink {
    let mut total = 0.0;
    let mut score_factors = Vec::new();
    for (name, weight, value, evidence) in factors {
        total += weight * value;
        score_factors.push(ScoreFactor {
            name: name.to_string(),
            weight: *weight,
            value: *value,
            evidence: evidence.to_string(),
        });
    }
    SemanticLink {
        source_id: source_id.into(),
        target_id: target_id.into(),
        kind,
        description: description.into(),
        score: RelationshipScore {
            score: total.min(1.0),
            factors: score_factors,
        },
        confidence: base_confidence,
    }
}

/// Compute relationship analytics.
pub fn compute_relationship_analytics(
    knowledge_items: &[NormalizedKnowledge],
    links: &[SemanticLink],
) -> RelationshipAnalytics {
    let all_findings: Vec<&NormalizedFinding> = knowledge_items
        .iter()
        .flat_map(|k| k.findings.iter())
        .collect();
    let total_findings = all_findings.len();

    let exploits: Vec<&NormalizedFinding> = all_findings
        .iter()
        .filter(|f| {
            f.report_id.starts_with("postmortem:")
                || f.report_id.starts_with("defihacklabs:")
                || f.report_id.starts_with("defillama:")
        })
        .cloned()
        .collect();
    let total_exploits = exploits.len();

    let exploit_to_audit_links = links
        .iter()
        .filter(|l| matches!(l.kind, LinkKind::ExploitToAuditFinding))
        .count();
    let exploit_to_invariant_links = links
        .iter()
        .filter(|l| matches!(l.kind, LinkKind::Violates))
        .count();
    let exploit_to_audit_rate = if total_exploits > 0 {
        exploit_to_audit_links as f64 / total_exploits as f64
    } else {
        0.0
    };
    let exploit_to_invariant_rate = if total_exploits > 0 {
        exploit_to_invariant_links as f64 / total_exploits as f64
    } else {
        0.0
    };

    let total_artifacts = total_findings + knowledge_items.len();
    let relationship_density = if total_artifacts > 0 {
        links.len() as f64 / total_artifacts as f64
    } else {
        0.0
    };

    let scores: Vec<f64> = links.iter().map(|l| l.score.score).collect();
    let score_distribution = compute_score_distribution(&scores);

    let mut sorted_links: Vec<&SemanticLink> = links.iter().collect();
    sorted_links.sort_by(|a, b| {
        b.score
            .score
            .partial_cmp(&a.score.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let strongest: Vec<SemanticLink> = sorted_links.iter().take(10).map(|l| (*l).clone()).collect();
    let weakest: Vec<SemanticLink> = sorted_links
        .iter()
        .rev()
        .take(10)
        .map(|l| (*l).clone())
        .collect();

    let mut connection_count: BTreeMap<String, usize> = BTreeMap::new();
    for link in links {
        *connection_count.entry(link.source_id.clone()).or_insert(0) += 1;
        *connection_count.entry(link.target_id.clone()).or_insert(0) += 1;
    }
    let mut most_connected: Vec<ConnectedConcept> = connection_count
        .iter()
        .map(|(id, count)| ConnectedConcept {
            concept_id: id.clone(),
            kind: if id.starts_with("protocol:") {
                "protocol"
            } else {
                "finding"
            }
            .into(),
            relationship_count: *count,
            avg_score: 0.0,
        })
        .collect();
    most_connected.sort_by_key(|b| std::cmp::Reverse(b.relationship_count));

    let mut type_frequency: BTreeMap<String, usize> = BTreeMap::new();
    for link in links {
        *type_frequency.entry(link.kind.to_string()).or_insert(0) += 1;
    }

    let mut coverage_by_protocol: BTreeMap<String, usize> = BTreeMap::new();
    let mut coverage_by_class: BTreeMap<String, usize> = BTreeMap::new();
    let mut coverage_by_root_cause: BTreeMap<String, usize> = BTreeMap::new();
    for link in links {
        if let Some(finding) = all_findings.iter().find(|f| f.finding_id == link.source_id) {
            *coverage_by_protocol
                .entry(finding.protocol_name.clone())
                .or_insert(0) += 1;
            *coverage_by_class
                .entry(finding.vulnerability_class.to_string())
                .or_insert(0) += 1;
            *coverage_by_root_cause
                .entry(finding.root_cause.to_string())
                .or_insert(0) += 1;
        }
    }

    let mut invariant_violations: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    for finding in &all_findings {
        let inv = finding.violated_invariant.kind.clone();
        if !inv.is_empty() && inv != "unknown" {
            let entry = invariant_violations.entry(inv).or_insert((0, vec![]));
            entry.0 += 1;
            if !entry.1.contains(&finding.protocol_name) {
                entry.1.push(finding.protocol_name.clone());
            }
        }
    }
    let mut common_invariant_violations: Vec<InvariantViolationStat> = invariant_violations
        .into_iter()
        .map(|(invariant, (count, protocols))| InvariantViolationStat {
            invariant,
            violation_count: count,
            protocols,
        })
        .collect();
    common_invariant_violations.sort_by_key(|a| std::cmp::Reverse(a.violation_count));

    let mut class_counts: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    for finding in &all_findings {
        let class = finding.vulnerability_class.to_string();
        if !class.starts_with("other(") {
            let entry = class_counts.entry(class).or_insert((0, vec![]));
            entry.0 += 1;
            if !entry.1.contains(&finding.protocol_name) {
                entry.1.push(finding.protocol_name.clone());
            }
        }
    }
    let mut weak_concepts: Vec<WeakConcept> = class_counts
        .iter()
        .filter(|(_, (count, _))| *count < 5)
        .map(|(name, (count, protocols))| WeakConcept {
            name: name.clone(),
            kind: "vulnerability_class".into(),
            finding_count: *count,
            protocol_count: protocols.len(),
            recommendation: format!(
                "Need more evidence for '{}' ({} findings, {} protocols)",
                name,
                count,
                protocols.len()
            ),
        })
        .collect();
    weak_concepts.sort_by_key(|a| a.finding_count);

    RelationshipAnalytics {
        exploit_to_audit_rate,
        exploit_to_standard_rate: 0.0,
        exploit_to_invariant_rate,
        protocol_component_coverage: 0,
        total_protocol_components: 0,
        invariant_coverage: common_invariant_violations.len(),
        total_invariants: common_invariant_violations.len(),
        trust_boundary_coverage: 0,
        total_trust_boundaries: 0,
        relationship_density,
        avg_relationships_per_artifact: relationship_density,
        common_exploit_chains: vec![],
        common_invariant_violations,
        weak_concepts,
        score_distribution,
        strongest_relationships: strongest,
        weakest_relationships: weakest,
        most_connected,
        type_frequency,
        causal_chain_depth: ChainDepthStats {
            max_depth: 0,
            avg_depth: 0.0,
            depth_distribution: BTreeMap::new(),
        },
        coverage_by_protocol,
        coverage_by_class,
        coverage_by_root_cause,
        disconnected_clusters: vec![],
    }
}

fn compute_score_distribution(scores: &[f64]) -> ScoreDistribution {
    if scores.is_empty() {
        return ScoreDistribution {
            min: 0.0,
            max: 0.0,
            mean: 0.0,
            median: 0.0,
            std_dev: 0.0,
            buckets: vec![0; 5],
        };
    }
    let mut sorted = scores.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let median = if sorted.len().is_multiple_of(2) {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    } else {
        sorted[sorted.len() / 2]
    };
    let variance = sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / sorted.len() as f64;
    let std_dev = variance.sqrt();
    let mut buckets = vec![0usize; 5];
    for s in scores {
        let bucket = (s * 4.99).min(4.0) as usize;
        buckets[bucket] += 1;
    }
    ScoreDistribution {
        min,
        max,
        mean,
        median,
        std_dev,
        buckets,
    }
}

pub fn analytics_to_json(analytics: &RelationshipAnalytics) -> String {
    serde_json::to_string_pretty(analytics).unwrap_or_else(|_| "{}".into())
}
