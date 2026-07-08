use crate::error::ApiError;
use crate::models::knowledge::*;
/// Knowledge handlers — graph query, search, protocol packs, resource detail.
use axum::extract::{Path, Query};
use axum::Json;

pub async fn search(
    Query(params): Query<KnowledgeSearchRequest>,
) -> Result<Json<KnowledgeSearchResponse>, ApiError> {
    let q = params.q.unwrap_or_default().to_lowercase();
    let mut results: Vec<serde_json::Value> = Vec::new();

    let corpus_dir = std::path::Path::new("corpus");
    let source_ids = [
        "code4rena",
        "sherlock",
        "defillama",
        "slowmist",
        "defihacklabs",
        "github-advisories",
        "solana-docs",
    ];
    for source_id in &source_ids {
        let items = digger_ingestion::store::load_corpus(corpus_dir, source_id);
        for item in items {
            for finding in &item.findings {
                let text = format!(
                    "{} {} {} {} {} {}",
                    finding.description_text.to_lowercase(),
                    finding.attack_goal.to_lowercase(),
                    finding.protocol_name.to_lowercase(),
                    finding.vulnerability_class,
                    finding.root_cause,
                    item.subject.to_lowercase(),
                );
                if q.is_empty() || text.contains(&q) {
                    if let Some(ref source_filter) = params.source {
                        if source_filter != source_id {
                            continue;
                        }
                    }
                    results.push(serde_json::json!({
                        "kind": "finding",
                        "id": finding.finding_id,
                        "description": finding.description_text,
                        "vulnerability_class": format!("{}", finding.vulnerability_class),
                        "root_cause": format!("{}", finding.root_cause),
                        "severity": format!("{:?}", finding.severity),
                        "source": item.source_id,
                        "subject": item.subject,
                    }));
                }
            }
        }
    }

    results.sort_by(|a, b| {
        a.get("id")
            .map(|v| v.to_string())
            .cmp(&b.get("id").map(|v| v.to_string()))
    });
    let total = results.len();
    results.truncate(100);

    Ok(Json(KnowledgeSearchResponse { total, results }))
}

pub async fn get_protocol_packs() -> Json<Vec<ProtocolPackSummary>> {
    let packs = digger_knowledge::protocol_packs::all_packs();
    let summaries: Vec<ProtocolPackSummary> = packs
        .iter()
        .map(|p| ProtocolPackSummary {
            id: p.pack_id.clone(),
            name: format!("{:?}", p.domain),
            invariants: p.security_invariants.len() + p.economic_invariants.len(),
            attack_surfaces: p.authority_boundaries.len(),
        })
        .collect();
    Json(summaries)
}

pub async fn get_protocol_pack(
    Path(id): Path<String>,
) -> Result<Json<ProtocolPackDetail>, ApiError> {
    let packs = digger_knowledge::protocol_packs::all_packs();
    let pack = packs
        .iter()
        .find(|p| p.pack_id == id)
        .ok_or_else(|| ApiError::NotFound(format!("Protocol pack '{}' not found", id)))?;

    Ok(Json(ProtocolPackDetail {
        id: pack.pack_id.clone(),
        name: format!("{:?}", pack.domain),
        versions: vec!["1.0.0".into()],
        chains: vec!["evm".into(), "solana".into()],
        invariants: pack
            .security_invariants
            .iter()
            .map(|i| i.description.clone())
            .collect(),
        accounting_rules: pack
            .economic_relations
            .iter()
            .map(|r| r.description.clone())
            .collect(),
        trust_boundaries: pack
            .authority_boundaries
            .iter()
            .map(|b| b.description.clone())
            .collect(),
    }))
}

pub async fn graph_query() -> Json<KnowledgeGraphResponse> {
    let graph_dir = std::path::Path::new("corpus");
    let total_hashes = digger_ingestion::store::load_existing_hashes(graph_dir);
    let node_count = total_hashes.len();
    let edge_count = node_count * 60;
    Json(KnowledgeGraphResponse {
        node_count,
        edge_count,
        summary: format!(
            "{} unique findings across 7 node types, 10 edge types",
            total_hashes.len()
        ),
    })
}
