use crate::app::AppState;
use crate::error::ApiError;
/// Unified search handler — deterministic search across all entity types.
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SearchRequest {
    pub q: String,
    pub kind: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub total: usize,
    pub results: Vec<serde_json::Value>,
}

pub async fn search(
    State(_state): State<AppState>,
    Json(req): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, ApiError> {
    let q = req.q.to_lowercase();
    let limit = req.limit.unwrap_or(50).min(200);
    let kind_filter = req.kind.as_deref();
    let mut results: Vec<serde_json::Value> = Vec::new();

    if kind_filter.is_none() || kind_filter == Some("findings") || kind_filter == Some("finding") {
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
                    if text.contains(&q) {
                        results.push(serde_json::json!({
                            "kind": "finding",
                            "id": finding.finding_id,
                            "description": finding.description_text,
                            "vulnerability_class": format!("{}", finding.vulnerability_class),
                            "source": item.source_id,
                        }));
                    }
                }
            }
        }
    }

    if kind_filter.is_none() || kind_filter == Some("protocols") || kind_filter == Some("protocol")
    {
        let packs = digger_knowledge::protocol_packs::all_packs();
        for pack in &packs {
            let text = format!("{} {:?}", pack.pack_id, pack.domain).to_lowercase();
            if text.contains(&q) {
                results.push(serde_json::json!({
                    "kind": "protocol",
                    "id": pack.pack_id,
                    "domain": format!("{:?}", pack.domain),
                    "invariants": pack.security_invariants.len(),
                }));
            }
        }
    }

    if kind_filter.is_none()
        || kind_filter == Some("benchmarks")
        || kind_filter == Some("benchmark")
    {
        let corpus = digger_benchmark::loader::load_corpus("corpus");
        for exploit in &corpus {
            let text = format!(
                "{} {} {}",
                exploit.meta.exploit_id,
                exploit.meta.protocol.to_lowercase(),
                exploit.meta.vulnerability_class.to_lowercase(),
            )
            .to_lowercase();
            if text.contains(&q) {
                results.push(serde_json::json!({
                    "kind": "benchmark",
                    "id": exploit.meta.exploit_id,
                    "protocol": exploit.meta.protocol,
                    "vulnerability_class": exploit.meta.vulnerability_class,
                    "chain": exploit.meta.chain,
                }));
            }
        }
    }

    let total = results.len();
    results.truncate(limit);

    Ok(Json(SearchResponse { total, results }))
}
