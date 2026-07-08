/// Knowledge endpoint request/response types.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct KnowledgeSearchRequest {
    pub q: Option<String>,
    pub source: Option<String>,
    pub class: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KnowledgeSearchResponse {
    pub total: usize,
    pub results: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ProtocolPackSummary {
    pub id: String,
    pub name: String,
    pub invariants: usize,
    pub attack_surfaces: usize,
}

#[derive(Debug, Serialize)]
pub struct ProtocolPackDetail {
    pub id: String,
    pub name: String,
    pub versions: Vec<String>,
    pub chains: Vec<String>,
    pub invariants: Vec<String>,
    pub accounting_rules: Vec<String>,
    pub trust_boundaries: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct KnowledgeGraphResponse {
    pub node_count: usize,
    pub edge_count: usize,
    pub summary: String,
}
