/// Digger SDK client — wraps the public REST API.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct DiggerClient {
    base_url: String,
    api_key: Option<String>,
    http_client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<serde_json::Value>,
    pub summary: serde_json::Value,
    pub program_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesisResult {
    pub program_id: String,
    pub total_chains: usize,
    pub viable_chains: usize,
    pub eliminated_chains: usize,
    pub confirmed: usize,
    pub report_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub chain_id: String,
    pub validation_score: f64,
    pub verdict: String,
    pub report_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub confirmation_status: String,
    pub transcript_entries: usize,
    pub total_gas: u64,
    pub execution_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub detection_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub total: usize,
    pub results: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgInfo {
    pub id: String,
    pub name: String,
    pub owner_id: String,
    pub members: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub project_id: String,
    pub status: String,
    pub language: String,
    pub hypothesis_count: usize,
    pub findings_count: usize,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportInfo {
    pub id: String,
    pub scan_id: String,
    pub version: u32,
    pub report_type: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookInfo {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub active: bool,
}

impl DiggerClient {
    pub fn new(base_url: &str, api_key: Option<&str>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.map(|s| s.to_string()),
            http_client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value, ApiError> {
        let mut req = self.http_client.get(self.url(path));
        if let Some(ref key) = self.api_key {
            req = req.header("X-API-Key", key.as_str());
        }
        let resp = req.send().await.map_err(|e| ApiError { code: "HTTP_ERROR".into(), message: e.to_string() })?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError { code: format!("HTTP_{}", status), message: body });
        }
        resp.json().await.map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    async fn post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, ApiError> {
        let mut req = self.http_client.post(self.url(path)).json(body);
        if let Some(ref key) = self.api_key {
            req = req.header("X-API-Key", key.as_str());
        }
        let resp = req.send().await.map_err(|e| ApiError { code: "HTTP_ERROR".into(), message: e.to_string() })?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError { code: format!("HTTP_{}", status), message: body });
        }
        resp.json().await.map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    async fn delete(&self, path: &str) -> Result<serde_json::Value, ApiError> {
        let mut req = self.http_client.delete(self.url(path));
        if let Some(ref key) = self.api_key {
            req = req.header("X-API-Key", key.as_str());
        }
        let resp = req.send().await.map_err(|e| ApiError { code: "HTTP_ERROR".into(), message: e.to_string() })?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError { code: format!("HTTP_{}", status), message: body });
        }
        resp.json().await.map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    // ── System ──────────────────────────────────────────────────────

    pub async fn health(&self) -> Result<serde_json::Value, ApiError> { self.get("/api/v1/health").await }
    pub async fn version(&self) -> Result<serde_json::Value, ApiError> { self.get("/api/v1/version").await }
    pub async fn metrics(&self) -> Result<serde_json::Value, ApiError> { self.get("/api/v1/metrics").await }

    // ── Analysis ────────────────────────────────────────────────────

    pub async fn scan(&self, code: &str, lang: &str) -> Result<ScanResult, ApiError> {
        let val = self.post("/api/v1/scan", &serde_json::json!({"code": code, "lang": lang})).await?;
        serde_json::from_value(val).map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    pub async fn synthesize(&self, code: &str, lang: &str) -> Result<SynthesisResult, ApiError> {
        let val = self.post("/api/v1/synthesize", &serde_json::json!({"code": code, "lang": lang})).await?;
        serde_json::from_value(val).map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    pub async fn validate(&self, chain_id: &str, code: &str, lang: &str) -> Result<ValidationReport, ApiError> {
        let val = self.post("/api/v1/validate", &serde_json::json!({"chain_id": chain_id, "code": code, "lang": lang})).await?;
        serde_json::from_value(val).map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    pub async fn execute(&self, code: &str, lang: &str) -> Result<serde_json::Value, ApiError> {
        self.post("/api/v1/execute", &serde_json::json!({"code": code, "lang": lang})).await
    }

    pub async fn evaluate(&self, eval_type: &str) -> Result<serde_json::Value, ApiError> {
        self.post("/api/v1/evaluate", &serde_json::json!({"eval_type": eval_type})).await
    }

    // ── Search ──────────────────────────────────────────────────────

    pub async fn search(&self, query: &str, kind: Option<&str>, limit: Option<usize>) -> Result<SearchResult, ApiError> {
        let mut body = serde_json::json!({"q": query});
        if let Some(k) = kind { body["kind"] = serde_json::json!(k); }
        if let Some(l) = limit { body["limit"] = serde_json::json!(l); }
        let val = self.post("/api/v1/search", &body).await?;
        serde_json::from_value(val).map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    // ── Knowledge ───────────────────────────────────────────────────

    pub async fn protocol_packs(&self) -> Result<serde_json::Value, ApiError> { self.get("/api/v1/protocol-packs").await }
    pub async fn protocol_pack(&self, id: &str) -> Result<serde_json::Value, ApiError> { self.get(&format!("/api/v1/protocol-packs/{}", id)).await }
    pub async fn knowledge_graph(&self) -> Result<serde_json::Value, ApiError> { self.get("/api/v1/knowledge/graph").await }

    // ── Organizations ───────────────────────────────────────────────

    pub async fn create_org(&self, name: &str, user_id: &str) -> Result<OrgInfo, ApiError> {
        let val = self.post("/api/v1/orgs", &serde_json::json!({"name": name, "user_id": user_id})).await?;
        serde_json::from_value(val).map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    pub async fn list_orgs(&self) -> Result<serde_json::Value, ApiError> { self.get("/api/v1/orgs").await }

    // ── Projects ────────────────────────────────────────────────────

    pub async fn create_project(&self, org_id: &str, name: &str, description: Option<&str>) -> Result<ProjectInfo, ApiError> {
        let val = self.post(&format!("/api/v1/orgs/{}/projects", org_id), &serde_json::json!({"name": name, "description": description.unwrap_or("")})).await?;
        serde_json::from_value(val).map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    pub async fn list_projects(&self, org_id: &str) -> Result<serde_json::Value, ApiError> { self.get(&format!("/api/v1/orgs/{}/projects", org_id)).await }

    // ── Benchmark ───────────────────────────────────────────────────

    pub async fn benchmark_status(&self) -> Result<BenchmarkResult, ApiError> {
        let val = self.get("/api/v1/benchmark/status").await?;
        serde_json::from_value(val).map_err(|e| ApiError { code: "PARSE_ERROR".into(), message: e.to_string() })
    }

    pub async fn run_benchmark(&self) -> Result<serde_json::Value, ApiError> { self.post("/api/v1/benchmark/run", &serde_json::json!({})).await }

    // ── Ingestion ───────────────────────────────────────────────────

    pub async fn ingestion_status(&self) -> Result<serde_json::Value, ApiError> { self.get("/api/v1/ingestion/status").await }
}
