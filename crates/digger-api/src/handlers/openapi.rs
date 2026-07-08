/// OpenAPI spec generation — covers all API endpoints.
use axum::Json;
use serde_json::{json, Value};

pub async fn openapi_spec() -> Json<Value> {
    Json(json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Digger — Deterministic Blockchain Security Platform",
            "version": "1.0.0",
            "description": "REST API for the Digger deterministic blockchain security analysis platform."
        },
        "servers": [
            { "url": "http://localhost:3000", "description": "Local development" }
        ],
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key. Required when DIGGER_API_KEY env is set."
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": {
                                "code": { "type": "string" },
                                "message": { "type": "string" }
                            }
                        }
                    }
                },
                "ScanRequest": {
                    "type": "object",
                    "required": ["code", "lang"],
                    "properties": {
                        "code": { "type": "string", "description": "Source code to analyze" },
                        "lang": { "type": "string", "enum": ["solidity", "sol", "anchor", "rust", "rs"] }
                    }
                },
                "RepoScanRequest": {
                    "type": "object",
                    "required": ["repo_url"],
                    "properties": {
                        "repo_url": { "type": "string", "description": "Git repository URL (https/http/git only)" },
                        "branch": { "type": "string", "description": "Branch name (optional)" }
                    }
                },
                "ExplainRequest": {
                    "type": "object",
                    "required": ["code", "lang"],
                    "properties": {
                        "code": { "type": "string" },
                        "lang": { "type": "string" }
                    }
                }
            }
        },
        "security": [{"ApiKeyAuth": []}],
        "paths": {
            "/api/v1/health": {
                "get": {
                    "summary": "System health check",
                    "tags": ["System"],
                    "responses": { "200": { "description": "Healthy" } }
                }
            },
            "/api/v1/version": {
                "get": {
                    "summary": "Version and capability discovery",
                    "tags": ["System"],
                    "responses": { "200": { "description": "Version info" } }
                }
            },
            "/api/v1/metrics": {
                "get": {
                    "summary": "Real-time operational metrics",
                    "tags": ["System"],
                    "responses": { "200": { "description": "Metrics snapshot" } }
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "summary": "This OpenAPI specification",
                    "tags": ["System"],
                    "responses": { "200": { "description": "OpenAPI 3.0.3 JSON" } }
                }
            },
            "/api/v1/scan": {
                "post": {
                    "summary": "Scan source code for vulnerabilities",
                    "tags": ["Analysis"],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ScanRequest" } } } },
                    "responses": { "200": { "description": "Scan results" }, "408": { "description": "Scan timed out" } }
                }
            },
            "/api/v1/scan/repo": {
                "post": {
                    "summary": "Clone a git repo and scan all source files",
                    "tags": ["Analysis"],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RepoScanRequest" } } } },
                    "responses": { "200": { "description": "Per-file scan results" } }
                }
            },
            "/api/v1/synthesize": {
                "post": {
                    "summary": "Synthesize exploit chains (Gen 3)",
                    "tags": ["Analysis"],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ScanRequest" } } } },
                    "responses": { "200": { "description": "Synthesized chains" } }
                }
            },
            "/api/v1/validate": {
                "post": {
                    "summary": "Validate exploit chains (Gen 3.2)",
                    "tags": ["Analysis"],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["chain_id", "code", "lang"],
                            "properties": { "chain_id": { "type": "string" }, "code": { "type": "string" }, "lang": { "type": "string" } }
                        } } }
                    },
                    "responses": { "200": { "description": "Validation report" } }
                }
            },
            "/api/v1/execute": {
                "post": {
                    "summary": "Execute and verify exploit chains (Gen 4)",
                    "tags": ["Analysis"],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ScanRequest" } } } },
                    "responses": { "200": { "description": "Execution result with transcript" } }
                }
            },
            "/api/v1/evaluate": {
                "post": {
                    "summary": "Run evaluation framework",
                    "tags": ["Analysis"],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "properties": { "eval_type": { "type": "string", "enum": ["benchmark", "continuous"] } }
                        } } }
                    },
                    "responses": { "200": { "description": "Evaluation results" } }
                }
            },
            "/api/v1/explain/scan": {
                "post": {
                    "summary": "Generate NL explanation of scan results",
                    "tags": ["Explanation"],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ExplainRequest" } } } },
                    "responses": { "200": { "description": "Markdown report" } }
                }
            },
            "/api/v1/explain/synthesis": {
                "post": {
                    "summary": "Generate NL explanation of synthesis results",
                    "tags": ["Explanation"],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ExplainRequest" } } } },
                    "responses": { "200": { "description": "Markdown report" } }
                }
            },
            "/api/v1/explain/full": {
                "post": {
                    "summary": "Generate full executive security assessment",
                    "tags": ["Explanation"],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ExplainRequest" } } } },
                    "responses": { "200": { "description": "Executive summary markdown" } }
                }
            },
            "/api/v1/search": {
                "post": {
                    "summary": "Search across findings, protocols, benchmarks",
                    "tags": ["Search"],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["q"],
                            "properties": {
                                "q": { "type": "string" },
                                "kind": { "type": "string", "enum": ["findings", "protocols", "benchmarks"] },
                                "limit": { "type": "integer", "maximum": 200, "default": 50 }
                            }
                        } } }
                    },
                    "responses": { "200": { "description": "Search results" } }
                }
            },
            "/api/v1/knowledge/search": {
                "get": {
                    "summary": "Search ingested knowledge findings",
                    "tags": ["Knowledge"],
                    "parameters": [
                        { "name": "q", "in": "query", "schema": { "type": "string" } },
                        { "name": "source", "in": "query", "schema": { "type": "string" } },
                        { "name": "class", "in": "query", "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "Search results" } }
                }
            },
            "/api/v1/knowledge/graph": {
                "get": {
                    "summary": "Knowledge graph statistics",
                    "tags": ["Knowledge"],
                    "responses": { "200": { "description": "Graph node/edge counts" } }
                }
            },
            "/api/v1/protocol-packs": {
                "get": {
                    "summary": "List all protocol semantic packs",
                    "tags": ["Knowledge"],
                    "responses": { "200": { "description": "List of protocol packs" } }
                }
            },
            "/api/v1/protocol-packs/{id}": {
                "get": {
                    "summary": "Get protocol pack detail",
                    "tags": ["Knowledge"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Protocol pack details" }, "404": { "description": "Not found" } }
                }
            },
            "/api/v1/finding/{id}": {
                "get": {
                    "summary": "Get finding detail by ID",
                    "tags": ["Resources"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Finding detail" }, "404": { "description": "Not found" } }
                }
            },
            "/api/v1/hypothesis/{id}": {
                "get": {
                    "summary": "Get hypothesis detail",
                    "tags": ["Resources"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Hypothesis detail" } }
                }
            },
            "/api/v1/report/{id}": {
                "get": {
                    "summary": "Get report detail",
                    "tags": ["Resources"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Report detail" } }
                }
            },
            "/api/v1/jobs/{id}": {
                "get": {
                    "summary": "Get job status",
                    "tags": ["Jobs"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Job status" }, "404": { "description": "Not found" } }
                },
                "delete": {
                    "summary": "Cancel a running job",
                    "tags": ["Jobs"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Job cancelled" }, "404": { "description": "Not found" } }
                }
            },
            "/api/v1/ingestion/status": {
                "get": {
                    "summary": "Ingestion pipeline status",
                    "tags": ["Ingestion"],
                    "responses": { "200": { "description": "Source counts and health" } }
                }
            },
            "/api/v1/ingestion/run": {
                "post": {
                    "summary": "Trigger ingestion pipeline",
                    "tags": ["Ingestion"],
                    "requestBody": {
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "properties": { "source": { "type": "string", "description": "Optional source filter" } }
                        } } }
                    },
                    "responses": { "200": { "description": "Ingestion results" } }
                }
            },
            "/api/v1/benchmark/run": {
                "post": {
                    "summary": "Run benchmark suite",
                    "tags": ["Benchmark"],
                    "requestBody": {
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "properties": { "corpus_dir": { "type": "string" } }
                        } } }
                    },
                    "responses": { "200": { "description": "Benchmark results" } }
                }
            },
            "/api/v1/benchmark/status": {
                "get": {
                    "summary": "Benchmark suite status",
                    "tags": ["Benchmark"],
                    "responses": { "200": { "description": "Benchmark metrics" } }
                }
            },
            "/api/v1/orgs": {
                "get": {
                    "summary": "List organizations",
                    "tags": ["Platform"],
                    "responses": { "200": { "description": "Organization list" } }
                },
                "post": {
                    "summary": "Create organization",
                    "tags": ["Platform"],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["name", "user_id"],
                            "properties": { "name": { "type": "string" }, "user_id": { "type": "string" } }
                        } } }
                    },
                    "responses": { "200": { "description": "Created organization" } }
                }
            },
            "/api/v1/orgs/{id}": {
                "get": {
                    "summary": "Get organization detail",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Organization detail" }, "404": { "description": "Not found" } }
                },
                "delete": {
                    "summary": "Delete organization",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Deleted" } }
                }
            },
            "/api/v1/orgs/{id}/members": {
                "post": {
                    "summary": "Add member to organization",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["user_id", "role"],
                            "properties": { "user_id": { "type": "string" }, "role": { "type": "string", "enum": ["admin", "member", "viewer"] } }
                        } } }
                    },
                    "responses": { "200": { "description": "Updated organization" } }
                }
            },
            "/api/v1/orgs/{org_id}/projects": {
                "get": {
                    "summary": "List projects in organization",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "org_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Project list" } }
                },
                "post": {
                    "summary": "Create project in organization",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "org_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["name"],
                            "properties": { "name": { "type": "string" }, "description": { "type": "string" } }
                        } } }
                    },
                    "responses": { "200": { "description": "Created project" } }
                }
            },
            "/api/v1/projects/{id}": {
                "get": {
                    "summary": "Get project detail",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Project detail" }, "404": { "description": "Not found" } }
                }
            },
            "/api/v1/orgs/{org_id}/scans": {
                "post": {
                    "summary": "Create scan record in organization",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "org_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["project_id", "language", "code"],
                            "properties": { "project_id": { "type": "string" }, "language": { "type": "string" }, "code": { "type": "string" } }
                        } } }
                    },
                    "responses": { "200": { "description": "Created scan record" } }
                }
            },
            "/api/v1/projects/{project_id}/scans": {
                "get": {
                    "summary": "List scan history for project",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "project_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Scan history" } }
                }
            },
            "/api/v1/scans/{id}": {
                "get": {
                    "summary": "Get scan detail",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Scan detail" }, "404": { "description": "Not found" } }
                }
            },
            "/api/v1/scans/{id}/compare": {
                "post": {
                    "summary": "Compare two scans",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["scan_b"],
                            "properties": { "scan_b": { "type": "string" } }
                        } } }
                    },
                    "responses": { "200": { "description": "Comparison result" } }
                }
            },
            "/api/v1/scans/{scan_id}/artifacts": {
                "get": {
                    "summary": "List artifacts for scan",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "scan_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Artifact list" } }
                }
            },
            "/api/v1/artifacts/{id}": {
                "get": {
                    "summary": "Get artifact detail",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Artifact detail" }, "404": { "description": "Not found" } }
                }
            },
            "/api/v1/reports/{id}/lineage": {
                "get": {
                    "summary": "Trace report version lineage",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Report lineage" } }
                }
            },
            "/api/v1/reports/{id}/diff": {
                "post": {
                    "summary": "Diff two report versions",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["report_b"],
                            "properties": { "report_b": { "type": "string" } }
                        } } }
                    },
                    "responses": { "200": { "description": "Diff result" } }
                }
            },
            "/api/v1/orgs/{org_id}/webhooks": {
                "get": {
                    "summary": "List webhooks for organization",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "org_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Webhook list" } }
                },
                "post": {
                    "summary": "Register webhook",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "org_id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": {
                            "type": "object",
                            "required": ["url", "events"],
                            "properties": {
                                "url": { "type": "string", "format": "uri" },
                                "events": { "type": "array", "items": { "type": "string", "enum": ["scan.completed", "scan.failed", "job.completed", "report.generated", "ingestion.completed", "benchmark.completed", "evaluation.completed"] } }
                            }
                        } } }
                    },
                    "responses": { "200": { "description": "Created webhook" } }
                }
            },
            "/api/v1/webhooks/{id}": {
                "delete": {
                    "summary": "Delete webhook",
                    "tags": ["Platform"],
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Deleted" } }
                }
            }
        },
        "tags": [
            { "name": "System", "description": "Health, version, metrics" },
            { "name": "Analysis", "description": "Scan, synthesize, validate, execute, evaluate" },
            { "name": "Explanation", "description": "Deterministic NL report generation" },
            { "name": "Search", "description": "Unified search across all entities" },
            { "name": "Knowledge", "description": "Knowledge graph and protocol packs" },
            { "name": "Resources", "description": "Finding, hypothesis, report detail" },
            { "name": "Jobs", "description": "Job status and cancellation" },
            { "name": "Ingestion", "description": "Corpus ingestion pipeline" },
            { "name": "Benchmark", "description": "Benchmark suite" },
            { "name": "Platform", "description": "Organizations, projects, scans, reports, artifacts, webhooks" }
        ]
    }))
}
