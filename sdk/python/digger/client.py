"""Digger Python SDK client — wraps the public REST API."""

import json
import urllib.request
import urllib.error
from typing import Optional, Any, Dict, List


class ApiError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class DiggerClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Any:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            resp = urllib.request.urlopen(req)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body_text = e.read().decode() if e.fp else str(e)
            raise ApiError(f"HTTP_{e.code}", body_text)

    def _get(self, path: str) -> Any:
        return self._request("GET", path)

    def _post(self, path: str, body: Dict) -> Any:
        return self._request("POST", path, body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    # System
    def health(self) -> Dict: return self._get("/api/v1/health")
    def version(self) -> Dict: return self._get("/api/v1/version")
    def metrics(self) -> Dict: return self._get("/api/v1/metrics")

    # Analysis
    def scan(self, code: str, lang: str) -> Dict:
        return self._post("/api/v1/scan", {"code": code, "lang": lang})

    def synthesize(self, code: str, lang: str) -> Dict:
        return self._post("/api/v1/synthesize", {"code": code, "lang": lang})

    def validate(self, chain_id: str, code: str, lang: str) -> Dict:
        return self._post("/api/v1/validate", {"chain_id": chain_id, "code": code, "lang": lang})

    def execute(self, code: str, lang: str) -> Dict:
        return self._post("/api/v1/execute", {"code": code, "lang": lang})

    def evaluate(self, eval_type: str) -> Dict:
        return self._post("/api/v1/evaluate", {"eval_type": eval_type})

    # Search
    def search(self, query: str, kind: Optional[str] = None, limit: Optional[int] = None) -> Dict:
        body: Dict[str, Any] = {"q": query}
        if kind: body["kind"] = kind
        if limit: body["limit"] = limit
        return self._post("/api/v1/search", body)

    # Knowledge
    def protocol_packs(self) -> List[Dict]: return self._get("/api/v1/protocol-packs")
    def protocol_pack(self, pack_id: str) -> Dict: return self._get(f"/api/v1/protocol-packs/{pack_id}")
    def knowledge_graph(self) -> Dict: return self._get("/api/v1/knowledge/graph")

    # Organizations
    def create_org(self, name: str, user_id: str) -> Dict:
        return self._post("/api/v1/orgs", {"name": name, "user_id": user_id})

    def list_orgs(self) -> List[Dict]: return self._get("/api/v1/orgs")
    def get_org(self, org_id: str) -> Dict: return self._get(f"/api/v1/orgs/{org_id}")
    def delete_org(self, org_id: str) -> Dict: return self._delete(f"/api/v1/orgs/{org_id}")

    # Projects
    def create_project(self, org_id: str, name: str, description: str = "") -> Dict:
        return self._post(f"/api/v1/orgs/{org_id}/projects", {"name": name, "description": description})

    def list_projects(self, org_id: str) -> List[Dict]: return self._get(f"/api/v1/orgs/{org_id}/projects")
    def get_project(self, project_id: str) -> Dict: return self._get(f"/api/v1/projects/{project_id}")

    # Scans
    def list_scans(self, project_id: str) -> List[Dict]: return self._get(f"/api/v1/projects/{project_id}/scans")
    def get_scan(self, scan_id: str) -> Dict: return self._get(f"/api/v1/scans/{scan_id}")
    def compare_scans(self, scan_id: str, scan_b: str) -> Dict:
        return self._post(f"/api/v1/scans/{scan_id}/compare", {"scan_b": scan_b})

    # Reports
    def get_report(self, report_id: str) -> Dict: return self._get(f"/api/v1/reports/{report_id}")
    def report_lineage(self, report_id: str) -> List[Dict]: return self._get(f"/api/v1/reports/{report_id}/lineage")
    def diff_reports(self, report_id: str, report_b: str) -> Dict:
        return self._post(f"/api/v1/reports/{report_id}/diff", {"report_b": report_b})

    # Artifacts
    def list_artifacts(self, scan_id: str) -> List[Dict]: return self._get(f"/api/v1/scans/{scan_id}/artifacts")
    def get_artifact(self, artifact_id: str) -> Dict: return self._get(f"/api/v1/artifacts/{artifact_id}")

    # Benchmark
    def benchmark_status(self) -> Dict: return self._get("/api/v1/benchmark/status")
    def run_benchmark(self) -> Dict: return self._post("/api/v1/benchmark/run", {})

    # Ingestion
    def ingestion_status(self) -> Dict: return self._get("/api/v1/ingestion/status")

    # Webhooks
    def register_webhook(self, org_id: str, url: str, events: List[str]) -> Dict:
        return self._post(f"/api/v1/orgs/{org_id}/webhooks", {"url": url, "events": events})

    def list_webhooks(self, org_id: str) -> List[Dict]: return self._get(f"/api/v1/orgs/{org_id}/webhooks")
    def delete_webhook(self, webhook_id: str) -> Dict: return self._delete(f"/api/v1/webhooks/{webhook_id}")
