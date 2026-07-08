/// Digger SDK for TypeScript — wraps the public REST API.

export interface DiggerConfig {
  baseUrl: string;
  apiKey?: string;
}

export interface ScanResult {
  findings: any[];
  summary: any;
  program_id: string;
}

export interface SynthesisResult {
  program_id: string;
  total_chains: number;
  viable_chains: number;
  eliminated_chains: number;
  confirmed: number;
  report_json: any;
}

export interface ValidationReport {
  chain_id: string;
  validation_score: number;
  verdict: string;
  report_json: any;
}

export interface BenchmarkResult {
  total_cases: number;
  passed: number;
  failed: number;
  detection_rate: number;
}

export interface SearchResult {
  total: number;
  results: any[];
}

export class DiggerClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor(config: DiggerConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
  }

  private async get(path: string): Promise<any> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['X-API-Key'] = this.apiKey;
    const resp = await fetch(`${this.baseUrl}${path}`, { method: 'GET', headers });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
    return resp.json();
  }

  private async post(path: string, body: any): Promise<any> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['X-API-Key'] = this.apiKey;
    const resp = await fetch(`${this.baseUrl}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
    return resp.json();
  }

  private async del(path: string): Promise<any> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['X-API-Key'] = this.apiKey;
    const resp = await fetch(`${this.baseUrl}${path}`, { method: 'DELETE', headers });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
    return resp.json();
  }

  // System
  async health(): Promise<any> { return this.get('/api/v1/health'); }
  async version(): Promise<any> { return this.get('/api/v1/version'); }
  async metrics(): Promise<any> { return this.get('/api/v1/metrics'); }

  // Analysis
  async scan(code: string, lang: string): Promise<ScanResult> { return this.post('/api/v1/scan', { code, lang }); }
  async synthesize(code: string, lang: string): Promise<SynthesisResult> { return this.post('/api/v1/synthesize', { code, lang }); }
  async validate(chainId: string, code: string, lang: string): Promise<ValidationReport> { return this.post('/api/v1/validate', { chain_id: chainId, code, lang }); }
  async execute(code: string, lang: string): Promise<any> { return this.post('/api/v1/execute', { code, lang }); }
  async evaluate(evalType: string): Promise<any> { return this.post('/api/v1/evaluate', { eval_type: evalType }); }

  // Search
  async search(query: string, kind?: string, limit?: number): Promise<SearchResult> { return this.post('/api/v1/search', { q: query, kind, limit }); }

  // Knowledge
  async protocolPacks(): Promise<any[]> { return this.get('/api/v1/protocol-packs'); }
  async protocolPack(id: string): Promise<any> { return this.get(`/api/v1/protocol-packs/${id}`); }
  async knowledgeGraph(): Promise<any> { return this.get('/api/v1/knowledge/graph'); }

  // Organizations
  async createOrg(name: string, userId: string): Promise<any> { return this.post('/api/v1/orgs', { name, user_id: userId }); }
  async listOrgs(): Promise<any[]> { return this.get('/api/v1/orgs'); }
  async getOrg(id: string): Promise<any> { return this.get(`/api/v1/orgs/${id}`); }
  async deleteOrg(id: string): Promise<any> { return this.del(`/api/v1/orgs/${id}`); }

  // Projects
  async createProject(orgId: string, name: string, description?: string): Promise<any> { return this.post(`/api/v1/orgs/${orgId}/projects`, { name, description: description || '' }); }
  async listProjects(orgId: string): Promise<any[]> { return this.get(`/api/v1/orgs/${orgId}/projects`); }
  async getProject(id: string): Promise<any> { return this.get(`/api/v1/projects/${id}`); }

  // Scans
  async listScans(projectId: string): Promise<any[]> { return this.get(`/api/v1/projects/${projectId}/scans`); }
  async getScan(id: string): Promise<any> { return this.get(`/api/v1/scans/${id}`); }
  async compareScans(id: string, scanB: string): Promise<any> { return this.post(`/api/v1/scans/${id}/compare`, { scan_b: scanB }); }

  // Reports
  async getReport(id: string): Promise<any> { return this.get(`/api/v1/reports/${id}`); }
  async reportLineage(id: string): Promise<any[]> { return this.get(`/api/v1/reports/${id}/lineage`); }
  async diffReports(id: string, reportB: string): Promise<any> { return this.post(`/api/v1/reports/${id}/diff`, { report_b: reportB }); }

  // Artifacts
  async listArtifacts(scanId: string): Promise<any[]> { return this.get(`/api/v1/scans/${scanId}/artifacts`); }
  async getArtifact(id: string): Promise<any> { return this.get(`/api/v1/artifacts/${id}`); }

  // Benchmark
  async benchmarkStatus(): Promise<BenchmarkResult> { return this.get('/api/v1/benchmark/status'); }
  async runBenchmark(): Promise<any> { return this.post('/api/v1/benchmark/run', {}); }

  // Ingestion
  async ingestionStatus(): Promise<any> { return this.get('/api/v1/ingestion/status'); }

  // Webhooks
  async registerWebhook(orgId: string, url: string, events: string[]): Promise<any> { return this.post(`/api/v1/orgs/${orgId}/webhooks`, { url, events }); }
  async listWebhooks(orgId: string): Promise<any[]> { return this.get(`/api/v1/orgs/${orgId}/webhooks`); }
  async deleteWebhook(id: string): Promise<any> { return this.del(`/api/v1/webhooks/${id}`); }
}
