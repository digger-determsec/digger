# Connect Your Agent

> **Status:** Self-hosted beta
> **Date:** 2026-07-01

## Overview

Connect your AI agent to Digger over MCP or REST. Digger is self-hosted — all processing happens locally on your machine. No cloud, no SaaS, no data leaves your environment.

**Digger is the evidence layer. Your agent proposes. Digger validates.**

## Quick Start

### 1. Start Digger API server

```bash
export DIGGER_API_KEY="your-secret-key"
cargo run --release -p digger-api
```

The server listens on `127.0.0.1:3000`.

### 2. Generate an API key

```bash
curl -X POST http://127.0.0.1:3000/api/v1/keys \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{"name": "my-agent", "org_id": "default"}'
```

Response:
```json
{
  "key": "abcdef01.restofsecretkey",
  "id": "uuid-here",
  "prefix": "abcdef01",
  "message": "Store this key securely. It will not be shown again."
}
```

**Store the key securely. It is shown only once.** The prefix is the first 8 hex characters of the generated secret. The full key format is `prefix.secret` (e.g., `abcdef01.restofsecretkey`).

### 3. Connect via MCP (stdio)

The MCP server loads a ScanContext from a JSON file (passed as argument or via `DIGGER_SCAN_CONTEXT` env var). It is NOT live-connected to the API server — the context file must be generated first.

```json
{
  "mcpServers": {
    "digger": {
      "command": "digger_mcp",
      "args": ["path/to/scan-context.json"],
      "env": {
        "DIGGER_MCP_KEY": "abcdef01.restofsecretkey",
        "DIGGER_API_KEY": "your-bootstrap-admin-secret"
      }
    }
  }
}
```

- `DIGGER_MCP_KEY` = the API key presented by the connecting agent/client
- `DIGGER_API_KEY` = the separate bootstrap/admin secret for local development

### 4. Connect via REST

```bash
# List findings
curl http://127.0.0.1:3000/api/v1/finding/scan-1 \
  -H "X-API-Key: abcdef01.restofsecretkey"

# Validate agent output
curl -X POST http://127.0.0.1:3000/api/v1/validate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: abcdef01.restofsecretkey" \
  -d '{"claims": [...]}'
```

## What Your Agent Can Do

| MCP Tool | What It Does | Read-Only |
|----------|-------------|-----------|
| `list_findings` | List all findings from a scan | Yes |
| `get_evidence` | Get evidence bundle for a finding | Yes |
| `get_explanation_context` | Build explanation ingredients | Yes |
| `validate_assistant_output` | Validate claims against engine truth | Yes |

All tools are read-only. Digger never executes anything.

## The Boxing

Digger enforces strict boundaries:

1. **Agents propose. Digger proves.** Model output goes through `validate_assistant_output` before any downstream use.
2. **No finding promotion.** `decide_valid_finding` is forbidden. Model output cannot become a finding.
3. **Evidence is mandatory.** Every claim must be backed by engine-derived evidence.
4. **is_finding: false.** All outputs maintain this invariant.

## Self-Hosted Deployment

```bash
# Build
cargo build --release

# Run API server
export DIGGER_API_KEY="your-admin-key"
./target/release/digger-api

# Run MCP server (stdio)
./target/release/digger_mcp
```

Digger runs entirely on your machine. No cloud, no SaaS, no hosted deployment in this beta.

## Key Management

- Generate keys via `POST /api/v1/keys`
- List keys via `GET /api/v1/keys`
- Revoke keys via `DELETE /api/v1/orgs/:org_id/keys/:key_id`
- Keys are stored as sha256 hashes — plaintext is never persisted
- Each key belongs to an org/project

## Security

- API keys are hashed (sha256) at rest
- Constant-time comparison prevents timing attacks
- Revoked keys are rejected
- Bootstrap key (DIGGER_API_KEY) is only for admin use
- No plaintext keys stored or logged

See [SECURITY.md](SECURITY.md) for the full security policy.
