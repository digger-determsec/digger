# Agent Integration Guide

> **Applies to:** v0.2.0-beta.7 (current clean beta)
> **Type:** Integration guide for agents and assistant workflows
> **Scope:** Current safe usage and proposed future integration boundaries

## Purpose

Digger is a deterministic proof and evidence layer for blockchain audit workflows. It is designed to be called by agents that need evidence-bound results — not to replace agent reasoning, but to anchor it.

- **Digger** produces and verifies evidence. It scans, detects, and validates deterministically.
- **Agents** may plan, summarize, draft, and triage. They should never override engine output.
- Digger is not a Mythos-like autonomous cyber agent. It does not execute exploits, run fuzzers, or make autonomous decisions. It is a tool that agents call and trust.

## Trust Model

| Principle | Rule |
|-----------|------|
| Engine truth | Digger output and validation gates are authoritative over LLM prose. |
| Evidence preservation | LLM summaries must preserve raw evidence. Never summarize away errors or omit fields. |
| Validation failures | If Digger validation fails, agents must not override it with reasoning. |
| Reproducibility | Evidence should be reproducible, versioned, and tied to command output. |
| Version identity | Tag, binary version, release notes, and artifacts must align. Agents should record `digger --version` with every evidence bundle. |

## Current Beta Capabilities

These features exist and are tested in v0.2.0-beta.7:

### Structural Scan

```bash
digger scan <PATH> --lang solidity|anchor|rust|auto --json
```

Produces engine-certified findings with typed severity/confidence/stage labels. Deterministic, reproducible, evidence-backed.

### Live Scan + ScanContext

```bash
digger scan-live --source-file <path> --emit-scan-context <ctx.json>
```

Produces a ScanContext JSON file that feeds into the MCP server for agent interaction.

### MCP Server (stdio, read-only)

```bash
digger_mcp <ctx.json>
```

Four read-only tools: `list_findings`, `get_evidence`, `get_explanation_context`, `validate_assistant_output`.

### Fuzz Maturity Scan (EVM)

```bash
digger fuzz-maturity --path <PATH> --chain evm [--json]
```

Static filesystem inspection. Reports whether an EVM repo has fuzzing infrastructure. Confidence ceiling: `harness/config_present` at most.

### Fuzz Evidence Artifact Parsing

```bash
digger fuzz-evidence --tool <foundry|echidna|medusa> --chain evm --artifact <PATH> [--json]
digger fuzz-evidence --tool crucible --chain solana --artifact <PATH.meta.json> [--json]
```

Parses existing fuzzer failure artifacts into structured evidence reports. All CLI-only, artifact/static parsing only. No fuzzer execution, no automatic vulnerability findings.

### Current Limitations

- **EVM maturity scan is EVM-only.** Solana fuzz maturity scanning is not implemented.
- **Crucible execution and harness generation** are not implemented.
- **MCP fuzz report exposure** is not implemented.
- **`predicate_states`** remains intentionally empty.
- **file:line spans** remain partial for op-layer and Solana classes.
- This is triage, not a full audit. Findings warrant human review.

## Installation and Version Contract

### Install

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/digger-determsec/digger/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/digger-determsec/digger/main/install.ps1 | iex

# Docker
docker compose up -d

# From source
git clone https://github.com/digger-determsec/digger.git && cd digger && cargo build --release
```

### Release Asset Names

Current release assets are `digger` (Linux x86_64 binary) and `digger-api`. Install scripts try platform-specific names first, then fall back to the generic `digger` asset.

### Version Verification

```bash
digger --version
# Expected: digger 0.2.0-beta.7
```

Agents should:
- Record the Digger version with every evidence bundle
- Reject or warn on unexpected versions if pinned to a specific release
- Include version in audit logs

## CLI Usage Contract for Agents

### Invocation Pattern

Agents should invoke Digger commands directly — spawning a subprocess, capturing stdout/stderr, and parsing the output. Digger commands are designed to be called once per invocation with deterministic results.

### Stdout/Stderr Handling

- **stdout**: Primary output (JSON when `--json` is specified, human-readable otherwise)
- **stderr**: Diagnostics, errors, warnings — never mix with primary output
- Agents must capture both streams separately

### Exit Codes

- `0`: Success
- Non-zero: Failure — inspect stderr for details
- Agents must not retry silently on failure without logging the error

### Failure Handling

- Parse stderr for error messages
- Report the exact error to the user or audit log
- Never silently swallow errors
- Never retry in a way that mutates state without explicit user action

### Raw Output Preservation

Agents must preserve raw command output before summarizing. Never summarize away fields, errors, or limitations.

## JSON/Evidence Contract

### Machine-Consumable Interfaces

All `--json` output is a machine-consumable interface. Agents should:

1. Parse the JSON exactly as returned
2. Validate expected fields before summarizing
3. Treat missing or unknown fields conservatively (assume absent means not available)
4. Never invent fields that Digger did not produce
5. Preserve raw JSON alongside any human-readable summary

### Schema Stability

Current schemas are under active development. Agents should:
- Tolerate additional fields being added in future versions
- Never depend on field ordering
- Use field names, not positional access
- Pin to a specific Digger version if schema stability is critical

### Current Beta Evidence Format

The `fuzz-evidence --json` output produces:

```json
{
  "chain": "evm" | "solana",
  "tool": "foundry" | "echidna" | "medusa" | "crucible",
  "report_type": "fuzz_evidence",
  "is_vulnerability_finding": false,
  "confidence_ceiling": "invariant_failed" | "failure_replayed",
  "invariant_name": "<string or null>",
  "test_name": "<string or null>",
  "target_path": "<string or null>",
  "counterexample": "<string or null>",
  "replay_command": "<string or null>",
  "raw_excerpt": "<string>",
  "limitations": ["<string>", ...]
}
```

- `is_vulnerability_finding` is always `false`. Fuzz evidence is for triage, not confirmation.
- `confidence_ceiling` is at most `failure_replayed`. Never `failure_minimized` or `poc_test_generated` in current beta.

## Proof Bundle Concept

> **Status:** Proposed baseline — not a runtime feature yet.

Agents may approximate a proof bundle today by preserving outputs manually. A future implementation may formalize this.

### Proposed Structure

```
proof-bundle/
  manifest.json         # Bundle metadata: Digger version, scan ID, timestamp
  commands.log          # Exact commands executed, with timestamps
  digger-version.txt    # Output of `digger --version`
  raw/                  # Unmodified command output (JSON, logs)
  normalized/           # Parsed/structured extracts if needed
  reports/              # Human-readable summaries
```

### Manifest (proposed)

```json
{
  "digger_version": "0.2.0-beta.7",
  "scan_id": "<unique-id>",
  "created_at": "<ISO-8601>",
  "commands": [
    {"command": "digger scan ...", "exit_code": 0, "output_file": "raw/scan.json"}
  ]
}
```

This is a recommendation for agent authors, not an implemented Digger feature.

## Agent Workflow Pattern

A recommended workflow for agents using Digger:

1. **Inspect** the target repository or source code
2. **Form hypothesis** about potential issues
3. **Run Digger command** (scan, fuzz-maturity, fuzz-evidence)
4. **Capture raw evidence** (stdout JSON, stderr, exit code)
5. **Validate** the JSON against expected schema
6. **Summarize** findings with evidence references — never without raw output
7. **Stop** on any validation failure — do not override with reasoning

### Example: EVM Fuzz Evidence Ingestion

```bash
# 1. Parse a Foundry failure artifact
digger fuzz-evidence --tool foundry --chain evm --artifact ./foundry_failure.txt --json > evidence.json

# 2. Agent validates expected fields
#    - report_type == "fuzz_evidence"
#    - tool == "foundry"
#    - chain == "evm"
#    - is_vulnerability_finding == false
#    - invariant_name or counterexample is non-empty

# 3. Agent summarizes with evidence reference
#    "Foundry fuzz evidence: invariant test_counter_never_negative failed
#     with counterexample. Confidence ceiling: invariant_failed.
#     This is triage evidence, not a confirmed vulnerability."
```

## Safety Boundaries

| Boundary | Rule |
|----------|------|
| No MCP exposure | Current beta has no MCP fuzz report tools. CLI-only. |
| No autonomous exploit generation | Digger does not generate, execute, or confirm exploits. |
| No hidden mutation | Digger does not modify source code, contracts, or on-chain state. |
| No fuzzer execution | Track K commands parse artifacts only. They do not run Foundry, Echidna, Medusa, or Crucible. |
| No LLM-as-proof | LLM analysis is never treated as proof. Only Digger output is authoritative. |
| No broad repo mutation | Agent integration docs do not authorize agent-side code changes. |

## Future Integration Path

These are proposed directions, not implemented features:

| Item | Status | Prerequisites |
|------|--------|---------------|
| Stable JSON schemas | Proposed | Schema versioning, field stability audit |
| Proof bundle manifest | Proposed | Schema stability, CLI output standardization |
| MCP read-only report exposure | Proposed (ADR-0039) | Stable schemas, proof bundle, evidence validation |
| Execution/evidence bridge | Future | MCP exposure, audit logging, safety model |
| Dashboard/workspace integration | Future | API stability, multi-tenant considerations |

## Checklist for Agent Authors

- [ ] Verify Digger version (`digger --version`)
- [ ] Record the exact command executed
- [ ] Capture raw stdout and stderr separately
- [ ] Parse and validate JSON output before summarizing
- [ ] Preserve all raw outputs in audit trail
- [ ] Cite specific evidence fields in summaries
- [ ] Never override a Digger validation failure with agent reasoning
- [ ] Never claim Digger confirmed a vulnerability — it provides evidence for triage
- [ ] Never execute fuzzers or mutate state without explicit user action
