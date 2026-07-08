---
name: digger
description: Evidence-gated blockchain security triage engine for Solana, EVM, and operational-layer (TS/Node) smart contracts. Returns engine-certified findings with typed severity/confidence/stage labels and function-symbol provenance — AI can suspect, Digger proves. Use when auditing smart contracts, triaging security findings, validating vulnerability claims, or investigating on-chain code for access-control, CPI, oracle, bootstrap, and failover bug classes.
user-invocable: true
license: MIT
compatibility: Rust toolchain (cargo), Solana CLI optional, Node.js 18+ optional for op-layer fixtures
metadata:
  author: digger-determsec
  version: 0.2.0-beta.1
---

# DIGGER — Blockchain Security Agent Skill

DIGGER is an evidence-gated, AI-assisted blockchain security triage tool for Solana, EVM smart contracts, and operational-layer (TS/Node) handler code. It produces engine-certified findings backed by structural analysis — AI can suspect, Digger proves. Models may help propose hypotheses, rank surfaces, explain evidence, suggest invariants, or draft report text, but all outputs are evidence-gated through proof tasks and audit logs.

## How it works

1. **Scan**: Run `digger scan-live --source-file <path> --emit-scan-context <ctx.json>` to produce a typed scan context from real engine analysis.
2. **Serve**: Run `digger_mcp <ctx.json>` to launch a local stdio JSON-RPC 2.0 server.
3. **Call tools**: Send newline-delimited JSON-RPC requests to stdin; read responses from stdout.

## Tools (read-only)

| Tool | Purpose |
|------|---------|
| `list_findings` | List all findings in a scan with typed labels (severity, confidence, stage). Input: `{scan_id}`. |
| `get_evidence` | Get evidence bundles for a specific finding. Input: `{finding_id}`. |
| `get_explanation_context` | Get explanation ingredients for a finding (precedents, attack shape, remediation). Input: `{finding_id}`. |
| `validate_assistant_output` | Deterministically validate structured claims against engine truth. Input: `{scan_id, claimed_findings, prose?}`. |

All four tools are read-only (`readOnlyHint: true`).

## What the engine emits

Findings carry typed severity (info/low/medium/high/critical), confidence (experimental/graduated), and stage (shadow/advisory/armed) enums — never strings. Evidence IDs are populated from detector provenance and survive the MCP `list_findings` round-trip. File:line spans may be partial for op-layer/Solana classes; location data provides function-symbol references with provenance-level evidence IDs.

## Capabilities (honest)

**Graduated confidence (production-ready):**
- EVM: price oracle manipulation, readonly reentrancy
- Solana: access control bypass, unvalidated CPI, type cosplay, unchecked account owner

**Experimental confidence (structural observation, not a full audit):**
- Operational-layer (TS/Node): unverified attestation, control-plane routing authority, fail-open bootstrap, silent failover
- These detectors use syntactic proxy analysis — they match structural patterns in handler source code, not runtime behavior

- Validate tool catches promotion attempts (severity/confidence/stage/finding injection)
- Local stdio MCP entrypoint runs with no network and no auth; hosted HTTP `/scan` endpoint requires `X-Digger-Api-Key` header (fail-closed by default; open only via explicit `DIGGER_ALLOW_OPEN=true`).

## Limitations

- File:line spans remain partial for op-layer and Solana classes; evidence is provenance-level, not full source-span proof.
- `predicate_states` remains intentionally empty until a production predicate registry exists.
- Recall varies by detector and class (see project README for per-class fractions).
- **This is triage, not a full audit.** Findings are structural observations that warrant human review, not confirmed vulnerabilities.
- Operational-layer detectors are **experimental**: they analyze handler-level patterns via syntactic proxies, not full type inference or control-flow analysis. Cross-function data flows, middleware-gated verification, and async patterns may not be captured.
- The validate tool compares claims against engine-emitted findings only — it cannot assess novel attack vectors or logic not present in the scanned source.

## Track K — Fuzzing maturity and evidence (CLI-only, beta)

These are static-repo CLI commands — they do NOT run fuzzers and do NOT emit vulnerability findings.

**EVM fuzz maturity scan** (static filesystem inspection):
```
digger fuzz-maturity --path <PATH> --chain evm [--json]
```
Reports whether an EVM repo has real invariant-fuzzing infrastructure. Confidence ceiling caps at `harness/config_present`. This is a maturity signal, not proof of a bug.

**Foundry/Echidna/Medusa fuzz evidence ingestion** (artifact parsing only, EVM):
```
digger fuzz-evidence --tool foundry|echidna|medusa --chain evm --artifact <PATH> [--json]
```
Parses existing Foundry, Echidna, or Medusa invariant/property failure output into a structured evidence report. Confidence ceiling is `invariant_failed` (no replay command) or `failure_replayed` (replay command present). This is evidence for triage, not a confirmed vulnerability.

**Crucible fuzz evidence ingestion** (artifact parsing only, Solana):
```
digger fuzz-evidence --tool crucible --chain solana --artifact <PATH.meta.json> [--json]
```
Parses existing Crucible crash metadata (`.meta.json`) into a structured evidence report. Extracts test name, action sequence, params, error codes, and seed. Confidence ceiling is `invariant_failed` unless a replay command is present. This is evidence for triage, not a confirmed vulnerability. Digger does NOT run Crucible or generate harnesses.

All tool parsers are CLI-only for now; they are not exposed through the MCP server. Crucible execution and harness generation remain future work.

## Known operational-layer limitations (experimental detectors)

The four op-layer detectors use pattern-matching over handler source code:
- `op_unverified_attestation` — fires on ValueFeed reads without verification checks
- `op_control_plane_authority` — fires on RoutingConfig reads to sinks without allowlist guards
- `op_fail_open_bootstrap` — fires on safety-gate predicates that default to permissive returns
- `op_silent_failover` — fires on fallback-to-source patterns without threshold adjustment

These are structural heuristics, not formal verification. A handler that passes all four checks may still have runtime vulnerabilities; a handler that fails one may be safe in context not visible to the parser. Treat findings as leads for expert review.

## Single-tenant deployment note

This skill runs a single-tenant local server. There is no multi-tenant isolation between scan requests — all scans share the same engine instance and output directory. When used via the Agent Skills catalog, the server is expected to run in an isolated container per user. Do not deploy this skill to a shared server without external authentication (the server supports `DIGGER_API_KEY` env var for request gating).

## Agentic boundary

The LLM/assistant may explain, summarize, draft, and triage using engine, MCP, or CLI outputs. The engine decides verdicts; the assistant never does. `validate_assistant_output` is the deterministic guardrail that catches assistant claims inconsistent with engine truth. Digger is a proof-aware engine with an agentic interface — not an AI auditor.

## Version

Original beta RC was `v0.1.0-rc.1` at tag `649e4e6`. This package is prepared for `v0.2.0-beta.1` after Track J/K/M/P hardening.
