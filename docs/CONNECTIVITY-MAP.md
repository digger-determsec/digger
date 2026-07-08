# Connectivity Map

> **Date:** 2026-07-01
> **Status:** Classification only — no deletions

## Entry Points

- `digger-cli` (binary) — the CLI entry point for all product surfaces
- `digger-server` (binary) — HTTP API for scan results
- `digger-api` (binary) — HTTP API with auth

## Direct CLI Dependencies (reachable from `digger audit-triage`)

digger-repo-intelligence, digger-fuzz-maturity, digger-agent-hypothesis, digger-agent-proof-task, digger-agent-audit-log, digger-agent-evidence-run, digger-agent-report-draft, digger-pipeline, digger-hypothesis, digger-parser, digger-graph, digger-surface, digger-synthesis, digger-reconstruct, digger-knowledge, digger-core

## Orphan Classification

| Crate | Reachable? | Depended on by kept crate? | Standalone tool? | Active docs/CI? | Classification | Justification |
|-------|-----------|---------------------------|-----------------|----------------|----------------|---------------|
| digger-flow | No | No | No | No | REMOVE | Zero dependents, disconnected from pipeline |
| digger-accuracy | No | No | No | No | REMOVE | Zero dependents, evaluation-only metric |
| digger-miss-analysis | No | No | No | No | REMOVE | Zero dependents, analysis-only |
| digger-agent-mcp | Yes (CLI) | Yes (cli) | No | Partial | PROMOTE | Wired to CLI, MCP boundary doc exists |
| digger-explanation | Yes (CLI) | Yes (cli) | No | Partial | PROMOTE | Wired to CLI report surface |
| digger-investigation | Yes (pipeline) | Yes (pipeline) | No | No | PROMOTE | Used by pipeline for investigation |
| digger-research-graph | Yes (pipeline) | Yes (pipeline) | No | No | WIRE | Used by pipeline, may need public CLI surface |
| digger-research-context | Yes (pipeline) | Yes (pipeline) | No | No | WIRE | Used by pipeline, may need public CLI surface |
| digger-protocol-model | Yes (pipeline) | Yes (pipeline) | No | No | PROMOTE | Used by pipeline and Gen2 |
| digger-systemir-bridge | Yes (pipeline) | Yes (pipeline) | No | No | PROMOTE | Used by Gen5 bridge |
| digger-semantic | Yes (surface) | Yes (surface) | No | No | WIRE | Used by surface layer, may need CLI surface |

## Summary

- **REMOVE** (3): digger-flow, digger-accuracy, digger-miss-analysis
- **PROMOTE** (5): digger-agent-mcp, digger-explanation, digger-investigation, digger-protocol-model, digger-systemir-bridge
- **WIRE** (3): digger-research-graph, digger-research-context, digger-semantic

**Action required:** Actual removals are a separate reviewed PR. This document classifies only.
