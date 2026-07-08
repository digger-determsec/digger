# DIGGER Blockchain Security Agent Skill

A local, evidence-gated, AI-assisted blockchain security triage tool for Solana and EVM smart contracts.

## What it does

DIGGER analyzes smart contract source code using structural analysis and produces engine-certified findings. The deterministic engine handles detection, evidence, and audit trails. AI/LLM assistance is available for hypothesis proposal, surface ranking, evidence explanation, and report drafting — all evidence-gated. Every finding carries typed labels (severity, confidence, stage) from the engine, and the guardrail validator catches any attempt to promote or fabricate results. Recall on real exploits is honest: 2/4 validated classes (access-control, reentrancy).

## Installation

Requires the `digger` CLI and `digger_mcp` binary built from this repository:

```bash
cargo build --release
# Binaries: target/release/digger, target/release/digger_mcp
```

## Quick start

```bash
# 1. Emit a scan context from a Solidity or Anchor source file
digger scan-live --source-file contract.sol --emit-scan-context ctx.json

# 2. Launch the MCP stdio server
digger_mcp ctx.json
# Then send JSON-RPC requests to stdin, read responses from stdout.
```

Or run the automated smoke test:

```bash
bash skills/digger/scripts/quickstart.sh
```

## Available tools

All tools are read-only (`readOnlyHint: true`):

| Tool | Description |
|------|-------------|
| `list_findings` | List all findings with typed severity/confidence/stage labels |
| `get_evidence` | Get evidence bundles for a specific finding |
| `get_explanation_context` | Get explanation ingredients (precedents, attack shape, remediation) |
| `validate_assistant_output` | Validate structured claims against engine truth |

## What the engine produces

Findings are structurally typed — severity is an enum (info/low/medium/high/critical), confidence is (experimental/graduated), stage is (shadow/advisory/armed). The engine never up-labels. The guardrail validator returns a deterministic failure report for assistant claims that promote severity, confidence, or stage beyond engine truth.

## Known limitations

- **Location scope**: Findings carry function-symbol references with provenance-level evidence IDs. File/line spans remain partial for op-layer and Solana classes.
- **Evidence wiring**: Evidence IDs are populated from detector provenance and survive the MCP `list_findings` round-trip. `predicate_states` remains intentionally empty until a production predicate registry exists.
- **Recall varies**: Per-class recall fractions are in the project README. This is triage, not a full audit.
- **No network**: Everything runs locally. No API keys, no hosted endpoints, no data leaves your machine.

## Architecture

```
Source Code → Parser → SystemIR → Detectors → Engine Truth → ScanContext → digger_mcp → Agent
```

The engine decides verdicts. The agent layer reads and validates; it never decides.
