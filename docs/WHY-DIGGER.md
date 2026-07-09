# Why Digger is different

The market is filling with AI auditors that produce confident, impressive reports full of findings that don't exist — fabricated severities, invented CVEs, hallucinated precedents. In security that's worse than useless: a false positive burns expensive expert time; a false negative drains a protocol.

Digger is built to be architecturally incapable of that:

1. **Hypotheses, not verdicts.** Findings are ranked hypotheses with explicit confidence — never "confirmed vulnerabilities."
2. **Evidence-gated.** No claim ships without a concrete evidence chain (line / call path / storage slot). No evidence, no claim.
3. **Deterministic core.** Same input → same output, every run. The core reasoning is not an LLM; there is no randomness in what it reports.
4. **Real precedents only.** Similar known incidents are cited with verifiable links (Parity, Poly Network, Wormhole, …) — never invented.
5. **Honest about limits.** Known gaps are documented in plain sight.

## What Digger does

1. **Multi-surface scanning.** Local source (Solidity / Anchor-Rust), a GitHub repo, or a live on-chain address (EVM & Solana; verified source or bytecode fallback).
2. **Evidence-gated hypotheses + deterministic reports.** Runs detectors, ranks hypotheses by severity/confidence, and renders a clean, beginner-readable report: location, evidence, similar known incidents, remediation, and a proof-of-concept scaffold.
3. **Transaction intent verification — "know before you sign."** Decode raw calldata, a transaction, an EIP-712 payload, or a Solana transaction into plain English, checked against what you expected.
4. **The agentic layer (MCP).** Digger runs as an MCP server, exposing scanning and intent-verification as tools any AI agent can call. As autonomous agents begin signing transactions and deploying contracts, Digger is the honest, deterministic security gate they call *before* acting — it won't make something up the way an LLM would.
5. **Security-first by design.** All network egress is gated behind explicit consent; Digger runs fully offline with `--no-network`. Its local trust store holds only scheme+host pairs — never secrets or full URLs.

## How it works

```
contract / address / repo / calldata
    → detectors → evidence → ranked hypotheses
    → triage (JSON) → render-report → human-readable report (Markdown)
```

Every stage is inspectable, deterministic, and evidence-gated.
