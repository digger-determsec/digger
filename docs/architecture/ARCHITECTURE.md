# Architecture

A Rust workspace of focused crates:

| Crate | Purpose |
|-------|---------|
| `digger-cli` | Command-line interface and all user commands |
| `digger-graph` | Function/instruction-level surface mapping, state access analysis |
| `digger-hypothesis` | Ranked hypothesis derivation with confidence tiers |
| `digger-reconstruct` | EVM bytecode decompilation + live source fetch from explorers |
| `digger-intent-verifier` | Transaction/calldata intent decoding (EVM + Solana) |
| `digger-report` | Deterministic Markdown report generator with PoC scaffolds |
| `digger-egress` | Network consent gate (trust store, `--no-network` enforcement) |
| `digger-agent-mcp` | MCP server for AI agent integration |
| `digger-evidence` | Evidence bundle schema and validation |
| `digger-ingestion` | Corpus ingestion pipeline |
| `sdk/rust` | Rust SDK (separate trust boundary — API client, not local scanner) |

## Evidence-gated pipeline

Digger's core is a deterministic pipeline where every output is evidence-grounded:

1. Parse source code (Solidity / Anchor-Rust / bytecode)
2. Build function-level surfaces and state dependency graphs
3. Run detectors against surfaces
4. Derive hypotheses from detector results
5. Rank by severity and confidence
6. Render human-readable reports with evidence chains

No model output enters this pipeline. The LLM-assisted layer (see [LLM-ASSISTED-BETA-BOUNDARY.md](product/LLM-ASSISTED-BETA-BOUNDARY.md)) is a separate, quarantined interface.

## Open-core model

The engine — detectors, evidence pipeline, report generator, intent verifier, CLI, SDKs, MCP server — is open source. A hosted API, deeper LLM-assisted explanations, and enterprise integrations build on top.
