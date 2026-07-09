# Digger

**Evidence-gated security analysis for smart contracts and the agents that touch them.**

> Digger surfaces *hypotheses*, not "guaranteed vulnerabilities." Every finding is tied to concrete evidence — an exact line, call path, or storage slot — and cites real, verifiable precedents. When it doesn't know, it says so.

[![CI](https://github.com/digger-determsec/digger/actions/workflows/ci.yml/badge.svg)](https://github.com/digger-determsec/digger/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Beta](https://img.shields.io/badge/status-beta-orange)]()

`EVM + Solana` · `2270 tests passing` · Rust

---

## Quickstart

```bash
# Build (one-time)
git clone https://github.com/digger-determsec/digger.git
cd digger && cargo build --release

# Scan a bundled sample contract
./target/release/digger audit-triage --path examples/evm-basic --chain evm

# Render a beginner-friendly report from the bundled sample
./target/release/digger render-report --from examples/sample-report/sample_packet.json
```

The second command produces a Markdown report with: what each finding is, why it matters, the exact code location, severity, similar known incidents, and a proof-of-concept scaffold. See the [sample output](examples/sample-report/) for the full result.

## What you can do

- **Scan local contracts** — `audit-triage --path ./src --chain evm` (or `solana`)
- **Scan a live on-chain address** — `scan-live --address 0x... --chain ethereum` (asks permission first; `--no-network` stays fully offline)
- **Verify a transaction** — `explain-intent --calldata 0x...` tells you what a transaction does before you sign
- **Run as an MCP tool** — Digger exposes scanning and intent-verification for AI agents ([docs/CONNECT-YOUR-AGENT.md](docs/CONNECT-YOUR-AGENT.md))

## Learn more

| Topic | Where |
|-------|-------|
| Architecture & pillars | [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) |
| How Digger differs from AI auditors | [docs/WHY-DIGGER.md](docs/WHY-DIGGER.md) |
| Intent verifier deep-dive | [docs/INTENT-VERIFIER.md](docs/INTENT-VERIFIER.md) |
| Deterministic report generator | [docs/REPORT-GENERATOR.md](docs/REPORT-GENERATOR.md) |
| Egress consent gate | [docs/EGRESS-GATE.md](docs/EGRESS-GATE.md) |
| CLI reference | [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) |
| LLM boundary (beta) | [docs/product/LLM-ASSISTED-BETA-BOUNDARY.md](docs/product/LLM-ASSISTED-BETA-BOUNDARY.md) |
| Beta limitations | [docs/LIMITATIONS.md](docs/LIMITATIONS.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security | [SECURITY.md](SECURITY.md) |

## Beta limitations

Digger is a triage tool, not a replacement for a professional audit.
- Single-contract scope (no cross-contract dataflow yet)
- Flash-loan governance detector unverified on real targets
- EVM modifier detection may miss complex multi-line patterns
- LLM layer is a schema/policy baseline only

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the full list.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Disclaimer

Digger is beta software that surfaces hypotheses for human review. It is NOT a substitute for a professional security audit and gives no guarantee that a contract is safe.
