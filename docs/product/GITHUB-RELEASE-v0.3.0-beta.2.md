# v0.3.0-beta.2 — Digger Audit Triage Beta

## What is Digger?

Local-first, evidence-gated audit triage for EVM and Solana security researchers.

Digger is deterministic at the evidence layer and agentic/LLM-assisted by design. It maps functions, instructions, privileged operations, state mutation signals, external calls/CPI, fuzz maturity, candidate hypotheses, proof tasks, and missing evidence.

**AI can suspect. Digger proves.**

## Why beta.2

`v0.3.0-beta.2` supersedes `v0.3.0-beta.1` for public beta launch. It includes corrected architecture documentation that accurately frames Digger as evidence-gated AI-assisted blockchain security infrastructure. The tag `v0.3.0-beta.1` was not moved — `v0.3.0-beta.2` is the corrected public beta release point.

## Quickstart

```bash
cargo build --release -p digger-cli

# EVM triage
./target/release/digger audit-triage --path examples/evm-basic --chain evm --json --output triage.json

# Solana triage
./target/release/digger audit-triage --path examples/solana-basic --chain solana --json --output triage.json
```

## What works

- EVM function-level triage (9 surfaces in example)
- Solana instruction/account-level triage (4 instructions, 4 account structs)
- Privileged operation detection with auth signals
- State mutation and external call/CPI signal detection
- Evidence-specific missing evidence with source references
- Candidate hypotheses and proof tasks
- Fuzz maturity scanning
- JSON AuditTriagePacket output
- Human summary mode
- Runs without any model (provider `none`)

## Agentic architecture

Models may assist with hypotheses, ranking, explanation, invariants, and report drafting. Model output is untrusted until grounded. `decide_valid_finding` is forbidden. No model-to-finding shortcut exists.

The LLM-assisted layer is schema/policy baseline in this beta — defined as model provider abstraction, LLM firewall, customer data boundary, model-call audit, and model evaluation harness. These are not live provider runtimes yet.

See [LLM-ASSISTED-BETA-BOUNDARY.md](docs/product/LLM-ASSISTED-BETA-BOUNDARY.md) for the full architecture boundary.

## What Digger does not do

- No final vulnerability findings
- No model-to-finding shortcut
- No fuzzer execution
- No exploit execution
- No source mutation
- No hidden network calls
- No compilation or execution of target code
- Live provider calls are schema/policy baseline, not beta runtime

## Known limitations

- Heuristic text scanning only (no AST/dataflow)
- EVM modifier detection may miss complex patterns
- Solana CPI detection is pattern-based
- No cross-function analysis
- LLM-assisted layer is schema/policy baseline in this beta
- Audit triage is not a complete audit

## Feedback

Open an issue: https://github.com/digger-determsec/digger/issues

We want: false positives, false negatives, noisy signals, missed surfaces, proof task quality, model-assisted workflow feedback, whether you'd use this at the start of an audit.
