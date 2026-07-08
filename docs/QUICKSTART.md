# Quickstart

Get Digger audit triage running in under 5 minutes.

## Build

```bash
git clone https://github.com/digger-determsec/digger.git
cd digger
cargo build --release
```

## Run

```bash
# EVM triage
./target/release/digger audit-triage --path examples/evm-basic --chain evm --json --output triage.json

# Solana triage
./target/release/digger audit-triage --path examples/solana-basic --chain solana --json --output triage.json
```

## Read the output

```bash
cat triage.json | python3 -m json.tool
```

## What to look for

1. **`limitations`** — what Digger could not determine
2. **`missing_evidence`** — evidence that would strengthen claims
3. **`candidate_hypotheses`** — potential issues worth investigating
4. **`proof_tasks`** — what to verify and how
5. **`is_finding`** — always `false` in the triage packet

## Next steps

- Point Digger at your own repository
- Review the audit triage packet
- Use the proof tasks as a checklist for manual review
- Report false positives or missing detections via GitHub Issues
