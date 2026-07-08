# Digger Audit Triage Beta — Walkthrough

## 1. Build Digger

```bash
git clone https://github.com/digger-determsec/digger.git
cd digger
cargo build --release -p digger-cli
```

## 2. Run the EVM Example

```bash
./target/release/digger audit-triage --path examples/evm-basic --chain evm --json --output evm-triage.json
```

This scans `examples/evm-basic/Safe.sol` — a minimal Safe wallet contract.

## 3. Inspect the EVM Output

Open `evm-triage.json` in your editor.

Key sections to look at:

- **`function_surfaces`** — 9 functions detected with visibility, auth, mutation, and call signals
- **`privileged_operations`** — functions with onlyOwner or admin patterns
- **`missing_evidence`** — function-specific evidence gaps with source references
- **`candidate_hypotheses`** — what to investigate
- **`proof_tasks`** — specific verification steps
- **`limitations`** — what Digger cannot determine

## 4. Run the Solana Example

```bash
./target/release/digger audit-triage --path examples/solana-basic --chain solana --json --output solana-triage.json
```

This scans `examples/solana-basic/vault.rs` — a minimal Anchor vault.

## 5. Inspect the Solana Output

Key sections:

- **`function_surfaces`** — 4 instruction handlers detected
- **`account_structs`** — 4 Anchor account structs with field analysis (Signer, mut, seeds, has_one)
- **`privileged_operations`** — instructions with authority/signer patterns
- **`missing_evidence`** — instruction/account-specific evidence gaps
- **`candidate_hypotheses`** — what to investigate
- **`proof_tasks`** — CPI/account constraint verification steps

## 6. Run on Your Own Repo

```bash
./target/release/digger audit-triage --path /path/to/your/repo --chain evm --json --output my-triage.json
```

Or for Solana:

```bash
./target/release/digger audit-triage --path /path/to/your/anchor-project --chain solana --json --output my-triage.json
```

## 7. Interpret Candidate Hypotheses

Each hypothesis is a starting point, not a finding. Example:

```json
{
  "description": "Function `withdraw` has external call and state mutation signals. Verify authority, CEI ordering, and reentrancy protections.",
  "confidence": "low",
  "status": "requires_investigation"
}
```

This means: Digger detected signals worth investigating. It does not mean the function is vulnerable.

## 8. Interpret Proof Tasks

Each proof task tells you what to check next. Example:

```json
{
  "description": "Verify whether `withdraw` has appropriate modifier, require guard, role check, or caller constraint",
  "evidence_type": "source_review",
  "priority": "high",
  "status": "pending"
}
```

Use these as a checklist for manual review.

## 9. Interpret Missing Evidence

Missing evidence tells you what Digger could not determine. Example:

```json
{
  "description": "CEI ordering and reentrancy evidence missing for function `withdraw` at Safe.sol:L60-L68",
  "category": "reentrancy_cei",
  "source_ref": "Safe.sol:L60-L68"
}
```

This tells you: check CEI ordering at that specific location.

## 10. Understand Limitations

The `limitations` array in every packet lists what Digger cannot do. Key limitations:

- Text heuristics only — no AST or dataflow analysis
- No compilation or type checking
- No cross-function analysis
- No network or chain state access

## 11. Submit Feedback

Open a GitHub issue using the appropriate template:

- **Bug report** — something broken
- **False positive** — signal that is not real
- **False negative** — thing missed
- **Triage output feedback** — general feedback on usefulness
- **Feature request** — what would help

Do not paste private code, secrets, or customer materials into public issues.
