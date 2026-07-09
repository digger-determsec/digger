# Intent Verifier

The intent verifier decodes transaction data and explains what it does in plain English, then flags it as Safe, Suspicious, or Dangerous.

## What it decodes

- **Raw calldata** (EVM): `--calldata 0x...` — function selector + argument decoding
- **JSON transactions** (EVM): `--tx path/to/tx.json`
- **EIP-712 typed data** (EVM): `--eip712 path/to/eip712.json`
- **Solana transactions**: `--sol-tx <base64-or-json>`

## Risk levels

| Level | Meaning |
|-------|---------|
| Safe | Known function selector, no risk signals detected |
| Suspicious | Unknown selector, or known dangerous function without matching expected target |
| Dangerous | Known high-risk function (e.g., upgrade, mint, pause) with no guardrails |

## Example

```bash
digger explain-intent --calldata 0x2e1a7d4d
```

Output:
```
Digger Intent Verifier — v0.4.0-beta.2
Chain: evm
Risk: Safe

[0x2e1a7d4d] unknown
  Effect: Unknown selector 0x2e1a7d4d. No argument data.

Decoded 1 call(s). 0 with risk signals. Overall risk: Safe.

is_finding: false
```

## Flags

| Flag | Purpose |
|------|---------|
| `--to <address>` | Target contract for mismatch detection |
| `--expected <address>` | Address the UI claims to target |
| `--json` | Machine-readable output |
| `--chain evm\|solana` | Target chain (default: evm) |

## How it works

1. Parse the transaction payload into structured calls
2. Match each function selector against a curated table of known functions
3. For known functions, assess risk based on the function's action class
4. Flag mismatches between `--to` and `--expected` addresses
5. Report `is_finding: false` — this is a decoded explanation, not a security finding
