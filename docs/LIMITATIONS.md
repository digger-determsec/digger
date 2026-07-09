# Beta Limitations

Digger is a triage / first-pass tool, not a replacement for a professional manual audit.

## Detection scope

- **Single-contract scope** — no cross-function or cross-contract dataflow analysis yet
- **Flash-loan governance detector** unverified on real-world targets
- **EVM modifier detection** may miss complex multi-line patterns
- **Solana detection** is constraint-absence based (3 axes only: ownership, authority-binding, signing)
- **No compilation or type checking** of target code

## LLM layer

- The LLM-assisted layer is a **schema/policy baseline** in this release
- Live model calls are quarantined behind validation — see [LLM-ASSISTED-BETA-BOUNDARY.md](product/LLM-ASSISTED-BETA-BOUNDARY.md)

## Technical boundaries

- The Rust SDK (`sdk/rust`) is a **separate trust boundary** — an HTTP client for a Digger API server, not a local scanner; it does not pass through the CLI egress gate.
- On Windows, the trust store (`~/.digger/trust.json`) inherits default file ACLs (the 0600 chmod is Unix-only). The trust store contains only scheme+host pairs — no secrets, API keys, or full URLs.

## What Digger does not do

- No autonomous verdicts or exploit execution
- No model-generated findings
- No `decide_valid_finding` shortcut
- No guarantee that a repository is safe
- No hidden network calls (all egress consent-gated)
