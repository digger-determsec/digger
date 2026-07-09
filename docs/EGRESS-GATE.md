# Egress Consent Gate

All network access from Digger is gated behind explicit user consent. This is the core network safety mechanism.

## How it works

1. Before any HTTP request, Digger calls `authorize_global(url, purpose)`
2. The gate checks: offline mode → trust store → interactive prompt (TTY) → deny
3. Trust store (`~/.digger/trust.json`) persists only `SCHEME://HOST` pairs, never full URLs or API keys
4. File mode 0600 on Unix; documented limitation on Windows

## Global flags

| Flag | Effect |
|------|--------|
| `--no-network` | Hard offline mode — zero network calls, fail-closed |
| `--allow-egress <host>` | Permit egress to a specific host (repeatable) |
| `--assume-yes` | Auto-approve consent prompts (CI / non-interactive) |

## Where the gate fires

Every HTTP call goes through `authorize_global()` before the request:

- `explorer.rs` — Etherscan API calls for EVM source fetch
- `solana_rpc.rs` — Solana RPC calls for program fetch
- `txwatch/lib.rs` — transaction watch polling
- `scan_live.rs` — git clone subprocess calls
- `fetcher.rs` — ingestion subprocess calls (git clone, gh api)

## What is stored

The trust store at `~/.digger/trust.json` contains only:
```json
{
  "HTTPS://API.ETHERSCAN.IO": ["fetch-contract-source"]
}
```

No API keys, no full URLs, no secrets. The store is purely a consent record.
