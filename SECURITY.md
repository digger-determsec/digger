# Security Policy

## Reporting vulnerabilities

Report security issues privately via email. Do not include private customer repositories in public issues.

## What Digger is

Digger is an audit triage tool, not a guarantee of safety. Findings require human validation. Digger prepares evidence — it does not deliver verdicts.

## What to never include in reports

- Private keys, wallet seeds, or mnemonics
- API keys or tokens
- Customer names or private audit outputs
- Internal URLs or infrastructure details
- Real secrets from any repository

## Scope

This policy covers the open-source Digger CLI. Hosted or commercial products have separate security procedures.

## Advisory ignores

Two RustSec advisories are acknowledged and ignored in `cargo audit`:

- **RUSTSEC-2025-0134**: Transitive dependency advisory. Does not affect Digger's attack surface — the affected crate is used only in offline knowledge ingestion (fetch-once at build time), not in the audit-triage path.
- **RUSTSEC-2026-0192**: `ttf-parser` (unmaintained). Used only in offline report rendering; no network-facing code path. Will be replaced when upstream provides an alternative.
