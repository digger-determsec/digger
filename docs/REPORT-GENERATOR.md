# Deterministic Report Generator

The `render-report` command produces a beginner-friendly Markdown report from an AuditTriagePacket JSON.

## Pipeline

```
audit-triage --json --output triage.json
    → render-report --from triage.json
    → Markdown report with sections per finding
```

## Report sections (per finding)

1. **Title** — vulnerability class + component name + file:line
2. **Summary** — what the finding is (curated per-rule text)
3. **Why it matters** — impact explanation (curated per-rule text)
4. **Location & Code** — file path, line range, code excerpt
5. **Evidence path** — what the detector observed in the code
6. **Severity & Confidence** — from the ranking engine
7. **Similar known issues** — precedent citations with verifiable links
8. **How to fix** — remediation guidance (curated per-rule text)
9. **Proof-of-concept scaffold** — deterministic test template with disclaimer

## What makes it honest

- All prose is curated per-rule content or real engine evidence — never fabricated
- Every sentence is either (a) written once per detector class, or (b) from the actual finding data
- PoC scaffolds are explicitly marked as unverified drafts
- Precedent citations link to real, verifiable incident reports

## Commands

```bash
# From audit-triage output
digger render-report --from triage.json

# From bundled sample (no scan needed)
digger render-report --from examples/sample-report/sample_packet.json

# With filtering
digger render-report --from triage.json --top 5 --min-confidence confirmed

# Output to file
digger render-report --from triage.json -o report.md
```
