# RUSTSEC-2026-0192: ttf-parser Unmaintained

> **Status:** Acknowledged — temporary cargo-audit ignore
> **Date:** 2026-06-30

## Advisory

- **ID:** RUSTSEC-2026-0192
- **Package:** `ttf-parser` (also known as `tff-parser` in RustSec)
- **Version:** 0.25.1
- **Severity:** Unmaintained (not RCE, not memory safety)
- **URL:** https://rustsec.org/advisories/RUSTSEC-2026-0192

## Dependency Path

```
ttf-parser v0.25.1
└── lopdf v0.42.0
    └── pdf-extract v0.12.0
        └── digger-knowledge v0.2.0-beta.6
            ├── digger-api
            ├── digger-cli
            └── digger-ingestion
```

`ttf-parser` is a transitive dependency through the PDF extraction stack (`lopdf` → `pdf-extract` → `digger-knowledge`). It handles TrueType font parsing within PDF files.

## Risk Assessment

- **Advisory type:** Unmaintained — not a memory safety or RCE issue
- **Reachability in Digger:** Only reachable through PDF text extraction in `digger-knowledge`. Digger's security-critical path (detectors, graph analysis, hypothesis engine) does not call PDF extraction at runtime.
- **Actual risk:** Low. The unmaintained status means no future security patches for `ttf-parser`, but no known exploitable vulnerability exists today.

## Chosen Fix

Temporary cargo-audit ignore added to CI workflow. This follows the existing pattern (RUSTSEC-2025-0134 is already ignored). A documentation note records the advisory, dependency path, and risk.

**Rationale:**
- Advisory is "unmaintained," not RCE or memory safety
- Dependency is transitive and not in the security-critical path
- No immediate replacement exists without replacing the entire PDF stack
- Temporary ignore is the standard Rust ecosystem response for unmaintained transitive dependencies

## Follow-Up Conditions

The ignore should be revisited when:
- A newer `lopdf` or `pdf-extract` version drops `ttf-parser`
- Digger's PDF extraction needs change
- A direct vulnerability (not just unmaintained) is reported
