# Contributing to Digger

Thank you for contributing to Digger.

## Principles

- Prefer deterministic outputs for the same input
- Avoid timestamps and randomness in core artifacts
- No model output as a source of truth
- No hidden network calls
- No source mutation during triage
- Tests for false positives and false negatives are valuable
- Preserve limitations and missing evidence — never hide them

## Development

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

## Pull requests

- One narrow change per PR
- Include test coverage for behavioral changes
- Document limitations in the PR description
- Run format, clippy, and tests before submitting

## Issue templates

We provide templates for bug reports, false positives, false negatives, feature requests, and triage output feedback. Use the appropriate template.

## Code of conduct

Be respectful. Security researchers are building tools to protect users. Disagreements about approach should focus on evidence and tradeoffs, not personal preferences.
