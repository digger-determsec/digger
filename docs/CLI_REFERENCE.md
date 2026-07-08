# Digger - CLI Reference

## Commands

### `digger scan`

Analyze a smart contract for security vulnerabilities.

```bash
digger scan <path> [OPTIONS]
```

**Options:**
- `--lang <language>` - Language: `solidity`, `anchor`, `rust`, `auto` (default: `auto`)
- `--json` - Output as JSON
- `--surface-json <path>` - Export SecurityIntelligenceOutput to file

**Examples:**
```bash
digger scan contract.sol
digger scan program.rs --lang anchor
digger scan contract.sol --json
digger scan contract.sol --surface-json output.json
```

---

### `digger report`

Generate a detailed triage report (JSON + Markdown).

```bash
digger report <path> [OPTIONS]
```

**Options:**
- `--lang <language>` - Language: `solidity`, `anchor`, `rust`, `auto` (default: `auto`)
- `--output-dir <path>` - Output directory (default: `.`)

**Examples:**
```bash
digger report contract.sol
digger report program.rs --output-dir ./reports
```

**Output:**
- `digger-report.json` - SecurityIntelligenceOutput
- `digger-report.md` - Human-readable Markdown report

---

### `digger hypothesis`

Derive exploit hypotheses from source.

```bash
digger hypothesis <path> [OPTIONS]
```

**Options:**
- `--lang <language>` - Language: `solidity`, `anchor`, `rust`, `auto` (default: `auto`)
- `--json` - Output as JSON
- `--output <path>` - Export HypothesisResult to file

**Examples:**
```bash
digger hypothesis contract.sol
digger hypothesis contract.sol --json
digger hypothesis contract.sol --output hypotheses.json
```

---

### `digger benchmark`

Run benchmark against corpus.

```bash
digger benchmark [OPTIONS]
```

**Options:**
- `--corpus <path>` - Path to corpus directory (default: `corpus`)
- `--json` - Output report as JSON

**Examples:**
```bash
digger benchmark
digger benchmark --corpus corpus/benchmark
digger benchmark --json
```

---

### `digger validate`

Validate Digger installation and test corpus.

```bash
digger validate
```

**Output:**
- Version check
- Schema version check
- Phase 3 freeze integrity check
- Frozen modules list
- Frozen schemas list
- Frozen hypothesis/compound/assumption/inversion/verification types

---

### `digger version`

Show version information.

```bash
digger version
```

---

## Output Formats

### SecurityIntelligenceOutput (JSON)

The canonical output format, version 2.3:

```json
{
  "version": "2.3",
  "program_id": "...",
  "attack_surface": {},
  "paths": {},
  "risk_groups": {},
  "cross_protocol": {},
  "evidence": [],
  "metadata": {}
}
```

### HypothesisResult (JSON)

```json
{
  "program_id": "...",
  "hypotheses": [],
  "summary": {}
}
```

### Benchmark Report (JSON)

```json
{
  "total_cases": 4,
  "passed": 4,
  "failed": 0,
  "detection_rate": 1.0,
  "categories": [],
  "cases": []
}
```
