# LLM-Assisted Beta Boundary

> **Date:** 2026-06-30
> **Status:** Architecture boundary document for public beta

## Core Principle

**AI can suspect. Digger proves.**

Digger is evidence-gated, AI-assisted blockchain security infrastructure. The deterministic engine is the source of truth. Models are replaceable accelerators.

## What the Agentic / LLM-Assisted Layer Is

Digger's architecture has two layers:

1. **Deterministic evidence layer** — parses source code, constructs graphs, runs detectors, produces evidence packets. This layer works with provider `none` (no model required).

2. **Agentic / LLM-assisted layer** — models may propose hypotheses, rank attack surfaces, explain evidence, suggest invariants, suggest fuzz/proof tasks, and draft report text. Model outputs are untrusted until grounded through the evidence layer.

The agentic layer is model-agnostic. It works with OpenAI, Anthropic, Gemini, Ollama, vLLM, enterprise VPC-hosted models, or no model at all.

## What Is Implemented in Current Beta (v0.3.0-beta.1)

- `digger audit-triage` CLI — deterministic packet generation
- Function/instruction-level source triage
- Repo intelligence scanning
- Fuzz maturity scanning
- Missing evidence generation with source references
- Candidate hypothesis generation
- Proof task generation
- Human summary output
- JSON AuditTriagePacket output
- Public beta docs, examples, issue templates

**The beta runs with provider `none` by default.** No live model calls are part of the `audit-triage` command.

## What Is Schema / Policy Baseline (Defined, Not Yet Runtime-Enforced)

These are defined as schemas and policies in the Plan 4 docs. They are not live provider runtime:

- **Model Provider Abstraction** (`digger.model_provider_config.v1`) — defines 10 provider modes and 7 allowed capabilities
- **LLM Firewall** (`digger.llm_firewall_policy.v1`) — defines secret redaction, context minimization, provider allowlist, prompt injection detection, output grounding
- **Customer Data Boundary** (`digger.data_boundary_policy.v1`) — defines what data can leave the environment
- **Model-Call Audit** (`digger.model_call_audit.v1`) — defines audit records for future model calls
- **Report Verifier Mode** (`digger.claim_verification.v1`) — defines how pasted claims flow through evidence gates
- **Model Evaluation Harness** (`digger.model_evaluation.v1`) — defines how to compare models using Digger outcomes

See `docs/plan4/` for full schema definitions.

## What Is Not Implemented (Unless Code Proves Otherwise)

- Live provider calls from `audit-triage`
- Provider SDKs
- Network model execution in triage path
- Full LLM firewall runtime enforcement
- Full report verifier runtime
- Model evaluation runtime
- Live model-call audit logging
- Any model output creating findings

## Allowed Model Capabilities

When the agentic layer is eventually wired, models may:

- Summarize evidence
- Propose hypotheses
- Rank attack surfaces
- Explain evidence
- Draft report text
- Suggest invariants
- Suggest fuzz/proof tasks

## Forbidden Model Capabilities

These must never exist in any future model interface:

- `decide_valid_finding` — models must never decide what constitutes a valid finding
- Create final findings
- Create EvidenceRun objects
- Create proof packages
- Make severity decisions as truth
- Confirm vulnerabilities
- Bypass evidence gates
- Mutate deterministic facts
- Override validation failures

## Provider Modes

Digger supports any provider or no provider:

- `none` — offline deterministic mode (default for beta)
- `local` — local model inference
- `ollama` — Ollama integration
- `vllm` — vLLM integration
- `openai_compatible` — OpenAI-compatible endpoints
- `openai` — OpenAI API
- `anthropic` — Anthropic API
- `gemini` — Google Gemini
- `enterprise_vpc` — enterprise VPC-hosted models
- `custom_http` — custom provider endpoints

## Offline Deterministic Mode

`DIGGER_MODEL_PROVIDER=none` is a first-class mode. The deterministic engine runs without any model. AI is an optional accelerator, never a requirement.

## LLM Firewall

When models are eventually wired, every model is treated as an untrusted analyst. The firewall enforces:

- Secret redaction
- Context minimization
- Provider allowlist
- Customer-controlled retention
- Prompt injection detection
- Output grounding
- Source citation requirements
- Evidence graph validation
- Model-call audit logging

## Customer Data Boundary

Enterprise promise: "You decide what leaves your environment."

Default: cloud models disallowed, secrets always redacted, external calls require approval, no retention.

## Evidence Gates

Model output must flow through the Plan 3 evidence stack:

```
Hypothesis → ProofTask → EvidenceRun → VerificationDecision
```

No model interface may include `decide_valid_finding`. Model outputs are untrusted evidence inputs, never truth.

## Key Architectural Invariants

1. **AI can suspect. Digger proves.**
2. Models are replaceable. Evidence is indispensable.
3. No model-to-finding shortcut exists.
4. `decide_valid_finding` is forbidden by architecture.
5. Model output is untrusted until grounded.
6. The deterministic engine runs without any model.
7. Every finding decision goes through evidence gates.
