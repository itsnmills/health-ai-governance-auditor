# Methodology

HealthAI Audit uses deterministic scoring so users can inspect and challenge every recommendation.

## Reference Model

The model combines practical healthcare AI review needs with public guidance:

- NIST AI RMF: govern, map, measure, and manage AI risk.
- HIPAA Security Rule: protect electronic protected health information with administrative, physical, and technical safeguards.
- HHS HPH Cybersecurity Performance Goals: prioritize healthcare-specific high-impact cybersecurity practices.
- OWASP Top 10 for LLM Applications: account for prompt injection, sensitive information disclosure, supply chain, excessive agency, vector/embedding weakness, misinformation, and resource abuse.

## Domains

### Data and PHI Governance

Looks for BAA status, PHI handling, training/product-improvement use, retention, deletion, subprocessors, and customer controls.

Common high-priority findings:

- PHI data with missing or unknown BAA.
- Customer data used for training without clear opt-out or contract language.
- No retention or deletion guarantee.

### Model and RAG Security

Looks for RAG usage, document permission sync, source attribution, prompt-injection testing, output validation, and retrieval logging.

Common high-priority findings:

- RAG enabled without permission sync evidence.
- No prompt-injection or indirect prompt-injection testing.
- No source attribution for clinical or administrative outputs.

### Agent and Non-Human Identity Permissions

Looks for EHR/FHIR/email/file/browser/shell/ticketing access, MCP/tool-broker servers, autonomous mode, network egress, least privilege, human approval, audit logs, and customer ability to disable tools.

Common high-priority findings:

- Agent can act in EHR, email, files, ticketing, browser, shell, billing, SMS, or MCP systems without approval gates.
- Unsupervised autonomous mode enabled for PHI or high-impact tools.
- No audit logs for tool calls or outbound actions.
- Tool scopes or MCP servers are broad or undocumented.

### Development Supply Chain

Looks for model provenance, SBOM, dependency scanning, dataset provenance, IDE/extension governance, and secret-handling controls.

Common high-priority findings:

- No model or data provenance.
- No dependency or package scanning.
- No SBOM or model card.

### Clinical Safety and Evaluation

Looks for clinician review, safety case, failure modes, escalation/refusal behavior, post-deployment monitoring, and evaluation dimensions such as factuality, completeness, hallucination, privacy, bias/fairness, workflow fit, and escalation.

Common high-priority findings:

- Clinical or patient-facing use without clinician review.
- Prescription-support workflow without state-policy review.
- No documented safety case or escalation behavior.

### Compliance Evidence

Looks for SOC 2, ISO, HITRUST or equivalent evidence, FDA analysis where relevant, incident process, breach notification route, state-policy review, and named security contact.

Common high-priority findings:

- Missing incident process for a PHI-touching vendor.
- Missing FDA classification analysis for clinical decision-support or diagnostic use.
- No state-policy review for multi-state or prescription-related workflows.

## Risk Level

Risk level is not legal or clinical advice. It is a triage label.

- `Critical`: deployment should pause until a core control gap is closed.
- `High`: leadership, MSP, security, compliance, or counsel review is needed before expansion.
- `Medium`: gaps should become tracked remediation items.
- `Low`: no major gaps found in provided inventory, but evidence should still be validated.

## Decisions (v0.2+)

Risk levels feed a separate **decision** layer with stable rule IDs:

| Decision | Meaning |
| --- | --- |
| `block` | Do not use for PHI / production until listed rules are closed |
| `restrict` | Limited use only under documented guardrails |
| `approve_with_conditions` | Usable with tracked remediation owners and dates |
| `approve` | No major inventory gaps; still validate evidence offline |

Examples of blocking rules:

- `HA-BAA-001` PHI tool without signed BAA
- `HA-TRAIN-001` customer-data training with PHI
- `HA-MCP-001` MCP/tool-broker without approval gates
- `HA-AUTO-001` unsupervised autonomous mode on PHI or tools

Evidence / approve-condition rules (v0.3+):

- `HA-EVID-001` PHI tool missing approve-grade evidence refs
- `HA-EVID-002` evidence refs expired relative to inventory `review_date`

Portfolio decision = worst tool decision. Owner packets export the queue without raw inventory source fields.

## Evidence refs (v0.3+)

Evidence is **reference-only metadata** attached to each tool:

| Field | Required | Notes |
| --- | --- | --- |
| `id` | recommended | Stable evidence ID for binders |
| `kind` | yes | `baa`, `policy`, `soc2`, `training_opt_out`, `clinician_signoff`, `mcp_allowlist`, … |
| `path` | yes | Relative local path; no `..`, no URL schemes |
| `sha256` | optional | 64-hex digest if the practice hashes files |
| `reviewed_on` | recommended | `YYYY-MM-DD` |
| `expires_on` | recommended | `YYYY-MM-DD`; expired refs fail approve for PHI tools |
| `covers_rules` | optional | Rule IDs this ref is meant to close |

HealthAI Audit does **not** open the files at `path`. Operators keep BAAs and signoffs in their private binder.

## Kit bridge (v0.3+)

`kit-export` / packet `kit-bridge/` maps decisions into Small Practice Security Kit language:

| HealthAI decision | Kit label |
| --- | --- |
| `approve` | allowed |
| `approve_with_conditions` / `restrict` | restricted |
| `block` | prohibited |

## Diff (v0.3+)

`healthai-audit diff before after` compares rule IDs and decisions per tool name so remediation can be proven across runs (closed rules vs regressions).

## Safety model (v0.2+)

Inventories are **fail-closed**:

- secrets / key-shaped strings rejected
- SSN-shaped values rejected
- free-text note/prompt/transcript fields rejected
- oversized files rejected
- report JSON omits raw `source` unless `--include-source` (still redacts high-risk keys)

This keeps the tool a governance workbench, not a place to paste clinical content.

## Output Use

Use reports as:

- vendor review packets
- intake notes before counsel/compliance review
- MSP or consultant workpapers
- evidence-binder inputs
- recurring AI inventory review artifacts

Do not use output as:

- a HIPAA compliance certification
- a breach determination
- a medical device classification opinion
- a clinical-safety approval
- a substitute for contract review
