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

Looks for EHR/FHIR/email/file/browser/shell/ticketing access, least privilege, human approval, audit logs, and customer ability to disable tools.

Common high-priority findings:

- Agent can act in EHR, email, files, ticketing, browser, shell, or billing systems without approval gates.
- No audit logs for tool calls.
- Tool scopes are broad or undocumented.

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
