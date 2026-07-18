"""Built-in report and intake templates."""

from __future__ import annotations

import json


def inventory_template() -> str:
    return json.dumps(
        {
            "practice": "Example Clinic",
            "review_owner": "Practice Manager",
            "review_date": "2026-05-01",
            "practice_profile": {
                "type": "general",
                "states": ["MO"],
                "msp_managed": False
            },
            "tools": [
                {
                    "name": "AI Tool Name",
                    "vendor": "Vendor Name",
                    "workflow": "What workflow does this support?",
                    "use_case": "clinical documentation / billing / scheduling / internal knowledge / other",
                    "data_types": ["PHI"],
                    "deployment_model": "SaaS",
                    "model_types": ["LLM"],
                    "baa_status": "unknown",
                    "customer_data_training": "unknown",
                    "retention_days": None,
                    "subprocessors": "unknown",
                    "rag": False,
                    "permission_sync": "unknown",
                    "source_attribution": False,
                    "prompt_injection_testing": "unknown",
                    "agent_tools": [],
                    "mcp_servers": [],
                    "autonomous_mode": "unknown",
                    "network_egress": "unknown",
                    "tool_scope": "unknown",
                    "human_approval": "unknown",
                    "audit_logging": "unknown",
                    "customer_can_disable_tools": False,
                    "clinical_use": False,
                    "patient_facing": False,
                    "prescription_support": False,
                    "clinician_review": False,
                    "safety_case": "unknown",
                    "evaluation_dimensions": [],
                    "escalation_behavior": "unknown",
                    "post_deployment_monitoring": "unknown",
                    "certifications": [],
                    "fda_analysis": "unknown",
                    "state_policy_review": "unknown",
                    "incident_process": "unknown",
                    "security_contact": "",
                    "model_provenance": "unknown",
                    "dataset_provenance": "unknown",
                    "sbom": False,
                    "dependency_scanning": False,
                    "ide_extension_governance": "unknown",
                    "secrets_controls": "unknown",
                    "evidence_refs": [
                        {
                            "id": "EVID-BAA-001",
                            "kind": "baa",
                            "path": "evidence/vendor-baa.pdf",
                            "sha256": "",
                            "reviewed_on": "2026-07-01",
                            "expires_on": "2027-07-01",
                            "covers_rules": ["HA-BAA-001"],
                        }
                    ],
                }
            ],
        },
        indent=2,
    ) + "\n"


def questionnaire_template() -> str:
    return """# Healthcare AI Vendor Risk Questionnaire

## Vendor Profile

| Field | Response |
| --- | --- |
| Vendor / product | |
| Workflow supported | |
| Clinical, administrative, research, or patient-facing use | |
| Data types handled | PHI / PII / deidentified / synthetic / none |
| Deployment model | SaaS / on-prem / customer cloud / hybrid |
| Model type | LLM / imaging / prediction / automation / agent / RAG |

## Data and PHI

- What PHI or sensitive data does the system access, store, transmit, infer, or log?
- Is customer data used for training, fine-tuning, evaluation, analytics, or product improvement?
- Can the practice opt out of model improvement data use?

## Agents, MCP, and automation

- Which agent tools, MCP servers, or tool brokers can the product call?
- Can the agent act autonomously, or is human approval required per action class?
- Can the practice allowlist, disable, or scope tools and MCP servers?
- What network egress is allowed (email, SMS, browser, webhooks, arbitrary HTTP)?
- Are tool calls, destinations, and approval decisions logged for review?

## Evidence references (no PHI)

For each control claim, record reference-only evidence:

| Field | Example |
| --- | --- |
| id | EVID-BAA-001 |
| kind | baa / policy / soc2 / training_opt_out / clinician_signoff / mcp_allowlist |
| path | evidence/vendor-baa.pdf (relative local path) |
| sha256 | optional 64-hex digest of the file |
| reviewed_on | 2026-07-01 |
| expires_on | 2027-07-01 |

Do not paste contract text, patient data, or credentials into the inventory.

- Are retention, deletion, and export guarantees contractually defined?
- Which subprocessors can access customer data?
- Is a BAA signed before PHI is used?

## Model and RAG Security

- Does the product use RAG, embeddings, or external knowledge retrieval?
- How are source document permissions synchronized into retrieval?
- How are prompt injection and indirect prompt injection tested?
- Are outputs source-attributed?
- Are retrieval and output events logged for audit?

## Agent and Tool Permissions

- Can the AI call tools, APIs, EHR/FHIR endpoints, email, browser, shell, files, billing, or ticketing systems?
- Are tool permissions least-privilege and customer-configurable?
- Is human approval required before high-impact actions?
- Are agent actions logged with user, prompt, tool, input, output, and timestamp?
- Can the practice disable tools or restrict scopes?

## Development Supply Chain

- Which model providers, model hubs, datasets, extensions, notebooks, and AI coding tools are used?
- Are dependencies, containers, model artifacts, and extensions scanned?
- Is there an SBOM, model card, or data provenance record?
- Are secrets prevented from entering prompts, logs, training data, and telemetry?

## Clinical Safety

- What clinical safety case exists for this use case?
- What failure modes have been identified?
- How are clinicians warned about limitations?
- What escalation or refusal behavior exists?
- Are factuality, completeness, hallucination, privacy, bias/fairness, workflow fit, and escalation tested?
- How are outputs monitored after deployment?

## Compliance and Evidence

- HIPAA / BAA posture:
- SOC 2 / ISO / HITRUST or equivalent evidence:
- FDA / medical device classification analysis:
- State clinical AI policy review:
- Incident response and breach notification process:
- Named security contact:
"""


def policy_template() -> str:
    return """# Small-Practice AI Use Policy Starter

## Purpose

This policy defines how the practice reviews, approves, and monitors AI tools that may affect patient care, ePHI, workforce operations, vendors, or security.

## Approved Use

- AI tools must be recorded in the AI inventory before use with practice data.
- PHI may only be used with AI tools after BAA, data-use, retention, deletion, logging, and security controls are reviewed.
- Patient-facing, clinical, prescription-support, triage, diagnosis, or documentation workflows require clinician owner approval.
- Staff may not paste PHI, patient identifiers, claims details, clinical notes, passwords, API keys, or secrets into unapproved AI tools.

## Vendor Review

Each AI vendor review should collect:

- workflow and data types
- BAA status
- training/product-improvement data use
- retention and deletion terms
- RAG permission controls
- agent/tool permissions
- audit logging
- clinical safety evidence
- incident and breach notification process
- security contact and evidence package

## Agent and RAG Controls

- AI agents must use least-privilege tool scopes.
- High-impact actions require human approval.
- RAG systems must preserve source permissions and log retrieval.
- Prompt-injection and data-exfiltration tests should be run before production use.

## Evidence

The practice should keep vendor answers, BAA status, risk decision, owner approval, test evidence, and review dates in its evidence binder.

## Review Cadence

AI inventory and vendor risk status should be reviewed at least quarterly, and whenever a vendor adds new data use, model training, RAG, agent tools, clinical functions, subprocessors, or state-specific workflows.
"""


TEMPLATES = {
    "inventory": inventory_template,
    "questionnaire": questionnaire_template,
    "policy": policy_template,
}
