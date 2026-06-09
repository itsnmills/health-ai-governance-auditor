# HealthAI Audit

[![CI](https://github.com/itsnmills/health-ai-governance-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/itsnmills/health-ai-governance-auditor/actions/workflows/ci.yml)

HealthAI Audit is a local-first command line auditor for small and medium healthcare practices adopting AI tools.

This is a Velari companion module for the public
[Small Practice Security Kit](https://github.com/itsnmills/small-practice-security-kit):
use it for AI vendor inventory, BAA/PHI handling, RAG, prompt-injection,
agent-permission, and clinical-safety review inputs that can roll into a
broader practice-readiness packet.

## Work with Velari

Use this auditor when a practice, MSP, compliance consultant, or healthcare operator needs a no-PHI AI inventory and vendor-risk review before approving ambient scribes, AI billing tools, RAG assistants, scheduling assistants, or agentic workflows. For a no-PHI readiness discussion, start from [Noah Mills on GitHub](https://github.com/itsnmills) or open a public-safe GitHub issue. Do not include PHI, credentials, private URLs, contracts, logs, patient details, or incident details.

It reads a simple AI-tool inventory and produces:

- AI vendor risk cards
- HIPAA/BAA and PHI handling gaps
- RAG, prompt-injection, and agent/tool-permission findings
- clinical safety and clinician-review gaps
- non-human identity and AI supply-chain questions
- prioritized remediation actions
- Markdown, JSON, and CSV reports
- a starter AI use policy and vendor questionnaire

See the buyer-facing sample output shape in [`docs/sample-output.md`](docs/sample-output.md).

The project is designed for independent practices, specialty clinics, therapy groups, dental offices, community clinics, MSPs, compliance consultants, and healthcare operators that need a practical AI governance workflow without sending sensitive operational data to a SaaS platform.

## What It Is Not

HealthAI Audit does not provide legal advice, clinical advice, HIPAA certification, FDA classification, penetration testing, or a formal security risk analysis opinion. It is a structured local workbench for evidence collection and review.

Do not put PHI, patient identifiers, credentials, secrets, or clinical notes into inventory files.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

No runtime dependencies are required beyond Python 3.11+.

## Quick Start

Generate a Markdown report from the sample inventory:

```bash
healthai-audit score samples/sample_inventory.json --format markdown --out reports/sample-report.md
```

Write JSON for automation:

```bash
healthai-audit score samples/sample_inventory.json --format json --out reports/sample-report.json
```

Write CSV for a spreadsheet:

```bash
healthai-audit score samples/sample_inventory.json --format csv --out reports/sample-summary.csv
```

Create starter templates:

```bash
healthai-audit template inventory --out templates/ai-inventory.json
healthai-audit template questionnaire --out templates/vendor-questionnaire.md
healthai-audit template policy --out templates/ai-use-policy.md
```

## Inventory Schema

The input is JSON with a `practice` name and a `tools` array. Each tool can include fields like:

```json
{
  "name": "Ambient Scribe",
  "vendor": "Example Health AI",
  "workflow": "Clinical documentation",
  "data_types": ["PHI"],
  "deployment_model": "SaaS",
  "model_types": ["LLM"],
  "baa_status": "signed",
  "customer_data_training": "no",
  "retention_days": 30,
  "rag": false,
  "agent_tools": ["EHR draft note"],
  "human_approval": "required",
  "audit_logging": "complete",
  "clinical_use": true,
  "clinician_review": true,
  "safety_case": "documented",
  "evaluation_dimensions": ["factuality", "clinical safety", "privacy"],
  "certifications": ["SOC 2 Type II"],
  "fda_analysis": "documented not medical device",
  "state_policy_review": "documented",
  "incident_process": "documented",
  "model_provenance": "documented",
  "sbom": true,
  "dependency_scanning": true
}
```

Unknown fields are preserved but ignored by the deterministic scorer.

## Scoring Model

Each tool receives 0-4 scores across six domains:

- Data and PHI governance
- Model and RAG security
- Agent and non-human identity permissions
- Development supply chain
- Clinical safety and evaluation
- Compliance evidence

Risk level is based on the lowest domain score plus high-impact flags such as missing BAAs for PHI tools, customer data training with PHI, RAG without permission sync, agent tools without approval gates, missing clinical safety review, missing state-policy review for prescribing support, and weak audit logging.

## Why This Helps Small Practices

Most small practices are being offered ambient scribes, AI scheduling, AI billing support, RAG knowledge assistants, claims appeal drafting, and clinical decision-support features before they have an AI inventory or governance process. HealthAI Audit turns that into a concrete local review packet:

- What AI tools exist?
- Which touch PHI?
- Which need BAAs or contract language?
- Which have unsafe training, retention, RAG, or agent permissions?
- Which require clinician review or state-policy review?
- What evidence should be collected before approval?

## Verification

Run the offline test suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run the full local verifier:

```bash
python3 scripts/verify.py
```

## Open Source

HealthAI Audit is MIT-licensed and intended to be safe for public portfolio, MSP, consulting, and clinic operations use. See `NOTICE.md` and `docs/METHODOLOGY.md` for attribution and scoring details.
