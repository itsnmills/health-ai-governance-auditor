# NOTICE / Attribution

HealthAI Audit is an original open-source project by Healthcare AI Security Lab.

It turns local AI-tool inventory data into a deterministic governance and vendor-risk report for healthcare practices. It does not certify HIPAA compliance, FDA status, clinical safety, or legal sufficiency.

## Public guidance used as reference points

- NIST AI Risk Management Framework
  - https://www.nist.gov/itl/ai-risk-management-framework
  - https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10
- HHS HIPAA Security Rule overview
  - https://www.hhs.gov/ocr/privacy/hipaa/administrative/securityrule/index.html
- HHS Healthcare and Public Health Cybersecurity Performance Goals
  - https://hhscyber.hhs.gov/performance-goals.html
- OWASP Top 10 for Large Language Model Applications
  - https://owasp.org/www-project-top-10-for-large-language-model-applications
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf

## Local source material

This first release was shaped by local Dario vault notes:

- `Research/Healthcare-AI-Security/Assessments/Healthcare AI Vendor Risk Questionnaire.md`
- `Research/Healthcare-AI-Security/Trackers/Clinical AI Evaluation Rubric.md`
- `Research/Healthcare-AI-Security/Trackers/Non-Human Identity Control Map.md`
- `Reports/weekly_intelligence/Healthcare AI Security Weekly Intelligence - 2026-04-28.md`

## Business-use guardrails

- Do not enter patient names, chart numbers, diagnosis details, claim contents, credentials, or secrets into inventory files.
- Treat output as structured preparation for qualified legal, compliance, security, clinical, and vendor review.
- Validate results against current contracts, BAAs, state rules, workflow design, and technical evidence before relying on them.
