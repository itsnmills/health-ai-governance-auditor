# Security Policy

HealthAI Audit is a local-first tool. It should not receive, store, or process patient identifiers, clinical notes, claim contents, credentials, API keys, or secrets.

## Supported Versions

The current supported development line is `0.4.x`.

## Reporting a Vulnerability

If you find a vulnerability, do not open a public issue containing exploit details, PHI, client data, screenshots from a real practice, or secrets.

Send a private report to the project maintainer with:

- affected version or commit
- concise reproduction steps using synthetic data
- expected and actual behavior
- suggested fix, if known

## Safety Boundary

HealthAI Audit output is triage support. It is not legal advice, clinical advice, HIPAA certification, FDA classification, penetration testing, or a formal security risk analysis opinion.

## Sensitive Data Handling

Use synthetic examples in issues, pull requests, tests, and documentation. Redact vendor contracts, hostnames, email addresses, client names, and any data that could identify a practice or patient unless the organization has explicitly approved disclosure.

## Built-in fail-closed checks (v0.2+)

`healthai-audit` refuses to score inventories that appear to contain:

- private keys, cloud/API token shapes, JWTs
- SSN-shaped values
- free-text fields such as `notes`, `prompt`, `transcript`, `clinical_notes`

Reports omit raw inventory `source` objects by default so free-text cannot ride along into packets. These checks reduce accidents; they are **not** a guarantee that an inventory is free of PHI. Operators remain responsible for using synthetic, non-sensitive inputs only.

To inspect without scoring:

```bash
healthai-audit safety-check path/to/inventory.json
```
