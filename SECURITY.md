# Security Policy

HealthAI Audit is a local-first tool. It should not receive, store, or process patient identifiers, clinical notes, claim contents, credentials, API keys, or secrets.

## Supported Versions

The current supported development line is `0.1.x`.

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
