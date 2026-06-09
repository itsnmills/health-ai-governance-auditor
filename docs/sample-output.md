# Sample Output Shape

This sample describes the report a practice owner, MSP, or consultant should expect from HealthAI Audit. It uses fictional data and intentionally avoids PHI, credentials, private URLs, contracts, logs, patient details, and incident details.

## Executive Readout

Fictional practice: Family Dental Clinic

Review question: Which AI tools can be approved, which need vendor follow-up, and which should stay blocked until evidence exists?

Summary:

- 4 AI tools inventoried.
- 2 tools touch PHI and require confirmed BAA status before approval.
- 1 tool uses retrieval or uploaded documents and needs permission-sync evidence.
- 1 tool has agent-style actions and needs human approval gates.
- 3 vendor follow-up questions should be sent before owner signoff.

## Example Risk Cards

| Tool | Workflow | Current Decision | Main Evidence Gap | Owner/MSP Action |
|---|---|---|---|---|
| Ambient Scribe | Clinical documentation | Conditionally approvable | Confirm BAA, retention, and clinician-review workflow | Collect vendor BAA and sample audit-log export |
| Billing Assistant | Claims and denial drafting | Needs review | Customer-data training and export-retention terms unclear | Ask vendor for training, retention, and subcontractor language |
| Scheduling Chatbot | Appointment scheduling | Limited approval | PHI boundary and escalation workflow unclear | Restrict intake content and document escalation path |
| Internal Policy Assistant | Staff policy lookup | Low risk if local-only | Permission-sync and source freshness evidence missing | Record source list and refresh cadence |

## Example Remediation Queue

1. Confirm BAA status for any AI tool that can receive PHI.
2. Document whether customer data is used for model training.
3. Require clinician review for documentation, triage, prescribing, or care-plan workflows.
4. Require approval gates before any AI agent can email, update records, create tickets, or contact a vendor.
5. Keep a simple AI inventory with owner, workflow, data types, vendor, BAA status, retention, and audit logging.

## Reviewer-Safe Output

The generated packet is intended to give a reviewer a clean evidence trail:

- what was reviewed
- what was approved, restricted, or blocked
- which vendor evidence is missing
- which owner/MSP actions are next
- what the tool does not prove

HealthAI Audit does not provide legal advice, clinical advice, HIPAA certification, FDA classification, penetration testing, or a formal Security Risk Analysis opinion.
