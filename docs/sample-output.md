# Sample Output Shape

This sample describes the report a practice owner, MSP, or consultant should expect from HealthAI Audit. It uses fictional data and intentionally avoids PHI, credentials, private URLs, contracts, logs, patient details, and incident details.

## Executive Readout

Fictional practice: Family Dental Clinic

Review question: Which AI tools can be approved, which need vendor follow-up, and which should stay blocked until evidence exists?

Summary (v0.1.1 sample shape):

- 4 AI tools inventoried (including one MCP scheduling agent).
- 2+ tools touch PHI and require confirmed BAA status before approval.
- 1+ tools use retrieval or uploaded documents and need permission-sync evidence.
- Agent-style actions, MCP servers, autonomous mode, and network egress are scored explicitly.
- Owner/MSP follow-up should cover training, BAA, approval gates, and MCP allowlists before signoff.

## Example Risk Cards

| Tool | Workflow | Current Decision | Main Evidence Gap | Owner/MSP Action |
|---|---|---|---|---|
| Ambient Scribe | Clinical documentation | Conditionally approvable | Confirm BAA, retention, and clinician-review workflow | Collect vendor BAA and sample audit-log export |
| Claims Appeal Drafting Bot | Billing appeals | Block / Critical | Missing BAA, training on customer data, unrestricted email agent | Pause PHI use; require BAA + human approval + logging |
| Clinic Policy RAG Assistant | Staff policy lookup | Needs review | Permission-sync and evaluation coverage partial | Finish source list, refresh cadence, injection tests |
| Front Desk MCP Scheduling Agent | Scheduling with MCP tools | Block / Critical | Autonomous mode + MCP + SMS/browser with no approval gates | Disable autonomous mode; allowlist MCP servers; require human-in-loop |

## Example Remediation Queue

1. Confirm BAA status for any AI tool that can receive PHI.
2. Document whether customer data is used for model training.
3. Require clinician review for documentation, triage, prescribing, or care-plan workflows.
4. Require approval gates before any AI agent can email, update records, create tickets, send SMS, or contact a vendor.
5. Inventory MCP/tool-broker servers, allowlist only required ones, and disable unsupervised autonomous mode for PHI or high-impact tools.
6. Keep a simple AI inventory with owner, workflow, data types, vendor, BAA status, retention, agent tools, MCP servers, and audit logging.

## Reviewer-Safe Output

The generated packet is intended to give a reviewer a clean evidence trail:

- what was reviewed
- what was approved, restricted, or blocked
- which vendor evidence is missing
- which owner/MSP actions are next
- what the tool does not prove

HealthAI Audit does not provide legal advice, clinical advice, HIPAA certification, FDA classification, penetration testing, or a formal Security Risk Analysis opinion.
