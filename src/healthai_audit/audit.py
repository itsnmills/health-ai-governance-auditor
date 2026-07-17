"""Deterministic AI governance scoring for healthcare practices."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class DomainResult:
    name: str
    score: int
    evidence: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    mappings: list[str] = field(default_factory=list)


@dataclass
class ToolAssessment:
    name: str
    vendor: str
    workflow: str
    risk_level: str
    maturity_score: int
    domain_results: list[DomainResult]
    critical_flags: list[str]
    high_priority_actions: list[str]
    source: dict[str, Any]
    data_types: list[str] = field(default_factory=list)
    evidence_refs: list[dict[str, Any]] = field(default_factory=list)
    evidence_status: dict[str, Any] = field(default_factory=dict)


def load_inventory(path: Path) -> dict[str, Any]:
    """Load a JSON or CSV AI tool inventory from disk."""
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        return {"practice": path.stem, "tools": [_normalize_csv_row(row) for row in rows]}

    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        data = {"practice": path.stem, "tools": data}
    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        raise ValueError("inventory must be a JSON object with a tools array, a JSON list, or a CSV file")
    return data


def audit_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic audit report for an AI inventory."""
    tools = [tool for tool in inventory.get("tools", []) if isinstance(tool, dict)]
    review_date = str(inventory.get("review_date", ""))
    assessments = [assess_tool(tool, review_date=review_date) for tool in tools]
    counts = {level: sum(1 for item in assessments if item.risk_level == level) for level in ("Critical", "High", "Medium", "Low")}
    top_actions: list[str] = []
    for assessment in assessments:
        for action in assessment.high_priority_actions:
            action_text = f"{assessment.name}: {action}"
            if action_text not in top_actions:
                top_actions.append(action_text)

    return {
        "metadata": {
            "practice": str(inventory.get("practice", "Unspecified practice")),
            "review_owner": str(inventory.get("review_owner", "")),
            "review_date": str(inventory.get("review_date", "")),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "method": "HealthAI Audit deterministic scoring v0.3.0",
            "disclaimer": "Triage support only; not legal, clinical, HIPAA, FDA, or security certification advice.",
        },
        "summary": {
            "tool_count": len(assessments),
            "risk_counts": counts,
            "average_maturity_score": round(sum(item.maturity_score for item in assessments) / max(1, len(assessments))),
            "top_actions": top_actions[:10],
        },
        "assessments": [_assessment_to_dict(item) for item in assessments],
    }


def run_audit(
    path: Path,
    *,
    strict_safety: bool = True,
    include_source: bool = False,
    with_decisions: bool = True,
) -> dict[str, Any]:
    """Load, safety-check, score, decide, and sanitize an inventory file.

    This is the preferred entrypoint for CLI and automation. It fails closed
    when the inventory looks like it contains secrets or free-text PHI risk.
    """
    from healthai_audit.decisions import attach_decisions
    from healthai_audit.safety import assert_inventory_safe, sanitize_report

    inventory = load_inventory(path)
    assert_inventory_safe(path, inventory, strict=strict_safety)
    report = audit_inventory(inventory)
    if with_decisions:
        report = attach_decisions(report)
    return sanitize_report(report, include_source=include_source)


def assess_tool(tool: dict[str, Any], *, review_date: str = "") -> ToolAssessment:
    from healthai_audit.evidence import evidence_status_for_tool, normalize_evidence_refs

    domain_results = [
        score_data_governance(tool),
        score_model_rag_security(tool),
        score_agent_permissions(tool),
        score_supply_chain(tool),
        score_clinical_safety(tool),
        score_compliance_evidence(tool),
    ]
    critical_flags = find_critical_flags(tool, domain_results)
    maturity_score = round(sum(result.score for result in domain_results) / (len(domain_results) * 4) * 100)
    risk_level = risk_from_results(maturity_score, domain_results, critical_flags)
    actions = []
    for flag in critical_flags:
        actions.append(flag)
    for result in domain_results:
        actions.extend(result.actions)

    evidence_refs, evidence_gaps = normalize_evidence_refs(tool.get("evidence_refs"))
    evidence_status = evidence_status_for_tool(
        tool, evidence_refs, evidence_gaps, review_date=review_date
    )
    data_types = [str(item) for item in as_list(tool.get("data_types")) if str(item).strip()]

    return ToolAssessment(
        name=str(tool.get("name", "Unnamed AI tool")),
        vendor=str(tool.get("vendor", "Unknown vendor")),
        workflow=str(tool.get("workflow", "Unspecified workflow")),
        risk_level=risk_level,
        maturity_score=maturity_score,
        domain_results=domain_results,
        critical_flags=critical_flags,
        high_priority_actions=_unique(actions)[:8],
        source=tool,
        data_types=data_types,
        evidence_refs=evidence_refs,
        evidence_status=evidence_status,
    )


def score_data_governance(tool: dict[str, Any]) -> DomainResult:
    score = 4
    evidence: list[str] = []
    gaps: list[str] = []
    actions: list[str] = []

    data_types = lower_list(tool.get("data_types"))
    touches_phi = any(value in {"phi", "ephi", "claims", "audio", "clinical notes"} for value in data_types)
    baa = normalized(tool.get("baa_status"))
    training = normalized(tool.get("customer_data_training"))
    retention = tool.get("retention_days")
    subprocessors = normalized(tool.get("subprocessors"))

    if touches_phi:
        evidence.append("Inventory says the tool can touch PHI or PHI-adjacent data.")
        if baa not in {"signed", "current", "not applicable"}:
            gaps.append("BAA is missing or unknown for a PHI-touching tool.")
            actions.append("Do not approve PHI use until BAA and data-use terms are documented.")
            score -= 2
    else:
        evidence.append("Inventory does not mark this tool as PHI-touching.")

    if training in {"yes", "true"}:
        gaps.append("Customer data may be used for training or product improvement.")
        actions.append("Require opt-out or contract language blocking customer-data training for practice data.")
        score -= 2 if touches_phi else 1
    elif training in {"no", "false"}:
        evidence.append("Customer data training is marked as no.")
    else:
        gaps.append("Customer data training posture is unknown.")
        actions.append("Ask vendor whether prompts, files, outputs, audio, and logs are used for training or evaluation.")
        score -= 1

    if retention in ("", None):
        gaps.append("Retention period is not defined.")
        actions.append("Document retention, deletion, and export terms.")
        score -= 1
    else:
        try:
            retention_days = int(retention)
            if retention_days < 0:
                raise ValueError("negative retention")
            evidence.append(f"Retention period recorded: {retention_days} days.")
            if touches_phi and retention_days > 365:
                gaps.append("PHI retention exceeds 365 days without a documented justification in inventory.")
                actions.append("Confirm retention minimum-necessary rationale and deletion/export process for PHI.")
                score -= 1
        except (TypeError, ValueError):
            gaps.append("Retention period is not a valid non-negative integer day count.")
            actions.append("Record retention as an integer number of days, plus deletion terms.")
            score -= 1

    if subprocessors in {"unknown", "unavailable", "none"}:
        gaps.append("Subprocessor list is missing or unavailable.")
        actions.append("Request current subprocessor list and breach-notification contact path.")
        score -= 1
    else:
        evidence.append("Subprocessor information is available.")

    return domain("Data and PHI governance", score, evidence, gaps, actions, ["HIPAA Security Rule", "NIST AI RMF Govern/Map"])


def score_model_rag_security(tool: dict[str, Any]) -> DomainResult:
    score = 4
    evidence: list[str] = []
    gaps: list[str] = []
    actions: list[str] = []
    uses_rag = boolish(tool.get("rag")) or "rag" in lower_list(tool.get("model_types"))
    permission_sync = normalized(tool.get("permission_sync"))
    prompt_tests = normalized(tool.get("prompt_injection_testing"))
    source_attribution = boolish(tool.get("source_attribution"))

    if uses_rag:
        evidence.append("RAG or retrieval is in scope.")
        if permission_sync not in {"documented", "not applicable"}:
            gaps.append("RAG permission sync is not fully documented.")
            actions.append("Verify retrieval preserves source permissions and excludes PHI folders by default.")
            score -= 2 if permission_sync in {"unknown", "none", ""} else 1
    else:
        evidence.append("RAG is not marked in scope.")

    if prompt_tests not in {"documented", "complete"}:
        gaps.append("Prompt-injection testing is missing or partial.")
        actions.append("Run direct and indirect prompt-injection tests before production expansion.")
        score -= 1
    else:
        evidence.append("Prompt-injection testing is documented.")

    if source_attribution:
        evidence.append("Source attribution is enabled or required.")
    elif uses_rag or boolish(tool.get("clinical_use")):
        gaps.append("Source attribution is missing for RAG or clinical workflow.")
        actions.append("Require source-linked outputs or a no-source warning for unsupported claims.")
        score -= 1

    return domain("Model and RAG security", score, evidence, gaps, actions, ["OWASP LLM01", "OWASP LLM08", "NIST AI RMF Measure"])


# High-impact agent/tool surfaces for small-practice AI review.
# Includes classic tool actions plus MCP/tool-broker and egress-capable actions.
HIGH_IMPACT_AGENT_TOOLS = {
    "ehr",
    "fhir",
    "email",
    "shell",
    "browser",
    "files",
    "file upload",
    "billing",
    "ticketing",
    "ehr draft note",
    "mcp",
    "mcp server",
    "mcp servers",
    "tool broker",
    "webhook",
    "http",
    "api call",
    "calendar write",
    "sms",
    "phone dialer",
    "payment",
    "remote desktop",
}


def score_agent_permissions(tool: dict[str, Any]) -> DomainResult:
    score = 4
    evidence: list[str] = []
    gaps: list[str] = []
    actions: list[str] = []
    agent_tools = lower_list(tool.get("agent_tools"))
    mcp_servers = lower_list(tool.get("mcp_servers"))
    high_impact = [name for name in agent_tools if name in HIGH_IMPACT_AGENT_TOOLS]
    approval = normalized(tool.get("human_approval"))
    logging = normalized(tool.get("audit_logging"))
    scope = normalized(tool.get("tool_scope"))
    autonomous = normalized(tool.get("autonomous_mode"))
    network_egress = normalized(tool.get("network_egress"))
    has_mcp = bool(mcp_servers) or any(
        token in name for name in agent_tools for token in ("mcp", "tool broker", "tool-broker")
    )
    has_egress = network_egress in {"yes", "true", "open", "unrestricted", "internet"} or any(
        token in name
        for name in agent_tools
        for token in ("browser", "webhook", "http", "email", "sms", "api call")
    )

    if agent_tools or mcp_servers:
        if agent_tools:
            evidence.append(f"Agent/tool capabilities recorded: {', '.join(agent_tools)}.")
        if mcp_servers:
            evidence.append(f"MCP/tool-broker servers recorded: {', '.join(mcp_servers)}.")
            high_impact = high_impact or ["mcp"]
        if high_impact and approval not in {"required", "some"}:
            gaps.append("High-impact tools lack a human approval gate.")
            actions.append(
                "Require human approval before EHR, email, file, billing, shell, browser, MCP, webhook, or ticketing actions."
            )
            score -= 2
        if logging not in {"complete", "documented"}:
            gaps.append("Agent/tool audit logging is missing or partial.")
            actions.append("Log user, prompt, tool, input, output, timestamp, and approval decision for each tool call.")
            score -= 1
        if scope not in {"limited", "least privilege", "documented"}:
            gaps.append("Tool scope is broad or unknown.")
            actions.append("Document least-privilege scopes and customer disable switches for each tool.")
            score -= 1
        if has_mcp and scope not in {"limited", "least privilege", "documented"}:
            gaps.append("MCP/tool-broker exposure lacks a least-privilege allowlist.")
            actions.append(
                "Inventory MCP servers and tools, allowlist only required servers, and block filesystem/shell egress by default."
            )
            score -= 1
        if autonomous in {"yes", "true", "full", "unsupervised"}:
            gaps.append("Autonomous mode can act without step-by-step human control.")
            actions.append("Disable unsupervised autonomous mode for PHI or high-impact tools; require human approval per action class.")
            score -= 2 if high_impact or has_mcp else 1
        elif autonomous in {"partial", "supervised", "human-in-loop", "human in the loop"}:
            evidence.append("Autonomous mode is supervised or partial.")
        elif autonomous in {"no", "false", "disabled", "none"}:
            evidence.append("Autonomous mode is disabled.")
        elif agent_tools or mcp_servers:
            gaps.append("Autonomous/agent execution mode is unknown.")
            actions.append("Document whether the agent can act without a human in the loop, and for which tools.")
            score -= 1
        if has_egress and logging not in {"complete", "documented"}:
            gaps.append("Network-capable tools lack complete audit logging.")
            actions.append("Log every outbound email, SMS, webhook, browser, or HTTP action with destination class and approver.")
            score -= 1
        prompt_tests = normalized(tool.get("prompt_injection_testing"))
        if (has_mcp or has_egress) and prompt_tests not in {"documented", "complete"}:
            gaps.append("Prompt-injection testing is missing for MCP or network-capable agents.")
            actions.append("Test direct and indirect prompt injection against MCP tools, browser actions, and outbound message tools.")
            score -= 1
    else:
        evidence.append("No agent tools or MCP servers are recorded.")

    if boolish(tool.get("customer_can_disable_tools")):
        evidence.append("Customer can disable or restrict tools.")
    elif agent_tools or mcp_servers:
        gaps.append("Customer disable switch for tools is not confirmed.")
        actions.append("Confirm the practice can disable agent tools, MCP servers, or reduce scopes.")
        score -= 1

    return domain(
        "Agent and non-human identity permissions",
        score,
        evidence,
        gaps,
        actions,
        ["OWASP LLM06", "OWASP LLM08", "HHS CPG Access Management", "NIST AI RMF Manage"],
    )


def score_supply_chain(tool: dict[str, Any]) -> DomainResult:
    score = 4
    evidence: list[str] = []
    gaps: list[str] = []
    actions: list[str] = []
    provenance = normalized(tool.get("model_provenance"))
    dataset = normalized(tool.get("dataset_provenance"))
    sbom = boolish(tool.get("sbom"))
    dependency_scanning = boolish(tool.get("dependency_scanning"))
    secrets = normalized(tool.get("secrets_controls"))

    if provenance in {"documented", "complete"}:
        evidence.append("Model provenance is documented.")
    else:
        gaps.append("Model provenance is unknown or incomplete.")
        actions.append("Request model card, provider list, hosted model details, and change-notification terms.")
        score -= 1

    if dataset in {"documented", "complete", "not applicable"}:
        evidence.append("Dataset provenance is documented or not applicable.")
    else:
        gaps.append("Dataset provenance is unknown or partial.")
        actions.append("Ask what datasets, fine-tuning data, and evaluation data were used.")
        score -= 1

    if not sbom:
        gaps.append("SBOM/model artifact inventory is missing.")
        actions.append("Request SBOM or equivalent software/model component inventory.")
        score -= 1
    else:
        evidence.append("SBOM or component inventory is available.")

    if not dependency_scanning:
        gaps.append("Dependency scanning is not confirmed.")
        actions.append("Confirm vulnerability and malicious-package scanning for code, containers, models, and extensions.")
        score -= 1
    else:
        evidence.append("Dependency scanning is confirmed.")

    if secrets not in {"documented", "complete"}:
        gaps.append("Secret-handling controls for prompts, logs, and telemetry are not documented.")
        actions.append("Verify secrets cannot be captured in prompts, logs, model telemetry, or training data.")
        score -= 1

    return domain("Development supply chain", score, evidence, gaps, actions, ["OWASP LLM03", "HHS CPG Third Party", "NIST AI RMF Map"])


def score_clinical_safety(tool: dict[str, Any]) -> DomainResult:
    score = 4
    evidence: list[str] = []
    gaps: list[str] = []
    actions: list[str] = []
    clinical = boolish(tool.get("clinical_use")) or "clinical" in normalized(tool.get("use_case"))
    patient_facing = boolish(tool.get("patient_facing"))
    prescription = boolish(tool.get("prescription_support"))
    clinician_review = boolish(tool.get("clinician_review"))
    safety_case = normalized(tool.get("safety_case"))
    evaluation_dimensions = lower_list(tool.get("evaluation_dimensions"))
    escalation = normalized(tool.get("escalation_behavior"))
    monitoring = normalized(tool.get("post_deployment_monitoring"))

    if clinical or patient_facing or prescription:
        evidence.append("Clinical, patient-facing, or prescription-support use is in scope.")
        if not clinician_review:
            gaps.append("Clinician review is not confirmed for a clinical workflow.")
            actions.append("Require named clinical owner review before use in patient-care workflows.")
            score -= 2
        if safety_case not in {"documented", "complete"}:
            gaps.append("Clinical safety case is missing, draft, or unknown.")
            actions.append("Document intended use, limitations, failure modes, escalation, and clinician responsibilities.")
            score -= 1
        if prescription:
            state_review = normalized(tool.get("state_policy_review"))
            if state_review not in {"documented", "complete", "not applicable"}:
                gaps.append("Prescription-support use lacks state-policy review.")
                actions.append("Do not use for prescription support until state medical-board and counsel review are complete.")
                score -= 1
    else:
        evidence.append("Tool is not marked as clinical or patient-facing.")

    expected_dimensions = {"factuality", "clinical safety", "privacy", "hallucination", "escalation"}
    missing_dimensions = sorted(expected_dimensions - set(evaluation_dimensions))
    if missing_dimensions and (clinical or patient_facing or "llm" in lower_list(tool.get("model_types"))):
        gaps.append(f"Evaluation coverage missing: {', '.join(missing_dimensions)}.")
        actions.append(f"Add {', '.join(missing_dimensions)} checks to acceptance testing.")
        score -= 1
    else:
        evidence.append("Core evaluation dimensions are recorded.")

    if escalation not in {"documented", "complete"} and (clinical or patient_facing):
        gaps.append("Escalation/refusal behavior is not documented.")
        actions.append("Define when the AI must refuse, escalate, or defer to staff.")
        score -= 1

    if monitoring not in {"documented", "complete"} and (clinical or patient_facing):
        gaps.append("Post-deployment monitoring is missing or partial.")
        actions.append("Define monitoring for unsafe outputs, complaints, drift, and workflow changes.")
        score -= 1

    return domain("Clinical safety and evaluation", score, evidence, gaps, actions, ["NIST AI RMF Measure/Manage", "OWASP LLM09"])


def score_compliance_evidence(tool: dict[str, Any]) -> DomainResult:
    score = 4
    evidence: list[str] = []
    gaps: list[str] = []
    actions: list[str] = []
    certifications = lower_list(tool.get("certifications"))
    fda = normalized(tool.get("fda_analysis"))
    state = normalized(tool.get("state_policy_review"))
    incident = normalized(tool.get("incident_process"))
    security_contact = str(tool.get("security_contact", "")).strip()
    clinical = boolish(tool.get("clinical_use")) or boolish(tool.get("patient_facing")) or boolish(tool.get("prescription_support"))

    if certifications:
        evidence.append(f"Security/compliance evidence recorded: {', '.join(certifications)}.")
    else:
        gaps.append("No SOC 2, ISO, HITRUST, or equivalent evidence is recorded.")
        actions.append("Request current security evidence package or compensating evidence for small vendors.")
        score -= 1

    if clinical and fda not in {"documented not medical device", "documented medical device", "not applicable"}:
        gaps.append("FDA/medical-device classification analysis is missing for clinical use.")
        actions.append("Request documented FDA/medical-device classification analysis for clinical workflows.")
        score -= 1
    else:
        evidence.append("FDA analysis is documented or not applicable.")

    if clinical and state not in {"documented", "complete", "not applicable"}:
        gaps.append("State clinical AI policy review is missing or unknown.")
        actions.append("Map state policy constraints before deployment in clinical or multi-state workflows.")
        score -= 1
    else:
        evidence.append("State-policy review is documented or not applicable.")

    if incident not in {"documented", "complete"}:
        gaps.append("Incident response and breach notification process is not documented.")
        actions.append("Request breach notification process, timelines, and after-hours contact path.")
        score -= 1
    else:
        evidence.append("Incident response process is documented.")

    if not security_contact:
        gaps.append("Named security contact is missing.")
        actions.append("Collect named security and emergency escalation contacts.")
        score -= 1

    return domain("Compliance evidence", score, evidence, gaps, actions, ["HIPAA Security Rule", "HHS CPG Vendor/Supplier", "NIST AI RMF Govern"])


def find_critical_flags(tool: dict[str, Any], domains: list[DomainResult]) -> list[str]:
    flags: list[str] = []
    data_types = lower_list(tool.get("data_types"))
    touches_phi = any(value in {"phi", "ephi", "claims", "audio", "clinical notes"} for value in data_types)
    baa = normalized(tool.get("baa_status"))
    training = normalized(tool.get("customer_data_training"))
    approval = normalized(tool.get("human_approval"))
    logging = normalized(tool.get("audit_logging"))
    clinical = boolish(tool.get("clinical_use")) or boolish(tool.get("patient_facing")) or boolish(tool.get("prescription_support"))

    if touches_phi and baa not in {"signed", "current", "not applicable"}:
        flags.append("Pause PHI use until BAA status is signed/current and data-use terms are reviewed.")
    if touches_phi and training in {"yes", "true"}:
        flags.append("Block PHI use until customer-data training/product-improvement use is prohibited or formally approved.")
    if (boolish(tool.get("rag")) or "rag" in lower_list(tool.get("model_types"))) and normalized(tool.get("permission_sync")) in {"unknown", "none", ""}:
        flags.append("Do not connect RAG to practice documents until permission sync and retrieval logging are verified.")
    agent_tools = lower_list(tool.get("agent_tools"))
    mcp_servers = lower_list(tool.get("mcp_servers"))
    autonomous = normalized(tool.get("autonomous_mode"))
    if (agent_tools or mcp_servers) and approval in {"none", "unknown", ""}:
        flags.append("Disable agent actions until least-privilege scopes and human approval gates are documented.")
    if (agent_tools or mcp_servers) and logging in {"none", "unknown", ""}:
        flags.append("Disable or limit agent tools until audit logging is available.")
    if mcp_servers and approval in {"none", "unknown", ""}:
        flags.append("Block MCP/tool-broker connections until each server is allowlisted and human-approved.")
    if autonomous in {"yes", "true", "full", "unsupervised"} and (
        agent_tools or mcp_servers or any(value in {"phi", "ephi", "claims", "audio", "clinical notes"} for value in data_types)
    ):
        flags.append("Disable unsupervised autonomous mode for PHI or tool-using agents until human-in-the-loop gates exist.")
    if clinical and not boolish(tool.get("clinician_review")):
        flags.append("Do not use in clinical workflow until clinician owner review is documented.")
    if boolish(tool.get("prescription_support")) and normalized(tool.get("state_policy_review")) not in {"documented", "complete"}:
        flags.append("Do not use for prescription support until state-policy and counsel review are complete.")
    if min(result.score for result in domains) == 0:
        flags.append("At least one governance domain scored 0; require owner review before approval.")

    return _unique(flags)


def risk_from_results(maturity_score: int, domains: list[DomainResult], critical_flags: list[str]) -> str:
    min_score = min(result.score for result in domains)
    if critical_flags:
        return "Critical"
    if min_score <= 1 or maturity_score < 45:
        return "High"
    if min_score == 2 or maturity_score < 75:
        return "Medium"
    return "Low"


def render_report(report: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output_format == "csv":
        return render_csv(report)
    if output_format == "markdown":
        return render_markdown(report)
    raise ValueError(f"unsupported format: {output_format}")


def render_markdown(report: dict[str, Any]) -> str:
    metadata = report["metadata"]
    summary = report["summary"]
    decision_counts = summary.get("decision_counts") or {}
    lines = [
        "# HealthAI Audit Report",
        "",
        f"- Practice: {metadata['practice']}",
        f"- Generated: {metadata['generated_at_utc']}",
        f"- Method: {metadata.get('method', '')}",
        f"- Tool count: {summary['tool_count']}",
        f"- Average maturity score: {summary['average_maturity_score']}/100",
        f"- Risk counts: Critical {summary['risk_counts']['Critical']}, High {summary['risk_counts']['High']}, Medium {summary['risk_counts']['Medium']}, Low {summary['risk_counts']['Low']}",
    ]
    if decision_counts:
        lines.append(
            f"- Decisions: block {decision_counts.get('block', 0)}, restrict {decision_counts.get('restrict', 0)}, "
            f"approve_with_conditions {decision_counts.get('approve_with_conditions', 0)}, "
            f"approve {decision_counts.get('approve', 0)}"
        )
        lines.append(f"- Portfolio decision: {summary.get('portfolio_decision', 'n/a')}")
    lines.extend(
        [
            "",
            "> Triage support only. This report is not legal, clinical, HIPAA, FDA, or security certification advice.",
            "> Raw inventory source fields are omitted by default to reduce accidental PHI leakage.",
            "",
            "## Priority Actions",
        ]
    )

    if summary["top_actions"]:
        lines.extend(f"- {item}" for item in summary["top_actions"])
    else:
        lines.append("- No high-priority actions were generated from the provided inventory.")

    lines.extend(["", "## AI Tool Risk Cards"])
    for assessment in report["assessments"]:
        lines.extend(
            [
                "",
                f"### {assessment['name']}",
                "",
                f"- Vendor: {assessment['vendor']}",
                f"- Workflow: {assessment['workflow']}",
                f"- Risk level: {assessment['risk_level']}",
                f"- Maturity score: {assessment['maturity_score']}/100",
            ]
        )
        if assessment.get("decision"):
            lines.append(f"- Decision: **{assessment['decision']}**")
        if assessment.get("rule_ids"):
            lines.append(f"- Rule IDs: {', '.join(assessment['rule_ids'])}")
        if assessment.get("evidence_status"):
            ev = assessment["evidence_status"]
            lines.append(
                f"- Evidence: {ev.get('status', 'n/a')} "
                f"(active={ev.get('active_count', 0)}, covering={ev.get('covering_count', 0)})"
            )
        if assessment.get("evidence_refs"):
            lines.append("- Evidence refs:")
            for ref in assessment["evidence_refs"][:5]:
                lines.append(
                    f"  - `{ref.get('id')}` · {ref.get('kind')} · `{ref.get('path')}` · "
                    f"reviewed {ref.get('reviewed_on') or 'n/a'}"
                )
        if assessment["critical_flags"]:
            lines.append("- Critical flags:")
            lines.extend(f"  - {flag}" for flag in assessment["critical_flags"])
        lines.append("")
        lines.append("| Domain | Score | Gaps | Actions |")
        lines.append("| --- | ---: | --- | --- |")
        for domain_result in assessment["domain_results"]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(domain_result["name"]),
                        str(domain_result["score"]),
                        _cell("; ".join(domain_result["gaps"]) or "No major gap recorded."),
                        _cell("; ".join(domain_result["actions"]) or "Maintain evidence."),
                    ]
                )
                + " |"
            )

    lines.extend(
        [
            "",
            "## Evidence To Collect",
            "",
            "- Signed BAA or documented non-PHI rationale for every vendor touching PHI.",
            "- Vendor answers for training/product-improvement data use, retention, deletion, subprocessors, and security contact.",
            "- RAG permission-sync evidence, retrieval logs, and prompt-injection test results where applicable.",
            "- Agent/MCP tool manifest with scopes, allowlisted servers, approval gates, autonomous-mode setting, and audit logs.",
            "- Clinical safety case, clinician owner approval, and evaluation results for clinical or patient-facing tools.",
            "- FDA/medical-device analysis and state-policy review where workflows support diagnosis, treatment, prescribing, triage, or multi-state care.",
            "",
            "## Framework Anchors",
            "",
            "- NIST AI RMF: Govern, Map, Measure, Manage.",
            "- HHS HIPAA Security Rule: administrative, physical, and technical safeguards for ePHI.",
            "- HHS HPH CPGs: access management, vendor/supplier cybersecurity, incident planning, and data protection.",
            "- OWASP LLM Top 10: prompt injection, sensitive disclosure, supply chain, excessive agency, vector/embedding weaknesses, misinformation.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_csv(report: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "name",
            "vendor",
            "workflow",
            "risk_level",
            "maturity_score",
            "decision",
            "rule_ids",
            "critical_flags",
            "priority_actions",
            "lowest_domain",
            "lowest_domain_score",
        ],
    )
    writer.writeheader()
    for assessment in report["assessments"]:
        domains = assessment.get("domain_results") or [{"name": "", "score": 0}]
        lowest = min(domains, key=lambda item: item["score"])
        writer.writerow(
            {
                "name": assessment["name"],
                "vendor": assessment["vendor"],
                "workflow": assessment["workflow"],
                "risk_level": assessment["risk_level"],
                "maturity_score": assessment["maturity_score"],
                "decision": assessment.get("decision", ""),
                "rule_ids": "; ".join(assessment.get("rule_ids") or []),
                "critical_flags": "; ".join(assessment["critical_flags"]),
                "priority_actions": "; ".join(assessment["high_priority_actions"]),
                "lowest_domain": lowest["name"],
                "lowest_domain_score": lowest["score"],
            }
        )
    return buffer.getvalue()


def validate_inventory(inventory: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    tools = inventory.get("tools")
    if not isinstance(tools, list) or not tools:
        return ["Inventory has no tools."]
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            warnings.append(f"tools[{index}] is not an object.")
            continue
        for field_name in ("name", "vendor", "workflow"):
            if not str(tool.get(field_name, "")).strip():
                warnings.append(f"tools[{index}] missing {field_name}.")
        if "PHI" in [str(item).upper() for item in as_list(tool.get("data_types"))] and normalized(tool.get("baa_status")) in {"", "unknown"}:
            warnings.append(f"{tool.get('name', f'tools[{index}]')}: PHI listed but BAA status is unknown.")
    return warnings


def domain(name: str, score: int, evidence: list[str], gaps: list[str], actions: list[str], mappings: list[str]) -> DomainResult:
    return DomainResult(name=name, score=max(0, min(4, score)), evidence=_unique(evidence), gaps=_unique(gaps), actions=_unique(actions), mappings=mappings)


def lower_list(value: Any) -> list[str]:
    return [str(item).strip().lower() for item in as_list(value) if str(item).strip()]


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        if not value.strip():
            return []
        if "," in value:
            return [item.strip() for item in value.split(",")]
    return [value]


def normalized(value: Any) -> str:
    return str(value if value is not None else "").strip().lower()


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return normalized(value) in {"yes", "true", "1", "y", "required", "documented", "complete", "current", "signed"}


def _assessment_to_dict(assessment: ToolAssessment) -> dict[str, Any]:
    return {
        "name": assessment.name,
        "vendor": assessment.vendor,
        "workflow": assessment.workflow,
        "risk_level": assessment.risk_level,
        "maturity_score": assessment.maturity_score,
        "critical_flags": assessment.critical_flags,
        "high_priority_actions": assessment.high_priority_actions,
        "data_types": assessment.data_types,
        "evidence_refs": assessment.evidence_refs,
        "evidence_status": assessment.evidence_status,
        "domain_results": [
            {
                "name": result.name,
                "score": result.score,
                "evidence": result.evidence,
                "gaps": result.gaps,
                "actions": result.actions,
                "mappings": result.mappings,
            }
            for result in assessment.domain_results
        ],
        "source": assessment.source,
    }


def _normalize_csv_row(row: dict[str, str]) -> dict[str, Any]:
    normalized_row: dict[str, Any] = {}
    for key, value in row.items():
        if value in {"true", "True", "yes", "Yes"}:
            normalized_row[key] = True
        elif value in {"false", "False", "no", "No"}:
            normalized_row[key] = False
        elif key in {
            "data_types",
            "model_types",
            "agent_tools",
            "mcp_servers",
            "evaluation_dimensions",
            "certifications",
        }:
            normalized_row[key] = [item.strip() for item in value.split(";") if item.strip()]
        elif key == "evidence_refs" and value.strip():
            # CSV cannot express full evidence objects; store path-only stubs.
            normalized_row[key] = [
                {"id": f"EVID-CSV-{i + 1:03d}", "kind": "other", "path": item.strip()}
                for i, item in enumerate(value.split(";"))
                if item.strip()
            ]
        else:
            normalized_row[key] = value
    return normalized_row


def _cell(value: Any) -> str:
    return str(value).replace("\n", " ").replace("\r", " ").replace("|", "\\|").strip()


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result
