"""Owner / MSP decision packet exports.

Produces reviewer-safe artifacts for handoff into Small Practice Security Kit
or local evidence binders. Never includes raw inventory source objects.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any


def write_packet(report: dict[str, Any], out_dir: Path, *, kit_bridge: bool = True) -> dict[str, Path]:
    """Write a local decision packet directory. Returns written paths."""
    from healthai_audit.kit_bridge import write_kit_bridge

    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "owner_packet": out_dir / "owner-decision-packet.md",
        "action_queue": out_dir / "action-queue.csv",
        "decisions_json": out_dir / "decisions.json",
        "vendor_questions": out_dir / "vendor-followups.md",
    }
    paths["owner_packet"].write_text(render_owner_packet(report), encoding="utf-8")
    paths["action_queue"].write_text(render_action_csv(report), encoding="utf-8")
    paths["decisions_json"].write_text(
        json.dumps(_packet_json(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths["vendor_questions"].write_text(render_vendor_followups(report), encoding="utf-8")
    if kit_bridge:
        kit_dir = out_dir / "kit-bridge"
        kit_paths = write_kit_bridge(report, kit_dir)
        for name, path in kit_paths.items():
            paths[f"kit_{name}"] = path
    return paths


def render_owner_packet(report: dict[str, Any]) -> str:
    metadata = report.get("metadata", {})
    summary = report.get("summary", {})
    decisions = summary.get("decision_counts", {})
    lines = [
        "# AI Tool Owner Decision Packet",
        "",
        f"- Practice: {metadata.get('practice', 'Unspecified practice')}",
        f"- Review owner: {metadata.get('review_owner', '') or 'Not set'}",
        f"- Review date: {metadata.get('review_date', '') or 'Not set'}",
        f"- Generated: {metadata.get('generated_at_utc', '')}",
        f"- Method: {metadata.get('method', '')}",
        f"- Portfolio decision: **{summary.get('portfolio_decision', 'unknown')}**",
        "",
        "> Triage support only. Not legal, clinical, HIPAA, FDA, or security certification advice.",
        "> This packet is PHI-avoidant by design: raw inventory source fields are not included.",
        "> Approve for PHI tools requires evidence refs (path/hash/date only).",
        "",
        "## Portfolio Summary",
        "",
        f"- Tools reviewed: {summary.get('tool_count', 0)}",
        f"- Risk counts: {summary.get('risk_counts', {})}",
        f"- Decisions: block {decisions.get('block', 0)}, restrict {decisions.get('restrict', 0)}, "
        f"approve_with_conditions {decisions.get('approve_with_conditions', 0)}, approve {decisions.get('approve', 0)}",
        f"- Evidence: sufficient={summary.get('evidence_sufficient_tools', 0)}, "
        f"PHI tools needing evidence={summary.get('evidence_missing_tools', 0)}",
        f"- Blocking rules: {', '.join(summary.get('blocking_rule_ids') or []) or 'None'}",
        "",
        "## Tool Decisions",
        "",
        "| Tool | Vendor | Risk | Decision | Evidence | Rule IDs | Top reason |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in report.get("assessments", []):
        reasons = item.get("decision_reasons") or []
        top_reason = reasons[0] if reasons else "—"
        ev = (item.get("evidence_status") or {}).get("status", "n/a")
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("name")),
                    _cell(item.get("vendor")),
                    _cell(item.get("risk_level")),
                    _cell(item.get("decision")),
                    _cell(ev),
                    _cell(", ".join(item.get("rule_ids") or [])),
                    _cell(top_reason),
                ]
            )
            + " |"
        )

    lines.extend(["", "## Owner / MSP Action Queue", ""])
    queue = report.get("action_queue") or []
    if not queue:
        lines.append("- No open actions generated.")
    else:
        for row in queue[:40]:
            lines.append(
                f"- **{row.get('decision', '')}** · `{row.get('rule_id', '')}` · "
                f"{row.get('tool', '')}: {row.get('title', '')} "
                f"(owner: {row.get('owner', 'Practice manager')})"
            )

    lines.extend(
        [
            "",
            "## What to do next",
            "",
            "1. **Block** tools stay off until every listed rule is closed with evidence references (not PHI).",
            "2. **Restrict** tools may run only under documented limits (no PHI paste, human approval, limited MCP allowlist).",
            "3. **Approve with conditions** requires a dated remediation owner and review date.",
            "4. Feed kit-bridge outputs (`kit-bridge/ai-workflow-review.md`, `handoff-actions.csv`) into Small Practice Security Kit.",
            "5. Keep BAAs, contracts, and logs outside this packet — store evidence references only (path/hash/date).",
            "6. Re-run with `healthai-audit diff before.json after.json` after remediation to prove closed rules.",
            "",
            "## Evidence refs (paths only)",
            "",
        ]
    )
    any_refs = False
    for item in report.get("assessments", []):
        for ref in item.get("evidence_refs") or []:
            any_refs = True
            lines.append(
                f"- **{item.get('name')}** · `{ref.get('id')}` · {ref.get('kind')} · "
                f"`{ref.get('path')}` · reviewed {ref.get('reviewed_on') or 'n/a'}"
            )
    if not any_refs:
        lines.append("- None recorded.")
    lines.extend(
        [
            "",
            "## Boundaries",
            "",
            "- Not a HIPAA certification or formal Security Risk Analysis.",
            "- Not a breach determination or clinical safety approval.",
            "- Do not paste patient data, credentials, or private URLs into inventories or packets.",
            "",
        ]
    )
    return "\n".join(lines)


def render_action_csv(report: dict[str, Any]) -> str:
    buffer = io.StringIO()
    fieldnames = ["tool", "vendor", "decision", "rule_id", "title", "owner"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in report.get("action_queue") or []:
        writer.writerow({key: row.get(key, "") for key in fieldnames})
    return buffer.getvalue()


def render_vendor_followups(report: dict[str, Any]) -> str:
    lines = [
        "# Vendor Follow-up Questions",
        "",
        "Generated from inventory gaps. Send only non-PHI questions. Do not attach patient data.",
        "",
    ]
    for item in report.get("assessments", []):
        if item.get("decision") == "approve" and not item.get("critical_flags"):
            continue
        lines.append(f"## {item.get('name')} ({item.get('vendor')})")
        lines.append("")
        lines.append(f"- Current decision: **{item.get('decision')}**")
        lines.append(f"- Rule IDs: {', '.join(item.get('rule_ids') or []) or 'None'}")
        lines.append("")
        questions = _questions_for_assessment(item)
        if questions:
            lines.extend(f"- {q}" for q in questions)
        else:
            lines.append("- Confirm current BAA, training posture, retention, subprocessors, and security contact.")
        lines.append("")
    if len(lines) <= 4:
        lines.append("No vendor follow-ups required from the current inventory.")
        lines.append("")
    return "\n".join(lines)


def _questions_for_assessment(item: dict[str, Any]) -> list[str]:
    questions: list[str] = []
    rule_ids = set(item.get("rule_ids") or [])
    mapping = {
        "HA-BAA-001": "Provide current BAA status and the named privacy/security contact for breach notification.",
        "HA-TRAIN-001": "Confirm whether prompts, files, audio, outputs, or logs are used for training or product improvement, and how to opt out.",
        "HA-RAG-001": "Document how retrieval respects source permissions and which folders/systems are excluded by default.",
        "HA-AGENT-001": "List every agent tool, required scopes, and the human approval gate for high-impact actions.",
        "HA-AGENT-002": "Provide sample audit-log fields for tool calls (user, tool, timestamp, approval, destination class).",
        "HA-MCP-001": "Inventory MCP/tool-broker servers, default allowlist, and customer disable controls.",
        "HA-AUTO-001": "Confirm autonomous mode defaults and how unsupervised actions are disabled for PHI workflows.",
        "HA-CLIN-001": "Name the clinical owner and review process before any patient-care use.",
        "HA-RX-001": "Provide state-policy / counsel review status for any prescription-support features.",
    }
    for rule_id, question in mapping.items():
        if rule_id in rule_ids:
            questions.append(question)
    # Domain gaps as secondary questions (short).
    for domain in item.get("domain_results") or []:
        for gap in (domain.get("gaps") or [])[:2]:
            q = f"Address gap ({domain.get('name')}): {gap}"
            if q not in questions:
                questions.append(q)
    return questions[:10]


def _packet_json(report: dict[str, Any]) -> dict[str, Any]:
    """Machine-readable packet without raw sources or oversized catalogs."""
    return {
        "metadata": report.get("metadata", {}),
        "summary": report.get("summary", {}),
        "assessments": [
            {
                "name": item.get("name"),
                "vendor": item.get("vendor"),
                "workflow": item.get("workflow"),
                "risk_level": item.get("risk_level"),
                "maturity_score": item.get("maturity_score"),
                "decision": item.get("decision"),
                "rule_ids": item.get("rule_ids"),
                "decision_reasons": item.get("decision_reasons"),
                "critical_flags": item.get("critical_flags"),
                "high_priority_actions": item.get("high_priority_actions"),
                "data_types": item.get("data_types"),
                "evidence_refs": item.get("evidence_refs"),
                "evidence_status": item.get("evidence_status"),
            }
            for item in report.get("assessments", [])
        ],
        "action_queue": report.get("action_queue", []),
    }


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("\n", " ").replace("|", "\\|").strip()
