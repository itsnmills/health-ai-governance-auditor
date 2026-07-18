"""Remediation plan with owners and due dates (automated).

Derives due dates from decision severity + optional inventory remediation_defaults
or per-tool remediation_due / owner fields.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any


DEFAULT_SLA = {
    "block": 14,
    "restrict": 30,
    "approve_with_conditions": 45,
    "approve": 90,
}


def attach_remediation_plan(
    report: dict[str, Any],
    inventory: dict[str, Any] | None = None,
    *,
    as_of: str | None = None,
) -> dict[str, Any]:
    inventory = inventory or {}
    defaults = inventory.get("remediation_defaults") if isinstance(inventory.get("remediation_defaults"), dict) else {}
    sla = {
        "block": int(defaults.get("block_days", DEFAULT_SLA["block"])),
        "restrict": int(defaults.get("restrict_days", DEFAULT_SLA["restrict"])),
        "approve_with_conditions": int(
            defaults.get("approve_with_conditions_days", DEFAULT_SLA["approve_with_conditions"])
        ),
        "approve": int(defaults.get("approve_days", DEFAULT_SLA["approve"])),
    }
    start = _parse_date(as_of) or _parse_date(str((report.get("metadata") or {}).get("review_date", ""))) or date.today()

    # Map tool -> owner / due override from inventory if available
    tool_meta: dict[str, dict[str, Any]] = {}
    for tool in inventory.get("tools") or []:
        if isinstance(tool, dict) and tool.get("name"):
            tool_meta[str(tool["name"]).lower()] = tool

    plan: list[dict[str, Any]] = []
    for assessment in report.get("assessments") or []:
        decision = str(assessment.get("decision", "restrict"))
        name = str(assessment.get("name", ""))
        meta = tool_meta.get(name.lower(), {})
        owner = str(meta.get("owner") or _default_owner(decision, assessment))
        due_override = str(meta.get("remediation_due") or "").strip()
        if due_override and _parse_date(due_override):
            due = due_override
        else:
            days = sla.get(decision, 30)
            due = (start + timedelta(days=days)).isoformat()

        for rule_id in assessment.get("rule_ids") or ["HA-RISK-MED"]:
            plan.append(
                {
                    "tool": name,
                    "vendor": assessment.get("vendor", ""),
                    "decision": decision,
                    "rule_id": rule_id,
                    "owner": owner,
                    "due_date": due,
                    "priority": _priority(decision),
                    "title": _rule_title(report, rule_id, assessment),
                    "sla_days": sla.get(decision, 30),
                }
            )

    plan.sort(key=lambda row: (_priority_rank(str(row["priority"])), str(row["due_date"]), str(row["tool"])))

    # Enrich action_queue rows with due dates when present
    queue = []
    due_by_key = {(p["tool"], p["rule_id"]): p for p in plan}
    for row in report.get("action_queue") or []:
        enriched = dict(row)
        key = (str(row.get("tool", "")), str(row.get("rule_id", "")))
        match = due_by_key.get(key)
        if match:
            enriched["due_date"] = match["due_date"]
            enriched["priority"] = match["priority"]
            if not enriched.get("owner"):
                enriched["owner"] = match["owner"]
        queue.append(enriched)

    report["action_queue"] = queue
    report["remediation_plan"] = plan
    summary = dict(report.get("summary") or {})
    summary["remediation_items"] = len(plan)
    summary["remediation_due_next_14_days"] = sum(
        1 for p in plan if _within_days(p["due_date"], start, 14) and p["decision"] != "approve"
    )
    report["summary"] = summary
    meta = dict(report.get("metadata") or {})
    meta["remediation_as_of"] = start.isoformat()
    meta["remediation_sla"] = sla
    report["metadata"] = meta
    return report


def render_remediation_markdown(report: dict[str, Any]) -> str:
    plan = report.get("remediation_plan") or []
    lines = [
        "# Remediation Plan",
        "",
        f"- As of: {(report.get('metadata') or {}).get('remediation_as_of', '')}",
        f"- Items: {len(plan)}",
        f"- Due in 14 days (non-approve): {(report.get('summary') or {}).get('remediation_due_next_14_days', 0)}",
        "",
        "| Due | Priority | Decision | Tool | Rule | Owner | Title |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in plan:
        if row.get("decision") == "approve" and not (row.get("rule_id") or "").startswith("HA-EVID"):
            continue
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row.get("due_date", "")),
                    str(row.get("priority", "")),
                    str(row.get("decision", "")),
                    str(row.get("tool", "")),
                    str(row.get("rule_id", "")),
                    str(row.get("owner", "")),
                    str(row.get("title", "")).replace("|", "/"),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def _default_owner(decision: str, assessment: dict[str, Any]) -> str:
    if decision == "block":
        return "Practice owner / MSP"
    if "CLIN" in " ".join(assessment.get("rule_ids") or []):
        return "Clinical owner"
    if "MSP" in " ".join(assessment.get("rule_ids") or []) or "PACK-MSP" in " ".join(
        assessment.get("rule_ids") or []
    ):
        return "MSP Lead"
    return "Practice manager"


def _priority(decision: str) -> str:
    return {
        "block": "P0",
        "restrict": "P1",
        "approve_with_conditions": "P2",
        "approve": "P3",
    }.get(decision, "P2")


def _priority_rank(priority: str) -> int:
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(priority, 9)


def _rule_title(report: dict[str, Any], rule_id: str, assessment: dict[str, Any]) -> str:
    catalog = report.get("rule_catalog") or {}
    if rule_id in catalog:
        return str(catalog[rule_id].get("title", rule_id))
    for reason in assessment.get("decision_reasons") or []:
        return str(reason)
    return rule_id


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value.strip()[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _within_days(due: str, start: date, days: int) -> bool:
    d = _parse_date(due)
    if not d:
        return False
    return start <= d <= start + timedelta(days=days)
