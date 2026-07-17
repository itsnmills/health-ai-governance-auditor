"""Diff two HealthAI Audit runs by tool name and rule ID.

Supports:
  - two inventory files (re-scored deterministically)
  - two decisions.json / report JSON files
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from healthai_audit.audit import run_audit
from healthai_audit.decisions import DECISION_RANK


def load_report_or_inventory(
    path: Path,
    *,
    strict_safety: bool = True,
) -> dict[str, Any]:
    """Load a prior report JSON or score an inventory into a decision report."""
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    if isinstance(data, dict) and "assessments" in data and "summary" in data:
        # Already a report / decisions.json
        return data
    # Treat as inventory path via normal audit pipeline
    return run_audit(path, strict_safety=strict_safety, include_source=False, with_decisions=True)


def diff_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two decision reports. Keys tools by lowercased name."""
    before_map = _tool_map(before)
    after_map = _tool_map(after)

    before_names = set(before_map)
    after_names = set(after_map)

    tools_added = sorted(after_names - before_names)
    tools_removed = sorted(before_names - after_names)
    shared = sorted(before_names & after_names)

    closed_rules: list[dict[str, str]] = []
    new_rules: list[dict[str, str]] = []
    unchanged_rules: list[dict[str, str]] = []
    decision_changes: list[dict[str, str]] = []
    evidence_changes: list[dict[str, str]] = []

    for name in shared:
        b = before_map[name]
        a = after_map[name]
        b_rules = set(b.get("rule_ids") or [])
        a_rules = set(a.get("rule_ids") or [])
        for rule_id in sorted(b_rules - a_rules):
            closed_rules.append({"tool": b["name"], "rule_id": rule_id})
        for rule_id in sorted(a_rules - b_rules):
            new_rules.append({"tool": a["name"], "rule_id": rule_id})
        for rule_id in sorted(b_rules & a_rules):
            unchanged_rules.append({"tool": a["name"], "rule_id": rule_id})

        b_dec = str(b.get("decision", ""))
        a_dec = str(a.get("decision", ""))
        if b_dec != a_dec:
            decision_changes.append(
                {
                    "tool": a["name"],
                    "from": b_dec,
                    "to": a_dec,
                    "direction": _direction(b_dec, a_dec),
                }
            )

        b_ev = str((b.get("evidence_status") or {}).get("status", ""))
        a_ev = str((a.get("evidence_status") or {}).get("status", ""))
        if b_ev != a_ev:
            evidence_changes.append(
                {
                    "tool": a["name"],
                    "from": b_ev or "unknown",
                    "to": a_ev or "unknown",
                }
            )

    improved = sum(1 for row in decision_changes if row.get("direction") == "improved")
    regressed = sum(1 for row in decision_changes if row.get("direction") == "regressed")

    return {
        "metadata": {
            "before_practice": (before.get("metadata") or {}).get("practice"),
            "after_practice": (after.get("metadata") or {}).get("practice"),
            "before_generated": (before.get("metadata") or {}).get("generated_at_utc"),
            "after_generated": (after.get("metadata") or {}).get("generated_at_utc"),
            "before_portfolio": (before.get("summary") or {}).get("portfolio_decision"),
            "after_portfolio": (after.get("summary") or {}).get("portfolio_decision"),
        },
        "summary": {
            "tools_before": len(before_map),
            "tools_after": len(after_map),
            "tools_added": tools_added,
            "tools_removed": tools_removed,
            "rules_closed": len(closed_rules),
            "rules_new": len(new_rules),
            "rules_unchanged": len(unchanged_rules),
            "decision_improvements": improved,
            "decision_regressions": regressed,
            "net": "improved" if improved > regressed and len(new_rules) <= len(closed_rules) else (
                "regressed" if regressed > improved or len(new_rules) > len(closed_rules) else "mixed"
            ),
        },
        "closed_rules": closed_rules,
        "new_rules": new_rules,
        "unchanged_rules": unchanged_rules,
        "decision_changes": decision_changes,
        "evidence_changes": evidence_changes,
    }


def render_diff(diff: dict[str, Any], fmt: str = "markdown") -> str:
    if fmt == "json":
        return json.dumps(diff, indent=2, sort_keys=True) + "\n"
    if fmt != "markdown":
        raise ValueError(f"unsupported diff format: {fmt}")

    meta = diff.get("metadata", {})
    summary = diff.get("summary", {})
    lines = [
        "# HealthAI Audit Diff",
        "",
        f"- Before practice: {meta.get('before_practice')}",
        f"- After practice: {meta.get('after_practice')}",
        f"- Before portfolio: **{meta.get('before_portfolio')}**",
        f"- After portfolio: **{meta.get('after_portfolio')}**",
        f"- Net: **{summary.get('net')}**",
        f"- Rules closed: {summary.get('rules_closed')} · new: {summary.get('rules_new')} · unchanged: {summary.get('rules_unchanged')}",
        f"- Decision improvements: {summary.get('decision_improvements')} · regressions: {summary.get('decision_regressions')}",
        "",
        "## Tools added / removed",
        "",
    ]
    if summary.get("tools_added"):
        lines.extend(f"- Added: {name}" for name in summary["tools_added"])
    else:
        lines.append("- Added: none")
    if summary.get("tools_removed"):
        lines.extend(f"- Removed: {name}" for name in summary["tools_removed"])
    else:
        lines.append("- Removed: none")

    lines.extend(["", "## Closed rules (good)", ""])
    if diff.get("closed_rules"):
        for row in diff["closed_rules"]:
            lines.append(f"- `{row['rule_id']}` closed on **{row['tool']}**")
    else:
        lines.append("- None")

    lines.extend(["", "## New rules (regressions / newly detected)", ""])
    if diff.get("new_rules"):
        for row in diff["new_rules"]:
            lines.append(f"- `{row['rule_id']}` opened on **{row['tool']}**")
    else:
        lines.append("- None")

    lines.extend(["", "## Decision changes", ""])
    if diff.get("decision_changes"):
        for row in diff["decision_changes"]:
            lines.append(
                f"- **{row['tool']}**: {row['from']} → {row['to']} ({row.get('direction', '')})"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Evidence status changes", ""])
    if diff.get("evidence_changes"):
        for row in diff["evidence_changes"]:
            lines.append(f"- **{row['tool']}**: {row['from']} → {row['to']}")
    else:
        lines.append("- None")

    lines.append("")
    return "\n".join(lines)


def _tool_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in report.get("assessments", []):
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        out[name.lower()] = item
    return out


def _direction(before: str, after: str) -> str:
    b = DECISION_RANK.get(before, 9)
    a = DECISION_RANK.get(after, 9)
    if a < b:
        return "regressed"
    if a > b:
        return "improved"
    return "unchanged"
