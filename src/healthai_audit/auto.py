"""One-shot automated customer run.

  healthai-audit run inventory.json

Detects policy packs, scores, decides, verifies evidence refs (optional),
writes owner packet + kit bridge + dashboard + remediation plan.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from healthai_audit.audit import run_audit
from healthai_audit.dashboard import write_dashboard
from healthai_audit.packet import write_packet
from healthai_audit.remediation import render_remediation_markdown


def default_out_dir(inventory_path: Path, practice: str = "") -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = _slug(practice) if practice else inventory_path.stem
    return Path("reports") / f"auto-{slug}-{stamp}"


def run_auto(
    inventory_path: Path,
    *,
    out_dir: Path | None = None,
    strict_safety: bool = True,
    include_source: bool = False,
    as_of: str | None = None,
    verify_evidence: bool = True,
    inventory_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Full automated pipeline. Returns result dict with paths + report summary."""
    report = run_audit(
        inventory_path,
        strict_safety=strict_safety,
        include_source=include_source,
        with_decisions=True,
        as_of=as_of,
        verify_evidence=verify_evidence,
        evidence_base_dir=inventory_path.parent if inventory_path else Path.cwd(),
        inventory_data=inventory_data,
    )
    practice = str((report.get("metadata") or {}).get("practice") or inventory_path.stem)
    target = out_dir or default_out_dir(inventory_path, practice)
    target.mkdir(parents=True, exist_ok=True)

    paths = write_packet(report, target, kit_bridge=True)

    report_path = target / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["report_json"] = report_path

    dash_path = write_dashboard(report, target / "dashboard.html")
    paths["dashboard"] = dash_path

    rem_path = target / "remediation-plan.md"
    rem_path.write_text(render_remediation_markdown(report), encoding="utf-8")
    paths["remediation_plan"] = rem_path

    if report.get("warnings"):
        warn_path = target / "warnings.txt"
        warn_path.write_text("\n".join(str(w) for w in report["warnings"]) + "\n", encoding="utf-8")
        paths["warnings"] = warn_path

    summary_md = render_auto_summary(report, paths)
    summary_path = target / "RUN_SUMMARY.md"
    summary_path.write_text(summary_md, encoding="utf-8")
    paths["run_summary"] = summary_path

    pack_meta = (report.get("metadata") or {}).get("policy_pack") or {}
    return {
        "out_dir": str(target),
        "paths": {k: str(v) for k, v in paths.items()},
        "portfolio_decision": (report.get("summary") or {}).get("portfolio_decision"),
        "tool_count": (report.get("summary") or {}).get("tool_count"),
        "decision_counts": (report.get("summary") or {}).get("decision_counts"),
        "policy_pack": pack_meta,
        "warnings": report.get("warnings") or [],
        "remediation_items": (report.get("summary") or {}).get("remediation_items", 0),
        "practice": practice,
        "report": report,
    }


def run_batch(
    input_dir: Path,
    *,
    out_dir: Path,
    strict_safety: bool = True,
    as_of: str | None = None,
    verify_evidence: bool = True,
) -> dict[str, Any]:
    """Run auto pipeline for every *.json inventory in a directory."""
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for path in sorted(input_dir.glob("*.json")):
        if path.name.startswith("."):
            continue
        child = out_dir / path.stem
        try:
            result = run_auto(
                path,
                out_dir=child,
                strict_safety=strict_safety,
                as_of=as_of,
                verify_evidence=verify_evidence,
            )
            results.append(
                {
                    "input": str(path),
                    "ok": True,
                    "out_dir": result["out_dir"],
                    "portfolio_decision": result["portfolio_decision"],
                    "policy_pack": (result.get("policy_pack") or {}).get("label"),
                }
            )
        except Exception as exc:
            results.append({"input": str(path), "ok": False, "error": str(exc)})
    index = {
        "batch_dir": str(input_dir),
        "out_dir": str(out_dir),
        "count": len(results),
        "ok": sum(1 for r in results if r.get("ok")),
        "failed": sum(1 for r in results if not r.get("ok")),
        "results": results,
    }
    (out_dir / "BATCH_INDEX.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Batch HealthAI Audit",
        "",
        f"- Inputs: {index['count']}",
        f"- OK: {index['ok']}",
        f"- Failed: {index['failed']}",
        "",
    ]
    for row in results:
        if row.get("ok"):
            lines.append(
                f"- OK `{row['input']}` → **{row.get('portfolio_decision')}** "
                f"({row.get('policy_pack')}) → `{row.get('out_dir')}`"
            )
        else:
            lines.append(f"- FAIL `{row['input']}`: {row.get('error')}")
    lines.append("")
    (out_dir / "BATCH_INDEX.md").write_text("\n".join(lines), encoding="utf-8")
    return index


def render_auto_summary(report: dict[str, Any], paths: dict[str, Path]) -> str:
    meta = report.get("metadata") or {}
    summary = report.get("summary") or {}
    pack = meta.get("policy_pack") or {}
    decisions = summary.get("decision_counts") or {}
    lines = [
        "# Automated HealthAI Audit Run",
        "",
        f"- Practice: **{meta.get('practice', '')}**",
        f"- Generated: {meta.get('generated_at_utc', '')}",
        f"- Method: {meta.get('method', '')}",
        f"- Policy pack (auto): **{pack.get('label', 'n/a')}**",
        f"- Pack reasons: {'; '.join(pack.get('reasons') or []) or 'n/a'}",
        f"- Portfolio decision: **{summary.get('portfolio_decision', 'n/a')}**",
        f"- Tools: {summary.get('tool_count', 0)}",
        (
            f"- Decisions: block {decisions.get('block', 0)}, "
            f"restrict {decisions.get('restrict', 0)}, "
            f"approve_with_conditions {decisions.get('approve_with_conditions', 0)}, "
            f"approve {decisions.get('approve', 0)}"
        ),
        f"- Remediation items: {summary.get('remediation_items', 0)} "
        f"(due ≤14d: {summary.get('remediation_due_next_14_days', 0)})",
        f"- Evidence verification problems: {summary.get('evidence_verification_problems', 0)}",
        f"- Warnings: {len(report.get('warnings') or [])}",
        "",
        "## What the customer does next",
        "",
        "1. Open `dashboard.html` for the visual summary.",
        "2. Open `owner-decision-packet.md` — act on **block** tools first.",
        "3. Use `remediation-plan.md` for owners + due dates.",
        "4. Send `vendor-followups.md` (no PHI).",
        "5. Drop `kit-bridge/` into Small Practice Security Kit.",
        "6. After fixes: `healthai-audit run inventory.json` then "
        "`healthai-audit diff old/report.json new/report.json`.",
        "",
        "## Tool decisions",
        "",
        "| Tool | Decision | Rules | Evidence | Verify |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report.get("assessments") or []:
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("name")),
                    _cell(item.get("decision")),
                    _cell(", ".join(item.get("rule_ids") or [])),
                    _cell((item.get("evidence_status") or {}).get("status", "n/a")),
                    _cell((item.get("evidence_verification") or {}).get("verification_status", "n/a")),
                ]
            )
            + " |"
        )

    if report.get("warnings"):
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {w}" for w in report["warnings"][:30])

    lines.extend(["", "## Artifacts", ""])
    for name, path in paths.items():
        lines.append(f"- `{name}`: `{path}`")
    lines.extend(
        [
            "",
            "> Automated triage only. Not legal, clinical, HIPAA, FDA, or certification advice.",
            "",
        ]
    )
    return "\n".join(lines)


def preview_pack(inventory_path: Path) -> dict[str, Any]:
    """Detect pack without full scoring (for dry-run / UX)."""
    from healthai_audit.audit import load_inventory
    from healthai_audit.packs import describe_pack, detect_pack
    from healthai_audit.safety import assert_inventory_safe

    inventory = load_inventory(inventory_path)
    assert_inventory_safe(inventory_path, inventory, strict=True)
    selection = detect_pack(inventory)
    return describe_pack(selection)


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return text[:48] or "practice"


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()
