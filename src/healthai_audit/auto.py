"""One-shot automated customer run.

  healthai-audit run inventory.json

Detects policy packs, scores, decides, writes owner packet + kit bridge,
and prints a short operator summary. No pack selection required.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from healthai_audit.audit import run_audit
from healthai_audit.packet import write_packet
from healthai_audit.packs import detect_pack, describe_pack


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
) -> dict[str, Any]:
    """Full automated pipeline. Returns result dict with paths + report summary."""
    # First pass uses run_audit which already embeds pack detection.
    report = run_audit(
        inventory_path,
        strict_safety=strict_safety,
        include_source=include_source,
        with_decisions=True,
    )
    practice = str((report.get("metadata") or {}).get("practice") or inventory_path.stem)
    target = out_dir or default_out_dir(inventory_path, practice)
    target.mkdir(parents=True, exist_ok=True)

    paths = write_packet(report, target, kit_bridge=True)

    # Persist full sanitized report for automation / re-diff.
    report_path = target / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["report_json"] = report_path

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
        "practice": practice,
        "report": report,
    }


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
        "",
        "## What the customer does next",
        "",
        "1. Open `owner-decision-packet.md` — act on **block** tools first.",
        "2. Send `vendor-followups.md` questions (no PHI).",
        "3. Drop `kit-bridge/` files into Small Practice Security Kit packet.",
        "4. After fixes, re-run `healthai-audit run inventory.json` and "
        "`healthai-audit diff old/report.json new/report.json`.",
        "",
        "## Tool decisions",
        "",
        "| Tool | Decision | Rules | Evidence |",
        "| --- | --- | --- | --- |",
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
                ]
            )
            + " |"
        )

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
