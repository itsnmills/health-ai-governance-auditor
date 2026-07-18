"""Dependency-free HTML dashboard for automated run outputs."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def write_dashboard(report: dict[str, Any], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_dashboard_html(report), encoding="utf-8")
    return out_path


def render_dashboard_html(report: dict[str, Any]) -> str:
    meta = report.get("metadata") or {}
    summary = report.get("summary") or {}
    pack = meta.get("policy_pack") or {}
    decisions = summary.get("decision_counts") or {}
    portfolio = html.escape(str(summary.get("portfolio_decision", "n/a")))
    practice = html.escape(str(meta.get("practice", "")))
    pack_label = html.escape(str(pack.get("label", "n/a")))
    method = html.escape(str(meta.get("method", "")))
    generated = html.escape(str(meta.get("generated_at_utc", "")))
    warnings = report.get("warnings") or []

    rows = []
    for item in report.get("assessments") or []:
        decision = str(item.get("decision", ""))
        cls = {
            "block": "bad",
            "restrict": "warn",
            "approve_with_conditions": "warn",
            "approve": "ok",
        }.get(decision, "")
        rules = ", ".join(item.get("rule_ids") or [])
        ev = (item.get("evidence_status") or {}).get("status", "n/a")
        ver = (item.get("evidence_verification") or {}).get("verification_status", "n/a")
        rows.append(
            "<tr class='{cls}'>"
            "<td>{name}</td><td>{vendor}</td><td><span class='pill {cls}'>{decision}</span></td>"
            "<td>{risk}</td><td>{ev}</td><td>{ver}</td><td class='mono'>{rules}</td>"
            "</tr>".format(
                cls=html.escape(cls),
                name=html.escape(str(item.get("name", ""))),
                vendor=html.escape(str(item.get("vendor", ""))),
                decision=html.escape(decision),
                risk=html.escape(str(item.get("risk_level", ""))),
                ev=html.escape(str(ev)),
                ver=html.escape(str(ver)),
                rules=html.escape(rules),
            )
        )

    warn_html = ""
    if warnings:
        warn_html = "<section><h2>Warnings</h2><ul>" + "".join(
            f"<li>{html.escape(str(w))}</li>" for w in warnings[:40]
        ) + "</ul></section>"

    action_rows = []
    for row in (report.get("action_queue") or [])[:50]:
        action_rows.append(
            "<tr><td class='mono'>{rule}</td><td>{tool}</td><td>{decision}</td>"
            "<td>{owner}</td><td>{title}</td><td>{due}</td></tr>".format(
                rule=html.escape(str(row.get("rule_id", ""))),
                tool=html.escape(str(row.get("tool", ""))),
                decision=html.escape(str(row.get("decision", ""))),
                owner=html.escape(str(row.get("owner", ""))),
                title=html.escape(str(row.get("title", ""))[:160]),
                due=html.escape(str(row.get("due_date", row.get("remediation_due", "")))),
            )
        )

    embedded = html.escape(json.dumps({
        "practice": meta.get("practice"),
        "portfolio_decision": summary.get("portfolio_decision"),
        "policy_pack": pack,
        "decision_counts": decisions,
        "tool_count": summary.get("tool_count"),
    }, indent=2))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>HealthAI Audit — {practice}</title>
  <style>
    :root {{
      --bg:#0b1220; --card:#121a2b; --text:#e7eefc; --muted:#9db0d0;
      --ok:#3dd68c; --warn:#f5c542; --bad:#ff6b6b; --line:#243047;
      --accent:#6ea8fe;
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background:radial-gradient(1200px 600px at 10% -10%, #1a2744, var(--bg));
      color:var(--text); line-height:1.45; padding:24px;
    }}
    h1,h2 {{ margin:0 0 12px; }}
    .muted {{ color:var(--muted); }}
    .grid {{ display:grid; gap:16px; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); margin:18px 0 24px; }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:16px; }}
    .stat {{ font-size:28px; font-weight:700; }}
    .pill {{ display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:700; text-transform:uppercase; }}
    .pill.ok {{ background:rgba(61,214,140,.15); color:var(--ok); }}
    .pill.warn {{ background:rgba(245,197,66,.15); color:var(--warn); }}
    .pill.bad {{ background:rgba(255,107,107,.15); color:var(--bad); }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }}
    th, td {{ border-bottom:1px solid var(--line); padding:10px 8px; text-align:left; vertical-align:top; }}
    th {{ color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
    tr.bad td:first-child {{ box-shadow: inset 3px 0 0 var(--bad); }}
    tr.warn td:first-child {{ box-shadow: inset 3px 0 0 var(--warn); }}
    tr.ok td:first-child {{ box-shadow: inset 3px 0 0 var(--ok); }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }}
    header {{ display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; align-items:flex-start; }}
    .brand {{ color:var(--accent); font-weight:700; letter-spacing:.04em; font-size:12px; text-transform:uppercase; }}
    footer {{ margin-top:28px; color:var(--muted); font-size:12px; }}
    pre {{ background:#0a101c; border:1px solid var(--line); border-radius:12px; padding:12px; overflow:auto; }}
  </style>
</head>
<body>
  <header>
    <div>
      <div class="brand">HealthAI Audit · Velari</div>
      <h1>{practice}</h1>
      <div class="muted">{method}</div>
      <div class="muted">Generated {generated}</div>
    </div>
    <div class="card">
      <div class="muted">Portfolio decision</div>
      <div class="stat"><span class="pill {html.escape({'block':'bad','restrict':'warn','approve_with_conditions':'warn','approve':'ok'}.get(str(summary.get('portfolio_decision')),''))}">{portfolio}</span></div>
      <div class="muted" style="margin-top:8px">Auto pack: <strong>{pack_label}</strong></div>
    </div>
  </header>

  <div class="grid">
    <div class="card"><div class="muted">Tools</div><div class="stat">{html.escape(str(summary.get('tool_count', 0)))}</div></div>
    <div class="card"><div class="muted">Block</div><div class="stat" style="color:var(--bad)">{html.escape(str(decisions.get('block', 0)))}</div></div>
    <div class="card"><div class="muted">Restrict</div><div class="stat" style="color:var(--warn)">{html.escape(str(decisions.get('restrict', 0)))}</div></div>
    <div class="card"><div class="muted">Conditional</div><div class="stat" style="color:var(--warn)">{html.escape(str(decisions.get('approve_with_conditions', 0)))}</div></div>
    <div class="card"><div class="muted">Approve</div><div class="stat" style="color:var(--ok)">{html.escape(str(decisions.get('approve', 0)))}</div></div>
    <div class="card"><div class="muted">Evidence problems</div><div class="stat">{html.escape(str(summary.get('evidence_verification_problems', 0)))}</div></div>
  </div>

  <section class="card">
    <h2>Tool decisions</h2>
    <table>
      <thead><tr><th>Tool</th><th>Vendor</th><th>Decision</th><th>Risk</th><th>Evidence</th><th>Verify</th><th>Rules</th></tr></thead>
      <tbody>
        {''.join(rows) or '<tr><td colspan="7">No tools</td></tr>'}
      </tbody>
    </table>
  </section>

  <section class="card" style="margin-top:16px">
    <h2>Action queue (top 50)</h2>
    <table>
      <thead><tr><th>Rule</th><th>Tool</th><th>Decision</th><th>Owner</th><th>Action</th><th>Due</th></tr></thead>
      <tbody>
        {''.join(action_rows) or '<tr><td colspan="6">No actions</td></tr>'}
      </tbody>
    </table>
  </section>

  {warn_html}

  <section class="card" style="margin-top:16px">
    <h2>Embedded summary JSON</h2>
    <pre class="mono">{embedded}</pre>
  </section>

  <footer>
    Triage support only. Not legal, clinical, HIPAA, FDA, or certification advice.
    Local-first · PHI-avoidant · automated policy packs.
  </footer>
</body>
</html>
"""
