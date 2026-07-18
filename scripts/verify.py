#!/usr/bin/env python3
"""Run HealthAI Audit local verification without external services."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHONPATH = str(ROOT / "src")


def run(command: list[str]) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    if result.stdout.strip():
        print(result.stdout.strip())


def main() -> int:
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests"])
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        run([sys.executable, "-m", "healthai_audit", "score", "samples/sample_inventory.json", "--format", "markdown", "--out", str(out / "report.md")])
        run([sys.executable, "-m", "healthai_audit", "score", "samples/sample_inventory.json", "--format", "json", "--out", str(out / "report.json")])
        run([sys.executable, "-m", "healthai_audit", "score", "samples/sample_inventory.json", "--format", "csv", "--out", str(out / "report.csv")])
        run([sys.executable, "-m", "healthai_audit", "packet", "samples/sample_inventory.json", "--out", str(out / "packet")])
        run([sys.executable, "-m", "healthai_audit", "kit-export", "samples/sample_inventory.json", "--out", str(out / "kit")])
        run([
            sys.executable, "-m", "healthai_audit", "diff",
            "samples/sample_inventory.json",
            "samples/sample_inventory_remediated.json",
            "--format", "json",
            "--out", str(out / "diff.json"),
        ])
        run([sys.executable, "-m", "healthai_audit", "safety-check", "samples/sample_inventory.json"])
        run([sys.executable, "-m", "healthai_audit", "detect-pack", "samples/sample_dental_msp.json"])
        run([
            sys.executable, "-m", "healthai_audit", "run",
            "samples/sample_dental_msp.json",
            "--out", str(out / "auto-run"),
            "--json-summary",
        ])
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert report["summary"]["tool_count"] == 4
        assert report["summary"]["risk_counts"]["Critical"] >= 1
        assert report["summary"]["portfolio_decision"] in {"block", "restrict", "approve_with_conditions", "approve"}
        assert "source" not in report["assessments"][0]
        assert report["assessments"][0].get("decision")
        assert "evidence_status" in report["assessments"][0]
        assert "v0.4.0" in report["metadata"]["method"]
        assert report["metadata"].get("policy_pack", {}).get("auto") is True
        assert "HealthAI Audit Report" in (out / "report.md").read_text(encoding="utf-8")
        assert "decision" in (out / "report.csv").read_text(encoding="utf-8")
        assert (out / "packet" / "owner-decision-packet.md").is_file()
        assert (out / "packet" / "action-queue.csv").is_file()
        assert (out / "packet" / "kit-bridge" / "ai-workflow-review.md").is_file()
        assert (out / "kit" / "handoff-actions.csv").is_file()
        assert (out / "auto-run" / "RUN_SUMMARY.md").is_file()
        assert (out / "auto-run" / "kit-bridge" / "ai-workflow-review.md").is_file()
        auto_report = json.loads((out / "auto-run" / "report.json").read_text(encoding="utf-8"))
        assert "dental" in str(auto_report["metadata"]["policy_pack"]["label"])
        assert "multi_state" in auto_report["metadata"]["policy_pack"]["overlays"]
        assert "msp_managed" in auto_report["metadata"]["policy_pack"]["overlays"]
        diff = json.loads((out / "diff.json").read_text(encoding="utf-8"))
        assert diff["summary"]["rules_closed"] >= 1
    print("HealthAI Audit verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
