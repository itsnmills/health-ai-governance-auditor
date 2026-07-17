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
        run([sys.executable, "-m", "healthai_audit", "safety-check", "samples/sample_inventory.json"])
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert report["summary"]["tool_count"] == 4
        assert report["summary"]["risk_counts"]["Critical"] >= 1
        assert report["summary"]["portfolio_decision"] in {"block", "restrict", "approve_with_conditions", "approve"}
        assert "source" not in report["assessments"][0]
        assert report["assessments"][0].get("decision")
        assert "HealthAI Audit Report" in (out / "report.md").read_text(encoding="utf-8")
        assert "decision" in (out / "report.csv").read_text(encoding="utf-8")
        assert (out / "packet" / "owner-decision-packet.md").is_file()
        assert (out / "packet" / "action-queue.csv").is_file()
    print("HealthAI Audit verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
