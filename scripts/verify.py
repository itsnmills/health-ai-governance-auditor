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
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert report["summary"]["tool_count"] == 3
        assert report["summary"]["risk_counts"]["Critical"] >= 1
        assert "HealthAI Audit Report" in (out / "report.md").read_text(encoding="utf-8")
        assert "risk_level" in (out / "report.csv").read_text(encoding="utf-8")
    print("HealthAI Audit verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
