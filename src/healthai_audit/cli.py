"""Command line interface for HealthAI Audit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from healthai_audit.audit import audit_inventory, load_inventory, render_report, validate_inventory
from healthai_audit.templates import TEMPLATES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="healthai-audit",
        description="Local-first AI governance and vendor-risk auditor for healthcare practices.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    score = subparsers.add_parser("score", help="Score an AI tool inventory and render a report.")
    score.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")
    score.add_argument("--format", choices=("markdown", "json", "csv"), default="markdown", help="Report format.")
    score.add_argument("--out", type=Path, help="Optional output path. Prints to stdout when omitted.")

    validate = subparsers.add_parser("validate", help="Validate inventory shape and required fields.")
    validate.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")

    template = subparsers.add_parser("template", help="Write a starter template.")
    template.add_argument("kind", choices=sorted(TEMPLATES), help="Template kind.")
    template.add_argument("--out", type=Path, help="Optional output path. Prints to stdout when omitted.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "score":
            inventory = load_inventory(args.input)
            report = audit_inventory(inventory)
            output = render_report(report, args.format)
            write_output(output, args.out)
            return 0

        if args.command == "validate":
            inventory = load_inventory(args.input)
            warnings = validate_inventory(inventory)
            if warnings:
                sys.stdout.write("\n".join(f"WARN {item}" for item in warnings) + "\n")
                return 1
            sys.stdout.write("OK inventory is valid enough to score.\n")
            return 0

        if args.command == "template":
            output = TEMPLATES[args.kind]()
            write_output(output, args.out)
            return 0
    except Exception as exc:
        parser.exit(1, f"healthai-audit: error: {exc}\n")

    parser.error("unknown command")
    return 2


def write_output(output: str, out: Path | None) -> None:
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
