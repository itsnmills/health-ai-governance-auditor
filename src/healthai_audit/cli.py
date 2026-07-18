"""Command line interface for HealthAI Audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from healthai_audit.audit import render_report, run_audit, validate_inventory, load_inventory
from healthai_audit.diff import diff_reports, load_report_or_inventory, render_diff
from healthai_audit.kit_bridge import write_kit_bridge
from healthai_audit.packet import write_packet
from healthai_audit.safety import SafetyError, assert_inventory_safe, check_inventory_file
from healthai_audit.templates import TEMPLATES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="healthai-audit",
        description="Local-first AI governance and vendor-risk auditor for healthcare practices.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run",
        help="ONE command for customers: auto-detect policy pack, score, decide, write full packet + kit bridge.",
    )
    run.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")
    run.add_argument(
        "--out",
        type=Path,
        help="Output directory (default: reports/auto-<practice>-<timestamp>).",
    )
    run.add_argument(
        "--allow-unsafe",
        action="store_true",
        help="Do not fail closed on safety findings (not recommended).",
    )
    run.add_argument(
        "--json-summary",
        action="store_true",
        help="Print machine-readable run summary JSON to stdout.",
    )

    detect = subparsers.add_parser(
        "detect-pack",
        help="Show which policy pack would be auto-selected (no scoring).",
    )
    detect.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")

    score = subparsers.add_parser("score", help="Score an AI tool inventory and render a report.")
    score.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")
    score.add_argument("--format", choices=("markdown", "json", "csv"), default="markdown", help="Report format.")
    score.add_argument("--out", type=Path, help="Optional output path. Prints to stdout when omitted.")
    score.add_argument(
        "--packet-dir",
        type=Path,
        help="Write owner decision packet + kit-bridge artifacts to this directory.",
    )
    score.add_argument(
        "--include-source",
        action="store_true",
        help="Include redacted inventory source objects in JSON output (off by default for safety).",
    )
    score.add_argument(
        "--allow-unsafe",
        action="store_true",
        help="Do not fail closed on safety findings (not recommended).",
    )

    packet = subparsers.add_parser(
        "packet",
        help="Score inventory and write a PHI-avoidant owner/MSP decision packet (+ kit bridge).",
    )
    packet.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")
    packet.add_argument(
        "--out",
        type=Path,
        default=Path("reports/decision-packet"),
        help="Packet output directory (default: reports/decision-packet).",
    )
    packet.add_argument(
        "--allow-unsafe",
        action="store_true",
        help="Do not fail closed on safety findings (not recommended).",
    )
    packet.add_argument(
        "--no-kit-bridge",
        action="store_true",
        help="Skip Small Practice Security Kit bridge exports.",
    )

    kit = subparsers.add_parser(
        "kit-export",
        help="Score inventory and write only kit-bridge artifacts (ai-workflow-review + handoff CSV).",
    )
    kit.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")
    kit.add_argument(
        "--out",
        type=Path,
        default=Path("reports/kit-bridge"),
        help="Output directory (default: reports/kit-bridge).",
    )
    kit.add_argument(
        "--allow-unsafe",
        action="store_true",
        help="Do not fail closed on safety findings (not recommended).",
    )

    diff = subparsers.add_parser(
        "diff",
        help="Diff two inventories or decision reports by tool name and rule ID.",
    )
    diff.add_argument("before", type=Path, help="Earlier inventory JSON or decisions/report JSON.")
    diff.add_argument("after", type=Path, help="Later inventory JSON or decisions/report JSON.")
    diff.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Diff output format.")
    diff.add_argument("--out", type=Path, help="Optional output path.")
    diff.add_argument(
        "--allow-unsafe",
        action="store_true",
        help="Do not fail closed on safety findings when inputs are inventories.",
    )

    safety = subparsers.add_parser("safety-check", help="Scan an inventory for secrets/PHI-risk patterns without scoring.")
    safety.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")

    validate = subparsers.add_parser("validate", help="Validate inventory shape and required fields.")
    validate.add_argument("input", type=Path, help="Path to inventory JSON or CSV.")
    validate.add_argument(
        "--allow-unsafe",
        action="store_true",
        help="Skip fail-closed safety checks (not recommended).",
    )

    template = subparsers.add_parser("template", help="Write a starter template.")
    template.add_argument("kind", choices=sorted(TEMPLATES), help="Template kind.")
    template.add_argument("--out", type=Path, help="Optional output path. Prints to stdout when omitted.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "run":
            from healthai_audit.auto import run_auto

            result = run_auto(
                args.input,
                out_dir=args.out,
                strict_safety=not args.allow_unsafe,
            )
            if args.json_summary:
                payload = {k: v for k, v in result.items() if k != "report"}
                sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            else:
                pack = result.get("policy_pack") or {}
                sys.stdout.write(
                    "Automated HealthAI Audit complete.\n"
                    f"  Practice: {result.get('practice')}\n"
                    f"  Policy pack (auto): {pack.get('label', 'n/a')}\n"
                    f"  Why: {'; '.join(pack.get('reasons') or []) or 'n/a'}\n"
                    f"  Portfolio decision: {result.get('portfolio_decision')}\n"
                    f"  Tools: {result.get('tool_count')}\n"
                    f"  Output: {result.get('out_dir')}\n"
                    f"  Start here: {result.get('paths', {}).get('run_summary')}\n"
                )
            return 0

        if args.command == "detect-pack":
            from healthai_audit.auto import preview_pack

            info = preview_pack(args.input)
            sys.stdout.write(json.dumps(info, indent=2) + "\n")
            return 0

        if args.command == "score":
            report = run_audit(
                args.input,
                strict_safety=not args.allow_unsafe,
                include_source=args.include_source,
                with_decisions=True,
            )
            output = render_report(report, args.format)
            write_output(output, args.out)
            if args.packet_dir:
                paths = write_packet(report, args.packet_dir, kit_bridge=True)
                sys.stderr.write(
                    "Wrote decision packet:\n"
                    + "\n".join(f"  {name}: {path}" for name, path in paths.items())
                    + "\n"
                )
            return 0

        if args.command == "packet":
            report = run_audit(
                args.input,
                strict_safety=not args.allow_unsafe,
                include_source=False,
                with_decisions=True,
            )
            paths = write_packet(report, args.out, kit_bridge=not args.no_kit_bridge)
            sys.stdout.write(
                "Decision packet written:\n"
                + "\n".join(f"  {name}: {path}" for name, path in paths.items())
                + "\n"
            )
            return 0

        if args.command == "kit-export":
            report = run_audit(
                args.input,
                strict_safety=not args.allow_unsafe,
                include_source=False,
                with_decisions=True,
            )
            paths = write_kit_bridge(report, args.out)
            sys.stdout.write(
                "Kit bridge written:\n"
                + "\n".join(f"  {name}: {path}" for name, path in paths.items())
                + "\n"
            )
            return 0

        if args.command == "diff":
            before = load_report_or_inventory(args.before, strict_safety=not args.allow_unsafe)
            after = load_report_or_inventory(args.after, strict_safety=not args.allow_unsafe)
            result = diff_reports(before, after)
            output = render_diff(result, args.format)
            write_output(output, args.out)
            return 0

        if args.command == "safety-check":
            findings = check_inventory_file(args.input)
            if args.input.suffix.lower() in {".json", ".csv"} and args.input.is_file():
                try:
                    inventory = load_inventory(args.input)
                    findings = assert_inventory_safe(args.input, inventory, strict=False)
                except Exception as exc:
                    sys.stdout.write(f"FAIL parse: {exc}\n")
                    return 1
            if findings:
                for item in findings:
                    where = f" @ {item.path}" if item.path else ""
                    sys.stdout.write(f"FAIL {item.code}{where}: {item.message}\n")
                return 1
            sys.stdout.write("OK inventory passed local safety checks.\n")
            return 0

        if args.command == "validate":
            inventory = load_inventory(args.input)
            if not args.allow_unsafe:
                assert_inventory_safe(args.input, inventory, strict=True)
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
    except SafetyError as exc:
        sys.stderr.write("healthai-audit: safety check failed (fail closed):\n")
        for item in exc.findings[:20]:
            where = f" @ {item.path}" if item.path else ""
            sys.stderr.write(f"  - {item.code}{where}: {item.message}\n")
        sys.stderr.write("Remove secrets/PHI/free-text notes, or pass --allow-unsafe (not recommended).\n")
        return 2
    except Exception as exc:
        parser.exit(1, f"healthai-audit: error: {exc}\n")

    parser.error("unknown command")
    return 2


def write_output(output: str, out: Path | None) -> None:
    if out:
        out = out.expanduser()
        if out.exists() and out.is_dir():
            raise ValueError(f"--out must be a file path, not a directory: {out}")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
