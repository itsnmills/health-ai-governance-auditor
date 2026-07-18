"""Command line interface for HealthAI Audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from healthai_audit.audit import load_inventory, render_report, run_audit, validate_inventory
from healthai_audit.diff import diff_reports, load_report_or_inventory, render_diff
from healthai_audit.kit_bridge import write_kit_bridge
from healthai_audit.packet import write_packet
from healthai_audit.safety import SafetyError, assert_inventory_safe, check_inventory_file
from healthai_audit.templates import TEMPLATES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="healthai-audit",
        description="Local-first AI governance auditor — automated packs, packets, and remediation.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run",
        help="ONE command: auto pack, score, decide, verify evidence, write packet+dashboard+remediation.",
    )
    run.add_argument("input", type=Path, help="Inventory JSON/CSV, or intake JSON with --from-intake.")
    run.add_argument("--out", type=Path, help="Output directory.")
    run.add_argument("--as-of", dest="as_of", help="Deterministic YYYY-MM-DD for review/remediation dates.")
    run.add_argument("--from-intake", action="store_true", help="Treat input as minimal intake and expand first.")
    run.add_argument("--no-verify-evidence", action="store_true", help="Skip local evidence path/hash checks.")
    run.add_argument("--allow-unsafe", action="store_true", help="Do not fail closed on safety findings.")
    run.add_argument("--json-summary", action="store_true", help="Print machine-readable summary JSON.")

    batch = subparsers.add_parser("batch", help="Run automated audit for every *.json in a directory.")
    batch.add_argument("input_dir", type=Path, help="Directory of inventory JSON files.")
    batch.add_argument("--out", type=Path, required=True, help="Batch output directory.")
    batch.add_argument("--as-of", dest="as_of", help="Deterministic YYYY-MM-DD.")
    batch.add_argument("--no-verify-evidence", action="store_true")
    batch.add_argument("--allow-unsafe", action="store_true")

    intake = subparsers.add_parser("intake", help="Expand minimal intake JSON into a full inventory.")
    intake.add_argument("input", type=Path, help="Minimal intake JSON.")
    intake.add_argument("--out", type=Path, help="Write expanded inventory JSON.")
    intake.add_argument("--run", action="store_true", help="Immediately run automated audit after expand.")
    intake.add_argument("--run-out", type=Path, help="Output dir when using --run.")
    intake.add_argument("--as-of", dest="as_of")
    intake.add_argument("--allow-unsafe", action="store_true")

    detect = subparsers.add_parser("detect-pack", help="Show auto-selected policy pack (no scoring).")
    detect.add_argument("input", type=Path)

    score = subparsers.add_parser("score", help="Score inventory and render a report.")
    score.add_argument("input", type=Path)
    score.add_argument("--format", choices=("markdown", "json", "csv"), default="markdown")
    score.add_argument("--out", type=Path)
    score.add_argument("--packet-dir", type=Path)
    score.add_argument("--as-of", dest="as_of")
    score.add_argument("--verify-evidence", action="store_true")
    score.add_argument("--include-source", action="store_true")
    score.add_argument("--allow-unsafe", action="store_true")

    packet = subparsers.add_parser("packet", help="Write owner/MSP decision packet (+ kit bridge).")
    packet.add_argument("input", type=Path)
    packet.add_argument("--out", type=Path, default=Path("reports/decision-packet"))
    packet.add_argument("--as-of", dest="as_of")
    packet.add_argument("--verify-evidence", action="store_true")
    packet.add_argument("--allow-unsafe", action="store_true")
    packet.add_argument("--no-kit-bridge", action="store_true")

    kit = subparsers.add_parser("kit-export", help="Write kit-bridge artifacts only.")
    kit.add_argument("input", type=Path)
    kit.add_argument("--out", type=Path, default=Path("reports/kit-bridge"))
    kit.add_argument("--allow-unsafe", action="store_true")

    diff = subparsers.add_parser("diff", help="Diff two inventories or reports by rule ID.")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--format", choices=("markdown", "json"), default="markdown")
    diff.add_argument("--out", type=Path)
    diff.add_argument("--allow-unsafe", action="store_true")

    safety = subparsers.add_parser("safety-check", help="Scan inventory for secrets/PHI-risk patterns.")
    safety.add_argument("input", type=Path)

    validate = subparsers.add_parser("validate", help="Validate inventory shape + unknown fields.")
    validate.add_argument("input", type=Path)
    validate.add_argument("--allow-unsafe", action="store_true")

    template = subparsers.add_parser("template", help="Write a starter template.")
    template.add_argument(
        "kind",
        choices=sorted(set(TEMPLATES) | {"intake"}),
        help="Template kind (includes intake).",
    )
    template.add_argument("--out", type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "run":
            from healthai_audit.auto import run_auto
            from healthai_audit.intake import expand_intake_file

            inventory_data = None
            input_path = args.input
            if args.from_intake:
                expanded, written = expand_intake_file(
                    args.input,
                    out=(args.out / "expanded-inventory.json") if args.out else args.input.with_suffix(".expanded.json"),
                )
                inventory_data = expanded
                if written:
                    input_path = written
            result = run_auto(
                input_path,
                out_dir=args.out,
                strict_safety=not args.allow_unsafe,
                as_of=args.as_of,
                verify_evidence=not args.no_verify_evidence,
                inventory_data=inventory_data,
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
                    f"  Remediation items: {result.get('remediation_items')}\n"
                    f"  Warnings: {len(result.get('warnings') or [])}\n"
                    f"  Output: {result.get('out_dir')}\n"
                    f"  Dashboard: {result.get('paths', {}).get('dashboard')}\n"
                    f"  Summary: {result.get('paths', {}).get('run_summary')}\n"
                )
            return 0

        if args.command == "batch":
            from healthai_audit.auto import run_batch

            index = run_batch(
                args.input_dir,
                out_dir=args.out,
                strict_safety=not args.allow_unsafe,
                as_of=args.as_of,
                verify_evidence=not args.no_verify_evidence,
            )
            sys.stdout.write(
                f"Batch complete: {index['ok']}/{index['count']} ok → {index['out_dir']}\n"
            )
            return 0 if index["failed"] == 0 else 1

        if args.command == "intake":
            from healthai_audit.auto import run_auto
            from healthai_audit.intake import expand_intake_file

            inventory, written = expand_intake_file(args.input, out=args.out)
            if written:
                sys.stdout.write(f"Expanded inventory written: {written}\n")
            else:
                sys.stdout.write(json.dumps(inventory, indent=2) + "\n")
            if args.run:
                path = written or args.input
                result = run_auto(
                    path,
                    out_dir=args.run_out,
                    strict_safety=not args.allow_unsafe,
                    as_of=args.as_of,
                    inventory_data=inventory if not written else None,
                )
                sys.stdout.write(
                    f"Auto run complete: {result.get('portfolio_decision')} → {result.get('out_dir')}\n"
                )
            return 0

        if args.command == "detect-pack":
            from healthai_audit.auto import preview_pack

            sys.stdout.write(json.dumps(preview_pack(args.input), indent=2) + "\n")
            return 0

        if args.command == "score":
            report = run_audit(
                args.input,
                strict_safety=not args.allow_unsafe,
                include_source=args.include_source,
                with_decisions=True,
                as_of=args.as_of,
                verify_evidence=args.verify_evidence,
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
                as_of=args.as_of,
                verify_evidence=args.verify_evidence,
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
            write_output(render_diff(result, args.format), args.out)
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
            from healthai_audit.schema import inventory_warnings

            inventory = load_inventory(args.input)
            if not args.allow_unsafe:
                assert_inventory_safe(args.input, inventory, strict=True)
            warnings = validate_inventory(inventory) + inventory_warnings(inventory)
            if warnings:
                sys.stdout.write("\n".join(f"WARN {item}" for item in warnings) + "\n")
                return 1
            sys.stdout.write("OK inventory is valid enough to score.\n")
            return 0

        if args.command == "template":
            if args.kind == "intake":
                from healthai_audit.intake import intake_template

                write_output(intake_template(), args.out)
            else:
                write_output(TEMPLATES[args.kind](), args.out)
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
