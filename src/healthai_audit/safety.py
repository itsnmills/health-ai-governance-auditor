"""Local safety checks for inventories and reports.

HealthAI Audit is local-first and PHI-avoidant. This module fails closed when
an inventory looks like it contains secrets or patient-identifying content,
and strips raw source objects from reports by default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# Conservative size/shape limits to avoid accidental huge dumps or DoS-ish inputs.
MAX_INVENTORY_BYTES = 2 * 1024 * 1024
MAX_TOOLS = 500
MAX_STRING_CHARS = 8_000
MAX_LIST_ITEMS = 200

# Patterns that should never appear in a governance inventory.
# These are intentionally high-precision; free-text clinical notes are also blocked.
SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("generic_api_key", re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

# Free-text fields that often accumulate accidental PHI when users dump notes.
HIGH_RISK_TEXT_KEYS = {
    "notes",
    "note",
    "comments",
    "comment",
    "description",
    "patient",
    "patients",
    "clinical_notes",
    "prompt",
    "prompts",
    "transcript",
    "raw",
    "example_prompt",
    "sample_output",
}


@dataclass(frozen=True)
class SafetyFinding:
    code: str
    message: str
    path: str = ""


class SafetyError(ValueError):
    """Raised when an inventory fails closed for safety reasons."""

    def __init__(self, findings: list[SafetyFinding]) -> None:
        self.findings = findings
        lines = "; ".join(f"{item.code}: {item.message}" for item in findings[:8])
        super().__init__(lines or "inventory failed safety checks")


def check_inventory_file(path: Path) -> list[SafetyFinding]:
    """Validate an inventory file before parsing."""
    findings: list[SafetyFinding] = []
    if not path.exists():
        return [SafetyFinding("file_missing", f"Inventory file not found: {path}")]
    if not path.is_file():
        return [SafetyFinding("not_a_file", f"Inventory path is not a regular file: {path}")]
    size = path.stat().st_size
    if size > MAX_INVENTORY_BYTES:
        findings.append(
            SafetyFinding(
                "file_too_large",
                f"Inventory exceeds {MAX_INVENTORY_BYTES} bytes ({size} bytes). Split or redact before scoring.",
                str(path),
            )
        )
    # Read as text for pattern scan; binary garbage is rejected.
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [SafetyFinding("not_utf8", "Inventory must be UTF-8 text (JSON or CSV).")]
    findings.extend(scan_text_for_secrets(text, path=str(path)))
    return findings


def check_inventory_data(inventory: dict[str, Any]) -> list[SafetyFinding]:
    """Validate parsed inventory structure and content."""
    findings: list[SafetyFinding] = []
    tools = inventory.get("tools")
    if not isinstance(tools, list):
        return [SafetyFinding("invalid_tools", "Inventory tools must be a list.")]
    if len(tools) > MAX_TOOLS:
        findings.append(
            SafetyFinding(
                "too_many_tools",
                f"Inventory has {len(tools)} tools; max is {MAX_TOOLS}.",
            )
        )
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            findings.append(SafetyFinding("tool_not_object", f"tools[{index}] is not an object.", f"tools[{index}]"))
            continue
        findings.extend(_scan_value(tool, path=f"tools[{index}]"))
    findings.extend(_scan_value({k: v for k, v in inventory.items() if k != "tools"}, path="inventory"))
    return findings


def scan_text_for_secrets(text: str, path: str = "") -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []
    for code, pattern in SENSITIVE_PATTERNS:
        if pattern.search(text):
            findings.append(
                SafetyFinding(
                    code,
                    f"Possible {code.replace('_', ' ')} pattern detected. Remove secrets/PHI and use synthetic examples only.",
                    path,
                )
            )
    return findings


def assert_inventory_safe(path: Path, inventory: dict[str, Any], *, strict: bool = True) -> list[SafetyFinding]:
    """Run file + data checks. Raise SafetyError when strict and findings exist."""
    findings = check_inventory_file(path) + check_inventory_data(inventory)
    # De-dupe by code+path+message
    unique: list[SafetyFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for item in findings:
        key = (item.code, item.path, item.message)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    if strict and unique:
        raise SafetyError(unique)
    return unique


def sanitize_report(report: dict[str, Any], *, include_source: bool = False) -> dict[str, Any]:
    """Return a report copy safe for sharing / automation.

    By default, raw inventory source objects are stripped so free-text notes
    cannot be re-exported into packets.
    """
    sanitized = {
        "metadata": dict(report.get("metadata", {})),
        "summary": dict(report.get("summary", {})),
        "assessments": [],
    }
    for assessment in report.get("assessments", []):
        item = {k: v for k, v in assessment.items() if k != "source"}
        if include_source:
            source = assessment.get("source")
            if isinstance(source, dict):
                item["source"] = _redact_source(source)
            else:
                item["source"] = source
        sanitized["assessments"].append(item)
    return sanitized


def _redact_source(source: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in source.items():
        key_l = str(key).lower()
        if key_l in HIGH_RISK_TEXT_KEYS:
            redacted[key] = "[redacted: free-text field omitted]"
            continue
        if isinstance(value, str) and len(value) > 500:
            redacted[key] = value[:200] + "…[truncated]"
            continue
        if isinstance(value, str) and scan_text_for_secrets(value):
            redacted[key] = "[redacted: sensitive pattern]"
            continue
        redacted[key] = value
    return redacted


def _scan_value(value: Any, path: str, depth: int = 0) -> list[SafetyFinding]:
    if depth > 8:
        return [SafetyFinding("nesting_too_deep", "Inventory nesting exceeds safe depth.", path)]
    findings: list[SafetyFinding] = []
    if isinstance(value, dict):
        if len(value) > MAX_LIST_ITEMS:
            findings.append(SafetyFinding("object_too_large", f"Object at {path} has too many keys.", path))
        for key, child in value.items():
            key_l = str(key).lower()
            child_path = f"{path}.{key}" if path else str(key)
            if key_l in HIGH_RISK_TEXT_KEYS and isinstance(child, str) and child.strip():
                findings.append(
                    SafetyFinding(
                        "free_text_risk",
                        f"Field '{key}' contains free text. Use controlled enums/flags only — no notes, prompts, or clinical text.",
                        child_path,
                    )
                )
            findings.extend(_scan_value(child, child_path, depth + 1))
        return findings
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            findings.append(SafetyFinding("list_too_large", f"List at {path} exceeds {MAX_LIST_ITEMS} items.", path))
        for index, child in enumerate(value[: MAX_LIST_ITEMS + 1]):
            findings.extend(_scan_value(child, f"{path}[{index}]", depth + 1))
        return findings
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            findings.append(
                SafetyFinding(
                    "string_too_long",
                    f"String at {path} exceeds {MAX_STRING_CHARS} characters. Inventories should use short controlled values.",
                    path,
                )
            )
        findings.extend(scan_text_for_secrets(value, path=path))
    return findings
