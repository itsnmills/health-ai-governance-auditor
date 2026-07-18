"""Optional local evidence verification (binary presence + hash only).

Never opens files as text, never OCRs, never parses PDF content.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
MAX_HASH_BYTES = 50 * 1024 * 1024  # 50 MiB cap for local hashing


def verify_evidence_refs(
    assessment: dict[str, Any],
    *,
    base_dir: Path | None = None,
    verify_hashes: bool = True,
) -> dict[str, Any]:
    """Attach verification results onto a copy of evidence_status."""
    refs = assessment.get("evidence_refs") or []
    base = base_dir or Path.cwd()
    results: list[dict[str, Any]] = []
    present = 0
    missing = 0
    mismatch = 0
    skipped = 0

    for ref in refs:
        if not isinstance(ref, dict):
            continue
        path_raw = str(ref.get("path", "")).strip()
        entry: dict[str, Any] = {
            "id": ref.get("id", ""),
            "path": path_raw,
            "status": "unverified",
        }
        if not path_raw:
            entry["status"] = "missing_path"
            missing += 1
            results.append(entry)
            continue
        # Relative only; refuse absolute and parent escapes.
        if path_raw.startswith("/") or ".." in Path(path_raw).parts:
            entry["status"] = "unsafe_path"
            missing += 1
            results.append(entry)
            continue
        full = (base / path_raw).resolve()
        try:
            # Ensure resolved path stays under base when possible
            full.relative_to(base.resolve())
        except ValueError:
            entry["status"] = "unsafe_path"
            missing += 1
            results.append(entry)
            continue

        if not full.is_file():
            entry["status"] = "missing_file"
            missing += 1
            results.append(entry)
            continue

        present += 1
        expected = str(ref.get("sha256", "")).strip()
        if expected and verify_hashes:
            if not SHA256_RE.match(expected):
                entry["status"] = "invalid_hash_format"
                mismatch += 1
            else:
                digest = _sha256_file(full)
                if digest is None:
                    entry["status"] = "hash_skipped_too_large"
                    skipped += 1
                elif digest.lower() == expected.lower():
                    entry["status"] = "present_hash_ok"
                else:
                    entry["status"] = "hash_mismatch"
                    mismatch += 1
                entry["sha256_observed"] = digest
        else:
            entry["status"] = "present"

        results.append(entry)

    status = "none"
    if refs:
        if missing == 0 and mismatch == 0:
            status = "verified" if present else "none"
        elif present and (missing or mismatch):
            status = "partial"
        elif missing and not present:
            status = "missing"
        elif mismatch:
            status = "mismatch"
        else:
            status = "partial"

    return {
        "verification_status": status,
        "present": present,
        "missing": missing,
        "mismatch": mismatch,
        "skipped": skipped,
        "results": results,
    }


def attach_evidence_verification(
    report: dict[str, Any],
    *,
    base_dir: Path | None = None,
    verify_hashes: bool = True,
) -> dict[str, Any]:
    """Mutate report assessments with evidence_verification blocks."""
    verified_tools = 0
    problem_tools = 0
    for assessment in report.get("assessments", []):
        block = verify_evidence_refs(assessment, base_dir=base_dir, verify_hashes=verify_hashes)
        assessment["evidence_verification"] = block
        if block["verification_status"] in {"verified", "none"} and block["mismatch"] == 0 and block["missing"] == 0:
            if block["present"]:
                verified_tools += 1
        elif block["missing"] or block["mismatch"]:
            problem_tools += 1
            # Soft flag for packet visibility (does not re-score risk level).
            flags = list(assessment.get("critical_flags") or [])
            msg = (
                f"Evidence verification issues: missing={block['missing']}, "
                f"mismatch={block['mismatch']} (local path/hash check)."
            )
            if msg not in flags:
                flags.append(msg)
            assessment["critical_flags"] = flags
    summary = dict(report.get("summary") or {})
    summary["evidence_verified_tools"] = verified_tools
    summary["evidence_verification_problems"] = problem_tools
    report["summary"] = summary
    return report


def _sha256_file(path: Path) -> str | None:
    size = path.stat().st_size
    if size > MAX_HASH_BYTES:
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
