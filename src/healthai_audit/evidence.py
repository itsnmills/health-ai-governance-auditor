"""Evidence references for evidence-bound approvals.

Evidence is reference-only: path/id/hash/date/kind — never document bodies,
PHI, credentials, or free-text clinical content.

An ``approve`` decision for PHI-touching tools requires at least one valid
non-expired evidence ref covering BAA/policy (or explicit non-PHI rationale).
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

from healthai_audit.safety import scan_text_for_secrets


ALLOWED_KINDS = {
    "baa",
    "policy",
    "audit_log_sample",
    "vendor_questionnaire",
    "training_opt_out",
    "clinician_signoff",
    "mcp_allowlist",
    "retention_policy",
    "soc2",
    "other",
}

# Kinds that satisfy the minimum evidence bar for PHI tool approval.
APPROVE_COVERING_KINDS = {"baa", "policy", "soc2", "training_opt_out", "clinician_signoff"}

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Local relative paths only — no schemes, no parent escapes.
SAFE_PATH_RE = re.compile(r"^(?!/)(?!.*\.\.)[A-Za-z0-9._\- /]+$")


def normalize_evidence_refs(raw: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Return (normalized refs, gap messages). Invalid entries are dropped with gaps."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], ["evidence_refs must be a list of reference objects."]

    refs: list[dict[str, Any]] = []
    gaps: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            gaps.append(f"evidence_refs[{index}] is not an object.")
            continue
        normalized, item_gaps = _normalize_one(item, index)
        gaps.extend(item_gaps)
        if normalized:
            refs.append(normalized)
    return refs, gaps


def evidence_status_for_tool(
    tool: dict[str, Any],
    evidence_refs: list[dict[str, Any]],
    evidence_gaps: list[str],
    *,
    review_date: str = "",
) -> dict[str, Any]:
    """Compute evidence sufficiency for approval gating."""
    data_types = [str(x).strip().lower() for x in _as_list(tool.get("data_types"))]
    touches_phi = any(v in {"phi", "ephi", "claims", "audio", "clinical notes"} for v in data_types)
    as_of = _parse_date(review_date) or date.today()

    active = [ref for ref in evidence_refs if not _is_expired(ref, as_of)]
    expired = [ref for ref in evidence_refs if _is_expired(ref, as_of)]
    covering = [ref for ref in active if ref.get("kind") in APPROVE_COVERING_KINDS]

    status = "missing"
    if covering:
        status = "sufficient"
    elif active:
        status = "partial"
    elif expired:
        status = "expired"
    elif evidence_refs:
        status = "partial"

    gaps = list(evidence_gaps)
    if expired:
        gaps.append(f"{len(expired)} evidence ref(s) expired on or before {as_of.isoformat()}.")
    if touches_phi and not covering:
        gaps.append(
            "PHI-touching tool lacks a non-expired evidence ref of kind baa/policy/soc2/"
            "training_opt_out/clinician_signoff."
        )

    return {
        "touches_phi": touches_phi,
        "status": status,
        "active_count": len(active),
        "expired_count": len(expired),
        "covering_count": len(covering),
        "gaps": _unique(gaps),
        "requires_evidence_for_approve": touches_phi,
        "approve_eligible": (not touches_phi) or bool(covering),
    }


def apply_evidence_to_decision(
    decision: str,
    rule_ids: list[str],
    reasons: list[str],
    evidence_status: dict[str, Any],
) -> tuple[str, list[str], list[str]]:
    """Downgrade approve when PHI evidence is insufficient.

    Returns (decision, rule_ids, reasons).
    """
    rule_ids = list(rule_ids)
    reasons = list(reasons)

    if evidence_status.get("expired_count", 0) and evidence_status.get("requires_evidence_for_approve"):
        if "HA-EVID-002" not in rule_ids:
            rule_ids.append("HA-EVID-002")
        reasons.append("One or more evidence refs are expired; refresh before relying on approval.")
        if decision == "approve":
            decision = "approve_with_conditions"

    if evidence_status.get("requires_evidence_for_approve") and not evidence_status.get("approve_eligible"):
        if "HA-EVID-001" not in rule_ids:
            rule_ids.append("HA-EVID-001")
        reasons.append(
            "PHI-touching tool cannot receive unconditional approve without evidence refs "
            "(BAA/policy/SOC2/training opt-out/clinician signoff + reviewed_on)."
        )
        if decision == "approve":
            decision = "approve_with_conditions"

    return decision, rule_ids, reasons


def _normalize_one(item: dict[str, Any], index: int) -> tuple[dict[str, Any] | None, list[str]]:
    gaps: list[str] = []
    # Reject free-text bodies
    for banned in ("notes", "note", "content", "body", "text", "summary", "description"):
        if str(item.get(banned, "")).strip():
            gaps.append(
                f"evidence_refs[{index}].{banned} is not allowed. Use path/id/hash/date only."
            )
            return None, gaps

    ref_id = str(item.get("id", "")).strip() or f"EVID-{index + 1:03d}"
    kind = str(item.get("kind", "other")).strip().lower()
    if kind not in ALLOWED_KINDS:
        gaps.append(f"evidence_refs[{index}].kind '{kind}' is not recognized; using 'other'.")
        kind = "other"

    path = str(item.get("path", "")).strip()
    if not path:
        gaps.append(f"evidence_refs[{index}] missing path (local relative path to evidence file).")
        return None, gaps
    if not SAFE_PATH_RE.match(path):
        gaps.append(
            f"evidence_refs[{index}].path must be a relative local path without '..' or schemes."
        )
        return None, gaps
    if scan_text_for_secrets(path):
        gaps.append(f"evidence_refs[{index}].path looks sensitive; use synthetic paths only.")
        return None, gaps

    sha = str(item.get("sha256", "")).strip()
    if sha and not SHA256_RE.match(sha):
        gaps.append(f"evidence_refs[{index}].sha256 must be 64 hex characters when provided.")
        sha = ""

    reviewed_on = str(item.get("reviewed_on", "")).strip()
    if reviewed_on and not DATE_RE.match(reviewed_on):
        gaps.append(f"evidence_refs[{index}].reviewed_on must be YYYY-MM-DD.")
        reviewed_on = ""

    expires_on = str(item.get("expires_on", "")).strip()
    if expires_on and not DATE_RE.match(expires_on):
        gaps.append(f"evidence_refs[{index}].expires_on must be YYYY-MM-DD.")
        expires_on = ""

    covers_rules = [str(x).strip().upper() for x in _as_list(item.get("covers_rules")) if str(x).strip()]

    return {
        "id": ref_id,
        "kind": kind,
        "path": path,
        "sha256": sha,
        "reviewed_on": reviewed_on,
        "expires_on": expires_on,
        "covers_rules": covers_rules,
    }, gaps


def _is_expired(ref: dict[str, Any], as_of: date) -> bool:
    expires = _parse_date(str(ref.get("expires_on", "")))
    if not expires:
        return False
    return expires < as_of


def _parse_date(value: str) -> date | None:
    value = (value or "").strip()
    if not DATE_RE.match(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        if not value.strip():
            return []
        if "," in value:
            return [part.strip() for part in value.split(",")]
        return [value]
    return [value]


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
