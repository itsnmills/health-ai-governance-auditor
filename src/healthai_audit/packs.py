"""Automated policy packs.

Customers do not pick packs. HealthAI Audit detects practice context from the
inventory and applies the matching pack + overlays automatically.

Detection uses only non-PHI practice profile fields and tool inventory signals
(names, workflows, flags) — never document bodies or patient data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Extra rules introduced by packs (stable public IDs).
PACK_RULES: dict[str, dict[str, str]] = {
    "HA-PACK-DENTAL-001": {
        "title": "Dental imaging / sensor AI without signed BAA",
        "decision": "block",
        "owner": "Practice owner / compliance",
    },
    "HA-PACK-DENTAL-002": {
        "title": "Ambient scribe in dental practice without clinician signoff evidence",
        "decision": "approve_with_conditions",
        "owner": "Clinical owner",
    },
    "HA-PACK-BH-001": {
        "title": "Behavioral-health sensitive workflow without clinician review",
        "decision": "block",
        "owner": "Clinical owner",
    },
    "HA-PACK-BH-002": {
        "title": "Behavioral-health PHI retention over 90 days without justification evidence",
        "decision": "restrict",
        "owner": "Practice manager / compliance",
    },
    "HA-PACK-MS-001": {
        "title": "Multi-state clinical/patient-facing tool without state-policy review",
        "decision": "block",
        "owner": "Clinical owner / counsel",
    },
    "HA-PACK-MSP-001": {
        "title": "MSP-managed agent tools without customer disable switch",
        "decision": "restrict",
        "owner": "MSP / practice owner",
    },
    "HA-PACK-MSP-002": {
        "title": "MSP-managed high-impact tools without complete audit logging",
        "decision": "block",
        "owner": "MSP / security",
    },
    "HA-PACK-GEN-001": {
        "title": "Patient-facing tool without escalation/refusal behavior",
        "decision": "restrict",
        "owner": "Practice manager",
    },
    "HA-PACK-GEN-002": {
        "title": "PHI SaaS tool without security contact",
        "decision": "approve_with_conditions",
        "owner": "Practice manager / compliance",
    },
    "HA-PACK-DENTAL-003": {
        "title": "Dental patient-facing scheduling AI without human approval",
        "decision": "block",
        "owner": "Office manager / MSP",
    },
    "HA-PACK-BH-003": {
        "title": "Behavioral-health patient-facing tool with training-on-customer-data unknown/yes",
        "decision": "block",
        "owner": "Practice owner / counsel",
    },
    "HA-PACK-MS-002": {
        "title": "Multi-state prescription-adjacent support without counsel review",
        "decision": "block",
        "owner": "Clinical owner / counsel",
    },
    "HA-PACK-MSP-003": {
        "title": "MSP-managed MCP servers without allowlist evidence",
        "decision": "restrict",
        "owner": "MSP / security",
    },
}


@dataclass(frozen=True)
class PackSelection:
    """Resolved pack stack for one automated run."""

    primary: str
    overlays: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    profile: dict[str, Any] = field(default_factory=dict)

    @property
    def pack_ids(self) -> list[str]:
        return [self.primary, *self.overlays]

    @property
    def label(self) -> str:
        if self.overlays:
            return f"{self.primary}+{'+'.join(self.overlays)}"
        return self.primary


def detect_pack(inventory: dict[str, Any]) -> PackSelection:
    """Auto-select primary pack + overlays from inventory signals."""
    profile = _normalize_profile(inventory)
    tools = [t for t in inventory.get("tools", []) if isinstance(t, dict)]
    blob = _signal_blob(inventory, tools, profile)

    reasons: list[str] = []
    primary = "general_small"

    # Explicit profile wins when valid.
    explicit = profile.get("type") or profile.get("practice_type") or ""
    if explicit in {"dental", "dental_small"}:
        primary = "dental_small"
        reasons.append("practice_profile.type=dental")
    elif explicit in {"behavioral", "behavioral_health", "mental_health", "therapy"}:
        primary = "behavioral_health"
        reasons.append(f"practice_profile.type={explicit}")
    elif explicit in {"specialty", "specialty_clinic"}:
        primary = "specialty_clinic"
        reasons.append("practice_profile.type=specialty")
    elif explicit in {"general", "general_small", "family", "primary_care"}:
        primary = "general_small"
        reasons.append(f"practice_profile.type={explicit or 'general'}")
    else:
        # Infer primary from name + tool signals.
        if any(tok in blob for tok in ("dental", "dentist", "orthodont", "oral surgery", "hygiene")):
            primary = "dental_small"
            reasons.append("inferred dental from practice/tool signals")
        elif any(
            tok in blob
            for tok in ("behavioral", "mental health", "therapy", "psychiatr", "counseling", "psycholog")
        ):
            primary = "behavioral_health"
            reasons.append("inferred behavioral health from practice/tool signals")
        elif any(tok in blob for tok in ("imaging", "pacs", "radiolog", "specialty", "derm", "ophthal")):
            primary = "specialty_clinic"
            reasons.append("inferred specialty/imaging from practice/tool signals")
        else:
            primary = "general_small"
            reasons.append("defaulted to general_small (no stronger signal)")

    overlays: list[str] = []
    states = profile.get("states") or []
    if isinstance(states, list) and len(states) > 1:
        overlays.append("multi_state")
        reasons.append(f"multi-state practice ({len(states)} states)")
    elif profile.get("multi_state") in {True, "true", "yes", "1"}:
        overlays.append("multi_state")
        reasons.append("practice_profile.multi_state=true")

    if profile.get("msp_managed") in {True, "true", "yes", "1"}:
        overlays.append("msp_managed")
        reasons.append("practice_profile.msp_managed=true")
    elif "msp" in str(inventory.get("review_owner", "")).lower():
        overlays.append("msp_managed")
        reasons.append("review_owner indicates MSP")

    # De-dupe overlays while preserving order.
    seen: set[str] = set()
    clean_overlays: list[str] = []
    for item in overlays:
        if item not in seen:
            seen.add(item)
            clean_overlays.append(item)

    return PackSelection(
        primary=primary,
        overlays=tuple(clean_overlays),
        reasons=tuple(reasons),
        profile=profile,
    )


def apply_pack_flags(
    assessment: dict[str, Any],
    selection: PackSelection,
    inventory: dict[str, Any],
) -> list[str]:
    """Return additional critical-flag strings for pack-specific policy.

    Flags are plain English (like core flags) so FLAG_TO_RULE / pack mapping can
    attach stable rule IDs in decisions.py.
    """
    flags: list[str] = []
    name = str(assessment.get("name", "")).lower()
    workflow = str(assessment.get("workflow", "")).lower()
    data_types = [str(x).lower() for x in (assessment.get("data_types") or [])]
    source: dict[str, Any] = {}
    if isinstance(assessment.get("source"), dict):
        source = assessment["source"]
    elif isinstance(assessment.get("control_snapshot"), dict):
        source = assessment["control_snapshot"]
    # Prefer live fields on assessment; fall back to source/control_snapshot.
    clinical = _bool(source.get("clinical_use")) or "clinical" in workflow
    patient_facing = _bool(source.get("patient_facing"))
    baa = str(source.get("baa_status", "")).strip().lower()
    clinician_review = _bool(source.get("clinician_review"))
    state_review = str(source.get("state_policy_review", "")).strip().lower()
    retention = source.get("retention_days")
    agent_tools = [str(x).lower() for x in _as_list(source.get("agent_tools"))]
    can_disable = _bool(source.get("customer_can_disable_tools"))
    logging = str(source.get("audit_logging", "")).strip().lower()
    training = str(source.get("customer_data_training", "")).strip().lower()
    escalation = str(source.get("escalation_behavior", "")).strip().lower()
    security_contact = str(source.get("security_contact", "")).strip()
    deployment = str(source.get("deployment_model", "")).strip().lower()
    approval = str(source.get("human_approval", "")).strip().lower()
    mcp_servers = [str(x).lower() for x in _as_list(source.get("mcp_servers"))]
    evidence_status = assessment.get("evidence_status") or {}
    covering = int(evidence_status.get("covering_count") or 0)
    evidence_kinds = {str(r.get("kind", "")).lower() for r in (assessment.get("evidence_refs") or []) if isinstance(r, dict)}

    touches_phi = any(v in {"phi", "ephi", "claims", "audio", "clinical notes"} for v in data_types)
    imaging_like = any(tok in name or tok in workflow for tok in ("imaging", "x-ray", "xray", "sensor", "pacs", "radiograph"))
    scribe_like = any(tok in name or tok in workflow for tok in ("scribe", "ambient", "dictation", "transcription"))
    sched_like = any(tok in name or tok in workflow for tok in ("schedul", "front desk", "appointment"))
    bh_sensitive = any(tok in name or tok in workflow for tok in ("therapy", "psych", "counsel", "behavioral", "mental"))
    high_impact = any(
        tok in t
        for t in agent_tools
        for tok in ("email", "ehr", "mcp", "browser", "shell", "sms", "billing", "webhook")
    )

    pack_ids = set(selection.pack_ids)

    # General automated hygiene (always-on base density).
    if patient_facing and escalation not in {"documented", "complete"}:
        flags.append("Patient-facing tool without escalation/refusal behavior (auto general pack).")
    if touches_phi and deployment in {"saas", "cloud", ""} and not security_contact:
        flags.append("PHI SaaS tool without security contact (auto general pack).")

    if "dental_small" in pack_ids:
        if imaging_like and touches_phi and baa not in {"signed", "current", "not applicable"}:
            flags.append("Dental imaging / sensor AI without signed BAA (auto dental pack).")
        if scribe_like and covering < 1:
            flags.append(
                "Ambient scribe in dental practice without clinician signoff / BAA evidence ref (auto dental pack)."
            )
        if (sched_like or patient_facing) and approval in {"none", "unknown", ""}:
            flags.append("Dental patient-facing scheduling AI without human approval (auto dental pack).")

    if "behavioral_health" in pack_ids:
        if (clinical or patient_facing or bh_sensitive or touches_phi) and not clinician_review:
            flags.append(
                "Behavioral-health sensitive workflow without clinician review (auto behavioral pack)."
            )
        if touches_phi:
            try:
                days = int(retention) if retention not in (None, "") else None
            except (TypeError, ValueError):
                days = None
            if days is not None and days > 90 and covering < 1:
                flags.append(
                    "Behavioral-health PHI retention over 90 days without justification evidence (auto behavioral pack)."
                )
        if patient_facing and training in {"yes", "true", "unknown", ""}:
            flags.append(
                "Behavioral-health patient-facing tool with training-on-customer-data unknown/yes (auto behavioral pack)."
            )

    if "multi_state" in pack_ids:
        if (clinical or patient_facing or _bool(source.get("prescription_support"))) and state_review not in {
            "documented",
            "complete",
            "not applicable",
        }:
            flags.append(
                "Multi-state clinical/patient-facing tool without state-policy review (auto multi-state pack)."
            )
        if _bool(source.get("prescription_support")) and state_review not in {"documented", "complete"}:
            flags.append(
                "Multi-state prescription-adjacent support without counsel review (auto multi-state pack)."
            )

    if "msp_managed" in pack_ids:
        if agent_tools and not can_disable:
            flags.append("MSP-managed agent tools without customer disable switch (auto MSP pack).")
        if high_impact and logging not in {"complete", "documented"}:
            flags.append(
                "MSP-managed high-impact tools without complete audit logging (auto MSP pack)."
            )
        if mcp_servers and "mcp_allowlist" not in evidence_kinds:
            flags.append("MSP-managed MCP servers without allowlist evidence (auto MSP pack).")

    if "specialty_clinic" in pack_ids:
        if imaging_like and touches_phi and baa not in {"signed", "current", "not applicable"}:
            flags.append("Dental imaging / sensor AI without signed BAA (auto dental pack).")

    return _unique(flags)


def pack_flag_to_rule(flag: str) -> str | None:
    """Map pack flag text to stable rule ID."""
    mapping = [
        ("Dental imaging / sensor AI without signed BAA", "HA-PACK-DENTAL-001"),
        ("Ambient scribe in dental practice without clinician", "HA-PACK-DENTAL-002"),
        ("Dental patient-facing scheduling AI without human approval", "HA-PACK-DENTAL-003"),
        ("Behavioral-health sensitive workflow without clinician", "HA-PACK-BH-001"),
        ("Behavioral-health PHI retention over 90 days", "HA-PACK-BH-002"),
        ("Behavioral-health patient-facing tool with training-on-customer-data", "HA-PACK-BH-003"),
        ("Multi-state clinical/patient-facing tool without state-policy", "HA-PACK-MS-001"),
        ("Multi-state prescription-adjacent support without counsel", "HA-PACK-MS-002"),
        ("MSP-managed agent tools without customer disable", "HA-PACK-MSP-001"),
        ("MSP-managed high-impact tools without complete audit", "HA-PACK-MSP-002"),
        ("MSP-managed MCP servers without allowlist evidence", "HA-PACK-MSP-003"),
        ("Patient-facing tool without escalation/refusal behavior", "HA-PACK-GEN-001"),
        ("PHI SaaS tool without security contact", "HA-PACK-GEN-002"),
        ("Evidence verification issues:", "HA-EVID-003"),
    ]
    for prefix, rule_id in mapping:
        if flag.startswith(prefix) or prefix in flag:
            return rule_id
    return None


def describe_pack(selection: PackSelection) -> dict[str, Any]:
    catalog = {
        "general_small": "General / family small practice baseline",
        "dental_small": "Dental / oral-health small practice",
        "behavioral_health": "Behavioral health / therapy practice",
        "specialty_clinic": "Specialty clinic (imaging-heavy signals)",
        "multi_state": "Multi-state care overlay",
        "msp_managed": "MSP-managed operations overlay",
    }
    return {
        "primary": selection.primary,
        "overlays": list(selection.overlays),
        "label": selection.label,
        "reasons": list(selection.reasons),
        "profile": selection.profile,
        "descriptions": {pid: catalog.get(pid, pid) for pid in selection.pack_ids},
        "auto": True,
    }


def _normalize_profile(inventory: dict[str, Any]) -> dict[str, Any]:
    raw = inventory.get("practice_profile")
    if not isinstance(raw, dict):
        raw = {}
    profile: dict[str, Any] = dict(raw)
    # Allow top-level shortcuts for automation friendliness.
    for key in ("practice_type", "type", "states", "msp_managed", "multi_state", "specialty"):
        if key in inventory and key not in profile:
            profile[key] = inventory[key]
    if "type" not in profile and "practice_type" in profile:
        profile["type"] = profile["practice_type"]
    # Normalize states list.
    states = profile.get("states")
    if isinstance(states, str):
        profile["states"] = [s.strip() for s in states.replace(";", ",").split(",") if s.strip()]
    return profile


def _signal_blob(inventory: dict[str, Any], tools: list[dict[str, Any]], profile: dict[str, Any]) -> str:
    parts = [
        str(inventory.get("practice", "")),
        str(inventory.get("review_owner", "")),
        str(profile.get("type", "")),
        str(profile.get("specialty", "")),
    ]
    for tool in tools:
        parts.append(str(tool.get("name", "")))
        parts.append(str(tool.get("workflow", "")))
        parts.append(str(tool.get("use_case", "")))
        parts.append(str(tool.get("vendor", "")))
    return " ".join(parts).lower()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        if not value.strip():
            return []
        if "," in value:
            return [p.strip() for p in value.split(",")]
        return [value]
    return [value]


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value if value is not None else "").strip().lower() in {
        "yes",
        "true",
        "1",
        "y",
        "required",
        "documented",
        "complete",
        "current",
        "signed",
    }


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
