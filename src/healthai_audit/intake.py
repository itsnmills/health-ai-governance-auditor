"""Minimal intake → full inventory expansion (automated).

Customers provide a short intake card (practice, type, states, tool stubs).
HealthAI Audit expands pack-aware defaults so they do not hand-author 40 fields.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import date
from pathlib import Path
from typing import Any

from healthai_audit.packs import detect_pack


# Pack-aware defaults for expanded tool rows (conservative unknowns).
_BASE_TOOL = {
    "deployment_model": "SaaS",
    "model_types": ["LLM"],
    "baa_status": "unknown",
    "customer_data_training": "unknown",
    "retention_days": None,
    "subprocessors": "unknown",
    "rag": False,
    "permission_sync": "unknown",
    "source_attribution": False,
    "prompt_injection_testing": "unknown",
    "agent_tools": [],
    "mcp_servers": [],
    "autonomous_mode": "unknown",
    "network_egress": "unknown",
    "tool_scope": "unknown",
    "human_approval": "unknown",
    "audit_logging": "unknown",
    "customer_can_disable_tools": False,
    "clinical_use": False,
    "patient_facing": False,
    "prescription_support": False,
    "clinician_review": False,
    "safety_case": "unknown",
    "evaluation_dimensions": [],
    "escalation_behavior": "unknown",
    "post_deployment_monitoring": "unknown",
    "certifications": [],
    "fda_analysis": "unknown",
    "state_policy_review": "unknown",
    "incident_process": "unknown",
    "security_contact": "",
    "model_provenance": "unknown",
    "dataset_provenance": "unknown",
    "sbom": False,
    "dependency_scanning": False,
    "ide_extension_governance": "unknown",
    "secrets_controls": "unknown",
    "evidence_refs": [],
}

# Keyword → seed adjustments when expanding tool stubs by name/workflow.
_SEED_RULES: list[tuple[tuple[str, ...], dict[str, Any]]] = [
    (
        ("scribe", "ambient", "dictation"),
        {
            "use_case": "clinical documentation",
            "data_types": ["PHI", "audio"],
            "model_types": ["LLM", "speech-to-text"],
            "clinical_use": True,
            "agent_tools": ["EHR draft note"],
        },
    ),
    (
        ("imaging", "xray", "x-ray", "radiograph", "pacs", "sensor"),
        {
            "use_case": "clinical imaging",
            "data_types": ["PHI", "imaging"],
            "model_types": ["vision", "LLM"],
            "clinical_use": True,
        },
    ),
    (
        ("schedul", "front desk", "appointment"),
        {
            "use_case": "scheduling",
            "data_types": ["PHI", "appointments"],
            "patient_facing": True,
            "agent_tools": ["calendar write", "SMS"],
            "model_types": ["LLM", "agent"],
        },
    ),
    (
        ("billing", "claim", "appeal", "denial"),
        {
            "use_case": "administrative",
            "data_types": ["PHI", "claims"],
            "agent_tools": ["email", "file upload"],
            "rag": True,
        },
    ),
    (
        ("rag", "policy", "knowledge", "handbook"),
        {
            "use_case": "internal knowledge assistant",
            "data_types": ["policy", "operations"],
            "rag": True,
            "model_types": ["LLM", "RAG"],
            "baa_status": "not applicable",
        },
    ),
    (
        ("mcp", "agent", "tool broker"),
        {
            "use_case": "agent automation",
            "data_types": ["PHI"],
            "model_types": ["LLM", "agent"],
            "agent_tools": ["MCP"],
            "mcp_servers": ["unspecified-mcp"],
            "autonomous_mode": "unknown",
        },
    ),
    (
        ("therapy", "counsel", "psych", "behavioral"),
        {
            "use_case": "clinical documentation",
            "data_types": ["PHI", "clinical notes"],
            "clinical_use": True,
            "patient_facing": True,
        },
    ),
]


def load_intake(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("intake must be a JSON object")
    return data


def expand_intake(intake: dict[str, Any]) -> dict[str, Any]:
    """Expand a minimal intake card into a scorable inventory."""
    practice = str(intake.get("practice", "")).strip() or "Unspecified practice"
    review_owner = str(intake.get("review_owner", "")).strip() or "Practice Manager"
    review_date = str(intake.get("review_date", "")).strip() or date.today().isoformat()

    profile: dict[str, Any] = {}
    if isinstance(intake.get("practice_profile"), dict):
        profile = dict(intake["practice_profile"])
    for key in ("type", "practice_type", "states", "msp_managed", "multi_state", "specialty"):
        if key in intake and key not in profile:
            profile[key] = intake[key]
    if "type" not in profile and "practice_type" in profile:
        profile["type"] = profile["practice_type"]
    if isinstance(profile.get("states"), str):
        profile["states"] = [s.strip() for s in profile["states"].replace(";", ",").split(",") if s.strip()]

    raw_tools = intake.get("tools") or intake.get("tool_stubs") or []
    if not isinstance(raw_tools, list) or not raw_tools:
        raise ValueError("intake requires a non-empty tools or tool_stubs list")

    tools: list[dict[str, Any]] = []
    for item in raw_tools:
        if isinstance(item, str):
            tools.append(_expand_stub({"name": item}, profile))
        elif isinstance(item, dict):
            tools.append(_expand_stub(item, profile))
        else:
            raise ValueError("each tool stub must be a string or object")

    inventory: dict[str, Any] = {
        "practice": practice,
        "review_owner": review_owner,
        "review_date": review_date,
        "practice_profile": profile,
        "tools": tools,
        "remediation_defaults": intake.get("remediation_defaults")
        or {"block_days": 14, "restrict_days": 30, "approve_with_conditions_days": 45},
    }
    # Attach detected pack label for operator visibility (recomputed on run too).
    selection = detect_pack(inventory)
    inventory["_intake_meta"] = {
        "expanded_from": "minimal_intake",
        "detected_pack": selection.label,
        "tool_count": len(tools),
    }
    return inventory


def expand_intake_file(path: Path, out: Path | None = None) -> tuple[dict[str, Any], Path | None]:
    inventory = expand_intake(load_intake(path))
    # Strip internal meta before write? Keep for debugging but prefix underscore is ok.
    written = None
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {k: v for k, v in inventory.items() if not str(k).startswith("_")}
        # Keep _intake_meta out of scored inventory file for cleanliness
        out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        written = out
        inventory = payload
    return inventory, written


def _expand_stub(stub: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    tool = deepcopy(_BASE_TOOL)
    name = str(stub.get("name", "")).strip() or "Unnamed AI tool"
    tool["name"] = name
    tool["vendor"] = str(stub.get("vendor", "")).strip() or "Unknown vendor"
    tool["workflow"] = str(stub.get("workflow", "")).strip() or f"{name} workflow"
    tool["use_case"] = str(stub.get("use_case", "")).strip() or "other"
    tool["data_types"] = stub.get("data_types") or ["unknown"]

    blob = f"{name} {tool['workflow']} {tool['use_case']}".lower()
    for keywords, adjustments in _SEED_RULES:
        if any(k in blob for k in keywords):
            for key, value in adjustments.items():
                tool[key] = deepcopy(value)

    # Pack-aware seed tightening.
    ptype = str(profile.get("type") or profile.get("practice_type") or "").lower()
    if ptype in {"behavioral", "behavioral_health", "mental_health", "therapy"}:
        if tool.get("clinical_use") or "phi" in [str(x).lower() for x in tool.get("data_types", [])]:
            tool["clinician_review"] = tool.get("clinician_review") or False
            tool["retention_days"] = tool.get("retention_days") if tool.get("retention_days") is not None else 90
    if ptype in {"dental", "dental_small"} and any(
        k in blob for k in ("imaging", "xray", "scribe", "sensor")
    ):
        tool["clinical_use"] = True
        if "PHI" not in [str(x) for x in tool.get("data_types", [])]:
            tool["data_types"] = list(tool.get("data_types") or []) + ["PHI"]

    # Explicit stub fields always win.
    for key, value in stub.items():
        if key in {"name", "vendor", "workflow", "use_case", "data_types"} or key in _BASE_TOOL or key == "evidence_refs":
            if value is not None and value != "":
                tool[key] = value
    return tool


def intake_template() -> str:
    return json.dumps(
        {
            "practice": "Maple Grove Dental",
            "review_owner": "Office Manager",
            "review_date": date.today().isoformat(),
            "practice_profile": {
                "type": "dental",
                "states": ["MO"],
                "msp_managed": True,
            },
            "tools": [
                {"name": "Ambient Scribe", "vendor": "Example Health AI"},
                {"name": "Dental Imaging AI", "vendor": "BiteScan AI"},
                {"name": "Front Desk Scheduling Agent", "vendor": "DeskPilot Labs"},
            ],
            "remediation_defaults": {
                "block_days": 14,
                "restrict_days": 30,
                "approve_with_conditions_days": 45,
            },
        },
        indent=2,
    ) + "\n"
