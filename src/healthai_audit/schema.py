"""Inventory field catalog, unknown-key warnings, and light shape checks.

Does not replace fail-closed safety. Warns on typos and missing high-impact fields
so automated runs fail less often from silent ignore.
"""

from __future__ import annotations

from typing import Any


TOP_LEVEL_KNOWN = {
    "practice",
    "review_owner",
    "review_date",
    "practice_profile",
    "practice_type",
    "type",
    "states",
    "msp_managed",
    "multi_state",
    "specialty",
    "tools",
    "as_of",
    "cadence_days",
    "remediation_defaults",
}

PRACTICE_PROFILE_KNOWN = {
    "type",
    "practice_type",
    "states",
    "msp_managed",
    "multi_state",
    "specialty",
    "employee_count_band",
    "ehr",
    "location_count",
}

TOOL_KNOWN = {
    "name",
    "vendor",
    "workflow",
    "use_case",
    "data_types",
    "deployment_model",
    "model_types",
    "baa_status",
    "customer_data_training",
    "retention_days",
    "subprocessors",
    "rag",
    "permission_sync",
    "source_attribution",
    "prompt_injection_testing",
    "agent_tools",
    "mcp_servers",
    "autonomous_mode",
    "network_egress",
    "tool_scope",
    "human_approval",
    "audit_logging",
    "customer_can_disable_tools",
    "clinical_use",
    "patient_facing",
    "prescription_support",
    "clinician_review",
    "safety_case",
    "evaluation_dimensions",
    "escalation_behavior",
    "post_deployment_monitoring",
    "certifications",
    "fda_analysis",
    "state_policy_review",
    "incident_process",
    "security_contact",
    "model_provenance",
    "dataset_provenance",
    "sbom",
    "dependency_scanning",
    "ide_extension_governance",
    "secrets_controls",
    "evidence_refs",
    "owner",
    "remediation_due",
    "priority_override",
    "notes_ref",  # path-only reference, not free text notes
}

EVIDENCE_KNOWN = {
    "id",
    "kind",
    "path",
    "sha256",
    "reviewed_on",
    "expires_on",
    "covers_rules",
}

HIGH_IMPACT_TOOL_FIELDS = (
    "name",
    "vendor",
    "workflow",
    "data_types",
    "baa_status",
)


def inventory_warnings(inventory: dict[str, Any]) -> list[str]:
    """Return non-fatal warnings for unknown keys and missing high-impact fields."""
    warnings: list[str] = []
    for key in inventory.keys():
        if key not in TOP_LEVEL_KNOWN:
            warnings.append(f"Unknown top-level field '{key}' (ignored by scorer; check for typos).")

    profile = inventory.get("practice_profile")
    if isinstance(profile, dict):
        for key in profile.keys():
            if key not in PRACTICE_PROFILE_KNOWN:
                warnings.append(f"Unknown practice_profile field '{key}'.")

    tools = inventory.get("tools")
    if not isinstance(tools, list) or not tools:
        warnings.append("Inventory has no tools list.")
        return warnings

    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            warnings.append(f"tools[{index}] is not an object.")
            continue
        for key in tool.keys():
            if key not in TOOL_KNOWN:
                warnings.append(f"tools[{index}] ({tool.get('name', '?')}) unknown field '{key}'.")
        for required in HIGH_IMPACT_TOOL_FIELDS:
            if not str(tool.get(required, "")).strip() and required != "data_types":
                warnings.append(f"tools[{index}] missing high-impact field '{required}'.")
            if required == "data_types" and not tool.get("data_types"):
                warnings.append(f"tools[{index}] ({tool.get('name', '?')}) missing data_types.")
        refs = tool.get("evidence_refs")
        if refs is None:
            continue
        if not isinstance(refs, list):
            warnings.append(f"tools[{index}].evidence_refs must be a list.")
            continue
        for r_i, ref in enumerate(refs):
            if not isinstance(ref, dict):
                warnings.append(f"tools[{index}].evidence_refs[{r_i}] is not an object.")
                continue
            for key in ref.keys():
                if key not in EVIDENCE_KNOWN:
                    warnings.append(f"tools[{index}].evidence_refs[{r_i}] unknown field '{key}'.")
    return warnings
