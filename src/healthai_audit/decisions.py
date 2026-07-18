"""Deterministic approval decisions and rule-ID mapping.

Turns scored assessments into owner-facing decisions:
  block | restrict | approve_with_conditions | approve

Every critical flag and high-impact gap maps to a stable rule ID so packets
and handoffs remain auditable and comparable across runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


from healthai_audit.packs import PACK_RULES, pack_flag_to_rule


# Stable rule catalog. Codes are public API — do not renumber casually.
RULES: dict[str, dict[str, str]] = {
    "HA-BAA-001": {
        "title": "PHI tool without signed BAA",
        "decision": "block",
        "owner": "Practice owner / compliance",
    },
    "HA-TRAIN-001": {
        "title": "Customer-data training with PHI",
        "decision": "block",
        "owner": "Practice owner / counsel",
    },
    "HA-RAG-001": {
        "title": "RAG without permission sync",
        "decision": "block",
        "owner": "MSP / security",
    },
    "HA-AGENT-001": {
        "title": "Agent tools without human approval",
        "decision": "block",
        "owner": "MSP / security",
    },
    "HA-AGENT-002": {
        "title": "Agent tools without audit logging",
        "decision": "block",
        "owner": "MSP / security",
    },
    "HA-MCP-001": {
        "title": "MCP/tool-broker without approval gates",
        "decision": "block",
        "owner": "MSP / security",
    },
    "HA-AUTO-001": {
        "title": "Unsupervised autonomous mode on PHI or tools",
        "decision": "block",
        "owner": "Practice owner / MSP",
    },
    "HA-CLIN-001": {
        "title": "Clinical workflow without clinician review",
        "decision": "block",
        "owner": "Clinical owner",
    },
    "HA-RX-001": {
        "title": "Prescription support without state-policy review",
        "decision": "block",
        "owner": "Clinical owner / counsel",
    },
    "HA-DOMAIN-000": {
        "title": "At least one governance domain scored 0",
        "decision": "block",
        "owner": "Practice owner",
    },
    "HA-RISK-HIGH": {
        "title": "High residual risk without critical block flags",
        "decision": "restrict",
        "owner": "Practice manager / MSP",
    },
    "HA-RISK-MED": {
        "title": "Medium residual risk — track remediation",
        "decision": "approve_with_conditions",
        "owner": "Practice manager",
    },
    "HA-EVID-001": {
        "title": "PHI tool missing approve-grade evidence refs",
        "decision": "approve_with_conditions",
        "owner": "Practice manager / compliance",
    },
    "HA-EVID-002": {
        "title": "Evidence refs expired",
        "decision": "approve_with_conditions",
        "owner": "Practice manager / compliance",
    },
    "HA-EVID-003": {
        "title": "Local evidence path missing or hash mismatch",
        "decision": "approve_with_conditions",
        "owner": "Practice manager / compliance",
    },
}
RULES.update(PACK_RULES)


FLAG_TO_RULE: list[tuple[str, str]] = [
    ("Pause PHI use until BAA", "HA-BAA-001"),
    ("Block PHI use until customer-data training", "HA-TRAIN-001"),
    ("Do not connect RAG", "HA-RAG-001"),
    ("Disable agent actions until least-privilege", "HA-AGENT-001"),
    ("Disable or limit agent tools until audit logging", "HA-AGENT-002"),
    ("Block MCP/tool-broker", "HA-MCP-001"),
    ("Disable unsupervised autonomous mode", "HA-AUTO-001"),
    ("Do not use in clinical workflow until clinician", "HA-CLIN-001"),
    ("Do not use for prescription support", "HA-RX-001"),
    ("At least one governance domain scored 0", "HA-DOMAIN-000"),
]


DECISION_RANK = {
    "block": 0,
    "restrict": 1,
    "approve_with_conditions": 2,
    "approve": 3,
}


@dataclass(frozen=True)
class Decision:
    decision: str
    rule_ids: list[str]
    reasons: list[str]
    owner_actions: list[dict[str, str]]


def decide_assessment(assessment: dict[str, Any]) -> Decision:
    """Map one tool assessment to a decision with rule IDs."""
    from healthai_audit.evidence import apply_evidence_to_decision

    rule_ids: list[str] = []
    reasons: list[str] = []
    for flag in assessment.get("critical_flags") or []:
        rule_id = _rule_for_flag(str(flag))
        if rule_id and rule_id not in rule_ids:
            rule_ids.append(rule_id)
        reasons.append(str(flag))

    risk = str(assessment.get("risk_level", "High"))
    if not rule_ids:
        if risk == "Critical":
            # Defensive: critical without mapped flag still blocks.
            rule_ids.append("HA-DOMAIN-000")
            reasons.append("Critical risk without a mapped rule; require owner review.")
        elif risk == "High":
            rule_ids.append("HA-RISK-HIGH")
            reasons.append("High residual risk — restrict use until remediation is tracked.")
        elif risk == "Medium":
            rule_ids.append("HA-RISK-MED")
            reasons.append("Medium residual risk — approve only with tracked conditions.")

    decision = _worst_decision(rule_ids) if rule_ids else "approve"
    if not rule_ids and risk == "Low":
        decision = "approve"
        reasons = ["No critical flags and low residual risk from provided inventory."]

    # Evidence-bound approve: PHI tools need non-expired covering refs.
    evidence_status = assessment.get("evidence_status") or {}
    decision, rule_ids, reasons = apply_evidence_to_decision(
        decision, rule_ids, reasons, evidence_status
    )
    if rule_ids:
        # Never softer than the worst mapped rule (blocks still win).
        worst = _worst_decision(rule_ids)
        if DECISION_RANK.get(worst, 9) < DECISION_RANK.get(decision, 9):
            decision = worst

    owner_actions = []
    for rule_id in rule_ids:
        meta = RULES.get(rule_id, {})
        owner_actions.append(
            {
                "rule_id": rule_id,
                "title": meta.get("title", rule_id),
                "owner": meta.get("owner", "Practice manager"),
                "decision": meta.get("decision", decision),
            }
        )
    # Attach first priority actions as operational follow-through.
    for action in (assessment.get("high_priority_actions") or [])[:5]:
        owner_actions.append(
            {
                "rule_id": rule_ids[0] if rule_ids else "HA-RISK-MED",
                "title": str(action),
                "owner": "Practice manager / MSP",
                "decision": decision,
            }
        )
    # Evidence collection actions
    for gap in (evidence_status.get("gaps") or [])[:3]:
        owner_actions.append(
            {
                "rule_id": "HA-EVID-001",
                "title": str(gap),
                "owner": "Practice manager / compliance",
                "decision": decision,
            }
        )

    return Decision(decision=decision, rule_ids=rule_ids, reasons=reasons, owner_actions=_dedupe_actions(owner_actions))


def attach_decisions(report: dict[str, Any]) -> dict[str, Any]:
    """Return report with per-tool decisions and portfolio summary."""
    assessments_out: list[dict[str, Any]] = []
    decision_counts = {"block": 0, "restrict": 0, "approve_with_conditions": 0, "approve": 0}
    portfolio_rules: list[str] = []
    action_queue: list[dict[str, str]] = []

    for assessment in report.get("assessments", []):
        decision = decide_assessment(assessment)
        decision_counts[decision.decision] = decision_counts.get(decision.decision, 0) + 1
        for rule_id in decision.rule_ids:
            if rule_id not in portfolio_rules:
                portfolio_rules.append(rule_id)
        enriched = dict(assessment)
        enriched["decision"] = decision.decision
        enriched["rule_ids"] = decision.rule_ids
        enriched["decision_reasons"] = decision.reasons
        enriched["owner_actions"] = decision.owner_actions
        assessments_out.append(enriched)
        for action in decision.owner_actions:
            row = {
                "tool": str(assessment.get("name", "")),
                "vendor": str(assessment.get("vendor", "")),
                "decision": decision.decision,
                **action,
            }
            action_queue.append(row)

    # Sort assessments: block first, then restrict, then by name.
    assessments_out.sort(
        key=lambda item: (
            DECISION_RANK.get(str(item.get("decision")), 9),
            str(item.get("name", "")).lower(),
        )
    )
    action_queue.sort(
        key=lambda item: (
            DECISION_RANK.get(str(item.get("decision")), 9),
            str(item.get("tool", "")).lower(),
            str(item.get("rule_id", "")),
        )
    )

    summary = dict(report.get("summary", {}))
    summary["decision_counts"] = decision_counts
    summary["blocking_rule_ids"] = [r for r in portfolio_rules if RULES.get(r, {}).get("decision") == "block"]
    summary["portfolio_decision"] = _portfolio_decision(decision_counts)

    metadata = dict(report.get("metadata", {}))
    metadata["method"] = "HealthAI Audit automated dense scoring v0.5.0"

    evidence_sufficient = sum(
        1 for item in assessments_out if (item.get("evidence_status") or {}).get("status") == "sufficient"
    )
    summary["evidence_sufficient_tools"] = evidence_sufficient
    summary["evidence_missing_tools"] = sum(
        1
        for item in assessments_out
        if (item.get("evidence_status") or {}).get("status") in {"missing", "expired", "partial"}
        and (item.get("evidence_status") or {}).get("requires_evidence_for_approve")
    )

    return {
        "metadata": metadata,
        "summary": summary,
        "assessments": assessments_out,
        "action_queue": action_queue,
        "rule_catalog": {
            rule_id: {"title": meta["title"], "decision": meta["decision"], "owner": meta["owner"]}
            for rule_id, meta in RULES.items()
        },
    }


def _rule_for_flag(flag: str) -> str | None:
    for prefix, rule_id in FLAG_TO_RULE:
        if flag.startswith(prefix) or prefix in flag:
            return rule_id
    return pack_flag_to_rule(flag)


def _worst_decision(rule_ids: list[str]) -> str:
    worst = "approve"
    worst_rank = DECISION_RANK["approve"]
    for rule_id in rule_ids:
        decision = RULES.get(rule_id, {}).get("decision", "restrict")
        rank = DECISION_RANK.get(decision, 1)
        if rank < worst_rank:
            worst = decision
            worst_rank = rank
    return worst


def _portfolio_decision(counts: dict[str, int]) -> str:
    if counts.get("block", 0):
        return "block"
    if counts.get("restrict", 0):
        return "restrict"
    if counts.get("approve_with_conditions", 0):
        return "approve_with_conditions"
    return "approve"


def _dedupe_actions(actions: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for action in actions:
        key = (action.get("rule_id", ""), action.get("title", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(action)
    return out
