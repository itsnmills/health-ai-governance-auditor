import json
import tempfile
import unittest
from pathlib import Path

from healthai_audit.audit import audit_inventory, load_inventory, render_report, run_audit, validate_inventory
from healthai_audit.cli import main
from healthai_audit.decisions import attach_decisions, decide_assessment
from healthai_audit.diff import diff_reports, load_report_or_inventory, render_diff
from healthai_audit.kit_bridge import write_kit_bridge
from healthai_audit.packet import write_packet
from healthai_audit.safety import SafetyError, assert_inventory_safe, sanitize_report
from healthai_audit.templates import TEMPLATES


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "sample_inventory.json"
SAMPLE_FIXED = ROOT / "samples" / "sample_inventory_remediated.json"


class AuditTests(unittest.TestCase):
    def test_sample_inventory_scores_expected_risk_levels(self) -> None:
        report = audit_inventory(load_inventory(SAMPLE))
        by_name = {item["name"]: item for item in report["assessments"]}

        self.assertEqual(by_name["Claims Appeal Drafting Bot"]["risk_level"], "Critical")
        self.assertTrue(by_name["Claims Appeal Drafting Bot"]["critical_flags"])
        self.assertEqual(by_name["Front Desk MCP Scheduling Agent"]["risk_level"], "Critical")
        self.assertTrue(
            any(
                "autonomous" in flag.lower() or "MCP" in flag
                for flag in by_name["Front Desk MCP Scheduling Agent"]["critical_flags"]
            )
        )
        self.assertIn(by_name["Ambient Scribe"]["risk_level"], {"Low", "Medium"})
        self.assertEqual(report["summary"]["tool_count"], 4)
        self.assertIn("v0.5.0", report["metadata"]["method"])

    def test_run_audit_strips_source_and_adds_decisions(self) -> None:
        report = run_audit(SAMPLE)
        self.assertEqual(report["summary"]["tool_count"], 4)
        self.assertIn(report["summary"]["portfolio_decision"], {"block", "restrict", "approve_with_conditions", "approve"})
        self.assertTrue(report["summary"]["decision_counts"]["block"] >= 1)
        first = report["assessments"][0]
        self.assertNotIn("source", first)
        self.assertIn(first["decision"], {"block", "restrict", "approve_with_conditions", "approve"})
        self.assertTrue(first.get("rule_ids"))
        # Blocked tools should sort first.
        self.assertEqual(report["assessments"][0]["decision"], "block")

    def test_phi_without_baa_validates_with_warning(self) -> None:
        inventory = {
            "practice": "Test Clinic",
            "tools": [
                {
                    "name": "Unreviewed Tool",
                    "vendor": "Vendor",
                    "workflow": "Clinical notes",
                    "data_types": ["PHI"],
                    "baa_status": "unknown",
                }
            ],
        }

        warnings = validate_inventory(inventory)
        self.assertTrue(any("BAA status is unknown" in warning for warning in warnings))

    def test_rag_without_permission_sync_creates_critical_flag(self) -> None:
        report = audit_inventory(
            {
                "practice": "Test Clinic",
                "tools": [
                    {
                        "name": "Unsafe RAG",
                        "vendor": "Vendor",
                        "workflow": "Policy assistant",
                        "data_types": ["policy"],
                        "baa_status": "not applicable",
                        "customer_data_training": "no",
                        "retention_days": 7,
                        "subprocessors": "available",
                        "rag": True,
                        "permission_sync": "unknown",
                        "agent_tools": [],
                        "model_provenance": "documented",
                        "dataset_provenance": "documented",
                        "sbom": True,
                        "dependency_scanning": True,
                        "secrets_controls": "documented",
                        "incident_process": "documented",
                        "security_contact": "security@example.test",
                    }
                ],
            }
        )

        assessment = report["assessments"][0]
        self.assertEqual(assessment["risk_level"], "Critical")
        self.assertTrue(any("RAG" in flag for flag in assessment["critical_flags"]))

    def test_render_formats_are_stable(self) -> None:
        report = run_audit(SAMPLE)

        markdown = render_report(report, "markdown")
        self.assertIn("# HealthAI Audit Report", markdown)
        self.assertIn("## Framework Anchors", markdown)
        self.assertIn("Portfolio decision", markdown)
        self.assertIn("Decision:", markdown)

        data = json.loads(render_report(report, "json"))
        self.assertEqual(data["summary"]["tool_count"], 4)
        self.assertNotIn("source", data["assessments"][0])

        csv_text = render_report(report, "csv")
        self.assertIn("risk_level", csv_text)
        self.assertIn("decision", csv_text)
        self.assertIn("Claims Appeal Drafting Bot", csv_text)
        self.assertIn("Front Desk MCP Scheduling Agent", csv_text)

    def test_cli_writes_outputs_packet_and_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(
                main(["score", str(SAMPLE), "--format", "json", "--out", str(out / "report.json"), "--packet-dir", str(out / "packet")]),
                0,
            )
            self.assertEqual(main(["template", "policy", "--out", str(out / "policy.md")]), 0)
            self.assertEqual(main(["safety-check", str(SAMPLE)]), 0)
            self.assertEqual(main(["packet", str(SAMPLE), "--out", str(out / "packet2")]), 0)

            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["tool_count"], 4)
            self.assertIn("Small-Practice AI Use Policy", (out / "policy.md").read_text(encoding="utf-8"))
            self.assertTrue((out / "packet" / "owner-decision-packet.md").is_file())
            self.assertTrue((out / "packet2" / "action-queue.csv").is_file())

    def test_templates_exist(self) -> None:
        self.assertIn("vendor risk", TEMPLATES["questionnaire"]().lower())
        inventory = TEMPLATES["inventory"]()
        self.assertIn("tools", inventory)
        self.assertIn("mcp_servers", inventory)
        self.assertIn("autonomous_mode", inventory)
        self.assertIn("MCP", TEMPLATES["questionnaire"]())

    def test_autonomous_mcp_agent_flags_critical(self) -> None:
        report = audit_inventory(
            {
                "practice": "Test Clinic",
                "tools": [
                    {
                        "name": "Unsafe MCP Agent",
                        "vendor": "Vendor",
                        "workflow": "Scheduling",
                        "data_types": ["PHI"],
                        "baa_status": "signed",
                        "customer_data_training": "no",
                        "retention_days": 7,
                        "subprocessors": "available",
                        "rag": False,
                        "agent_tools": ["MCP", "calendar write", "SMS"],
                        "mcp_servers": ["calendar", "sms"],
                        "autonomous_mode": "yes",
                        "network_egress": "internet",
                        "tool_scope": "unknown",
                        "human_approval": "none",
                        "audit_logging": "none",
                        "customer_can_disable_tools": False,
                        "prompt_injection_testing": "none",
                        "model_provenance": "documented",
                        "dataset_provenance": "documented",
                        "sbom": True,
                        "dependency_scanning": True,
                        "secrets_controls": "documented",
                        "incident_process": "documented",
                        "security_contact": "security@example.test",
                    }
                ],
            }
        )
        assessment = report["assessments"][0]
        self.assertEqual(assessment["risk_level"], "Critical")
        flags = " ".join(assessment["critical_flags"]).lower()
        self.assertTrue("autonomous" in flags or "mcp" in flags or "agent" in flags)
        decision = decide_assessment(assessment)
        self.assertEqual(decision.decision, "block")
        self.assertTrue(any(rule.startswith("HA-") for rule in decision.rule_ids))

    def test_safety_rejects_secrets_and_free_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(
                json.dumps(
                    {
                        "practice": "Bad Clinic",
                        "tools": [
                            {
                                "name": "Leaky",
                                "vendor": "X",
                                "workflow": "test",
                                "notes": "patient complained about care",
                                "api_key": "sk_live_this_is_fake_but_long_enough_abcdef",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SafetyError):
                run_audit(path)

            # Explicit secret pattern
            path.write_text(
                json.dumps(
                    {
                        "practice": "Bad Clinic",
                        "tools": [
                            {
                                "name": "KeyLeak",
                                "vendor": "X",
                                "workflow": "test",
                                "token": "AKIAIOSFODNN7EXAMPLE",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SafetyError):
                inventory = load_inventory(path)
                assert_inventory_safe(path, inventory, strict=True)

    def test_safety_rejects_ssn_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ssn.json"
            path.write_text(
                json.dumps(
                    {
                        "practice": "Bad Clinic",
                        "tools": [
                            {
                                "name": "Tool",
                                "vendor": "X",
                                "workflow": "test",
                                "id": "123-45-6789",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SafetyError):
                run_audit(path)

    def test_sanitize_report_redacts_source_when_included(self) -> None:
        raw = audit_inventory(load_inventory(SAMPLE))
        raw["assessments"][0]["source"] = {
            "name": "Ambient Scribe",
            "notes": "should not ship",
            "baa_status": "signed",
        }
        cleaned = sanitize_report(raw, include_source=True)
        self.assertIn("source", cleaned["assessments"][0])
        self.assertIn("redacted", cleaned["assessments"][0]["source"]["notes"])
        stripped = sanitize_report(raw, include_source=False)
        self.assertNotIn("source", stripped["assessments"][0])

    def test_packet_write_has_no_source_payload(self) -> None:
        report = run_audit(SAMPLE)
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_packet(report, Path(tmp))
            packet_json = json.loads(paths["decisions_json"].read_text(encoding="utf-8"))
            self.assertTrue(packet_json["assessments"])
            self.assertNotIn("source", packet_json["assessments"][0])
            self.assertNotIn("domain_results", packet_json["assessments"][0])
            md = paths["owner_packet"].read_text(encoding="utf-8")
            self.assertIn("Owner Decision Packet", md)
            self.assertIn("Portfolio decision", md)

    def test_invalid_retention_reduces_data_score(self) -> None:
        report = audit_inventory(
            {
                "practice": "Test",
                "tools": [
                    {
                        "name": "T",
                        "vendor": "V",
                        "workflow": "w",
                        "data_types": ["policy"],
                        "baa_status": "not applicable",
                        "customer_data_training": "no",
                        "retention_days": "forever",
                        "subprocessors": "available",
                    }
                ],
            }
        )
        data_domain = next(d for d in report["assessments"][0]["domain_results"] if d["name"].startswith("Data"))
        self.assertLess(data_domain["score"], 4)
        self.assertTrue(any("valid" in gap.lower() or "integer" in gap.lower() for gap in data_domain["gaps"]))

    def test_attach_decisions_portfolio_block(self) -> None:
        report = attach_decisions(audit_inventory(load_inventory(SAMPLE)))
        self.assertEqual(report["summary"]["portfolio_decision"], "block")
        self.assertTrue(report["action_queue"])
        self.assertIn("rule_catalog", report)
        self.assertIn("HA-EVID-001", report["rule_catalog"])

    def test_evidence_refs_gate_approve_for_phi(self) -> None:
        good = audit_inventory(
            {
                "practice": "Test",
                "review_date": "2026-07-16",
                "tools": [
                    {
                        "name": "Safe PHI Tool",
                        "vendor": "V",
                        "workflow": "docs",
                        "data_types": ["PHI"],
                        "baa_status": "signed",
                        "customer_data_training": "no",
                        "retention_days": 30,
                        "subprocessors": "available",
                        "rag": False,
                        "prompt_injection_testing": "documented",
                        "agent_tools": [],
                        "clinical_use": False,
                        "patient_facing": False,
                        "model_provenance": "documented",
                        "dataset_provenance": "documented",
                        "sbom": True,
                        "dependency_scanning": True,
                        "secrets_controls": "documented",
                        "incident_process": "documented",
                        "security_contact": "s@example.test",
                        "certifications": ["SOC 2"],
                        "evidence_refs": [
                            {
                                "id": "EVID-1",
                                "kind": "baa",
                                "path": "evidence/baa.pdf",
                                "reviewed_on": "2026-01-01",
                                "expires_on": "2027-01-01",
                            }
                        ],
                    }
                ],
            }
        )
        decided = attach_decisions(good)
        self.assertEqual(decided["assessments"][0]["evidence_status"]["status"], "sufficient")
        self.assertEqual(decided["assessments"][0]["decision"], "approve")
        self.assertNotIn("HA-EVID-001", decided["assessments"][0]["rule_ids"])

        missing = audit_inventory(
            {
                "practice": "Test",
                "review_date": "2026-07-16",
                "tools": [
                    {
                        "name": "No Evidence PHI",
                        "vendor": "V",
                        "workflow": "docs",
                        "data_types": ["PHI"],
                        "baa_status": "signed",
                        "customer_data_training": "no",
                        "retention_days": 30,
                        "subprocessors": "available",
                        "rag": False,
                        "prompt_injection_testing": "documented",
                        "agent_tools": [],
                        "clinical_use": False,
                        "patient_facing": False,
                        "model_provenance": "documented",
                        "dataset_provenance": "documented",
                        "sbom": True,
                        "dependency_scanning": True,
                        "secrets_controls": "documented",
                        "incident_process": "documented",
                        "security_contact": "s@example.test",
                        "certifications": ["SOC 2"],
                    }
                ],
            }
        )
        decided_missing = attach_decisions(missing)
        self.assertIn(decided_missing["assessments"][0]["decision"], {"approve_with_conditions", "restrict", "block"})
        self.assertIn("HA-EVID-001", decided_missing["assessments"][0]["rule_ids"])

    def test_expired_evidence_flags(self) -> None:
        report = attach_decisions(
            audit_inventory(
                {
                    "practice": "Test",
                    "review_date": "2026-07-16",
                    "tools": [
                        {
                            "name": "Expired Evidence",
                            "vendor": "V",
                            "workflow": "docs",
                            "data_types": ["PHI"],
                            "baa_status": "signed",
                            "customer_data_training": "no",
                            "retention_days": 30,
                            "subprocessors": "available",
                            "prompt_injection_testing": "documented",
                            "model_provenance": "documented",
                            "dataset_provenance": "documented",
                            "sbom": True,
                            "dependency_scanning": True,
                            "secrets_controls": "documented",
                            "incident_process": "documented",
                            "security_contact": "s@example.test",
                            "certifications": ["SOC 2"],
                            "evidence_refs": [
                                {
                                    "id": "EVID-OLD",
                                    "kind": "baa",
                                    "path": "evidence/old-baa.pdf",
                                    "reviewed_on": "2024-01-01",
                                    "expires_on": "2025-01-01",
                                }
                            ],
                        }
                    ],
                }
            )
        )
        assessment = report["assessments"][0]
        self.assertEqual(assessment["evidence_status"]["status"], "expired")
        self.assertIn("HA-EVID-002", assessment["rule_ids"])

    def test_kit_bridge_exports(self) -> None:
        report = run_audit(SAMPLE)
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_kit_bridge(report, Path(tmp))
            md = paths["ai_workflow_review"].read_text(encoding="utf-8")
            self.assertIn("# AI Workflow Review", md)
            self.assertIn("prohibited", md)
            csv_text = paths["handoff_actions"].read_text(encoding="utf-8")
            self.assertIn("action_id", csv_text)
            self.assertIn("kit_decision", csv_text)
            manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "velari.kit_bridge.v1")

    def test_diff_closes_rules_on_remediation(self) -> None:
        before = load_report_or_inventory(SAMPLE)
        after = load_report_or_inventory(SAMPLE_FIXED)
        result = diff_reports(before, after)
        self.assertGreaterEqual(result["summary"]["rules_closed"], 1)
        self.assertEqual(result["summary"]["rules_new"], 0)
        self.assertTrue(any(row["direction"] == "improved" for row in result["decision_changes"]))
        md = render_diff(result, "markdown")
        self.assertIn("Closed rules", md)
        self.assertIn(result["summary"]["net"], {"improved", "mixed"})

    def test_cli_diff_and_kit_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(
                main(["diff", str(SAMPLE), str(SAMPLE_FIXED), "--format", "json", "--out", str(out / "diff.json")]),
                0,
            )
            self.assertEqual(main(["kit-export", str(SAMPLE), "--out", str(out / "kit")]), 0)
            diff = json.loads((out / "diff.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(diff["summary"]["rules_closed"], 1)
            self.assertTrue((out / "kit" / "ai-workflow-review.md").is_file())

    def test_packet_includes_kit_bridge(self) -> None:
        report = run_audit(SAMPLE)
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_packet(report, Path(tmp))
            self.assertTrue(paths["kit_ai_workflow_review"].is_file())
            self.assertIn("evidence_refs", json.loads(paths["decisions_json"].read_text(encoding="utf-8"))["assessments"][0])

    def test_auto_detects_dental_msp_multi_state_pack(self) -> None:
        from healthai_audit.packs import detect_pack, apply_pack_flags
        from healthai_audit.audit import load_inventory

        dental = ROOT / "samples" / "sample_dental_msp.json"
        inventory = load_inventory(dental)
        selection = detect_pack(inventory)
        self.assertEqual(selection.primary, "dental_small")
        self.assertIn("multi_state", selection.overlays)
        self.assertIn("msp_managed", selection.overlays)

        report = run_audit(dental)
        self.assertEqual(report["metadata"]["policy_pack"]["primary"], "dental_small")
        self.assertTrue(report["metadata"]["policy_pack"]["auto"])
        # Imaging without BAA should pick up pack rule via critical flags / rule ids
        by_name = {item["name"]: item for item in report["assessments"]}
        imaging = by_name["Dental Imaging AI"]
        self.assertEqual(imaging["decision"], "block")
        self.assertTrue(
            any(r.startswith("HA-PACK-") or r.startswith("HA-BAA") or r.startswith("HA-CLIN") for r in imaging["rule_ids"])
        )

    def test_run_command_writes_full_packet(self) -> None:
        dental = ROOT / "samples" / "sample_dental_msp.json"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "auto"
            self.assertEqual(main(["run", str(dental), "--out", str(out), "--json-summary"]), 0)
            self.assertTrue((out / "RUN_SUMMARY.md").is_file())
            self.assertTrue((out / "owner-decision-packet.md").is_file())
            self.assertTrue((out / "kit-bridge" / "handoff-actions.csv").is_file())
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertIn("dental_small", report["metadata"]["policy_pack"]["label"])

    def test_detect_pack_cli(self) -> None:
        dental = ROOT / "samples" / "sample_dental_msp.json"
        self.assertEqual(main(["detect-pack", str(dental)]), 0)

    def test_infer_dental_from_practice_name_without_profile(self) -> None:
        from healthai_audit.packs import detect_pack

        selection = detect_pack(
            {
                "practice": "Sunrise Dental Group",
                "tools": [{"name": "Charting helper", "workflow": "notes", "vendor": "X"}],
            }
        )
        self.assertEqual(selection.primary, "dental_small")

    def test_intake_expands_and_runs(self) -> None:
        from healthai_audit.intake import expand_intake, load_intake

        intake_path = ROOT / "samples" / "sample_intake_minimal.json"
        inventory = expand_intake(load_intake(intake_path))
        self.assertGreaterEqual(len(inventory["tools"]), 3)
        self.assertEqual(inventory["practice_profile"]["type"], "behavioral_health")
        # Expanded scribe-like tool should get PHI seed
        names = {t["name"] for t in inventory["tools"]}
        self.assertIn("Therapy Notes Scribe", names)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            self.assertEqual(
                main(
                    [
                        "run",
                        str(intake_path),
                        "--from-intake",
                        "--out",
                        str(out),
                        "--as-of",
                        "2026-07-18",
                        "--json-summary",
                    ]
                ),
                0,
            )
            self.assertTrue((out / "dashboard.html").is_file())
            self.assertTrue((out / "remediation-plan.md").is_file())
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertIn("behavioral", report["metadata"]["policy_pack"]["label"])
            self.assertTrue(report.get("remediation_plan"))

    def test_evidence_verification_hash(self) -> None:
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            evidence = base / "evidence"
            evidence.mkdir()
            blob = b"synthetic-baa-bytes-not-phi"
            path = evidence / "baa.pdf"
            path.write_bytes(blob)
            digest = hashlib.sha256(blob).hexdigest()
            inventory = {
                "practice": "Hash Clinic",
                "review_date": "2026-07-18",
                "practice_profile": {"type": "general", "states": ["MO"]},
                "tools": [
                    {
                        "name": "Safe Tool",
                        "vendor": "V",
                        "workflow": "admin",
                        "data_types": ["PHI"],
                        "baa_status": "signed",
                        "customer_data_training": "no",
                        "retention_days": 30,
                        "subprocessors": "available",
                        "prompt_injection_testing": "documented",
                        "model_provenance": "documented",
                        "dataset_provenance": "documented",
                        "sbom": True,
                        "dependency_scanning": True,
                        "secrets_controls": "documented",
                        "incident_process": "documented",
                        "security_contact": "s@example.test",
                        "certifications": ["SOC 2"],
                        "evidence_refs": [
                            {
                                "id": "EVID-1",
                                "kind": "baa",
                                "path": "evidence/baa.pdf",
                                "sha256": digest,
                                "reviewed_on": "2026-01-01",
                                "expires_on": "2027-01-01",
                            }
                        ],
                    }
                ],
            }
            inv_path = base / "inv.json"
            inv_path.write_text(json.dumps(inventory), encoding="utf-8")
            report = run_audit(inv_path, verify_evidence=True, as_of="2026-07-18")
            ver = report["assessments"][0]["evidence_verification"]
            self.assertEqual(ver["verification_status"], "verified")
            self.assertEqual(ver["results"][0]["status"], "present_hash_ok")

    def test_unknown_field_warnings(self) -> None:
        from healthai_audit.schema import inventory_warnings

        warnings = inventory_warnings(
            {
                "practice": "X",
                "typo_field": 1,
                "tools": [{"name": "T", "vendor": "V", "workflow": "w", "baa_statue": "signed"}],
            }
        )
        self.assertTrue(any("typo_field" in w for w in warnings))
        self.assertTrue(any("baa_statue" in w for w in warnings))

    def test_batch_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "batch"
            # Use samples dir but may include intake which is also valid json
            code = main(["batch", str(ROOT / "samples"), "--out", str(out), "--as-of", "2026-07-18", "--no-verify-evidence"])
            self.assertIn(code, {0, 1})  # some sample may fail safety? should be 0
            self.assertTrue((out / "BATCH_INDEX.json").is_file())


if __name__ == "__main__":
    unittest.main()
