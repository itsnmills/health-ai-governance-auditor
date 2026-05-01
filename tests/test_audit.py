import json
import tempfile
import unittest
from pathlib import Path

from healthai_audit.audit import audit_inventory, load_inventory, render_report, validate_inventory
from healthai_audit.cli import main
from healthai_audit.templates import TEMPLATES


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "sample_inventory.json"


class AuditTests(unittest.TestCase):
    def test_sample_inventory_scores_expected_risk_levels(self) -> None:
        report = audit_inventory(load_inventory(SAMPLE))
        by_name = {item["name"]: item for item in report["assessments"]}

        self.assertEqual(by_name["Claims Appeal Drafting Bot"]["risk_level"], "Critical")
        self.assertTrue(by_name["Claims Appeal Drafting Bot"]["critical_flags"])
        self.assertIn(by_name["Ambient Scribe"]["risk_level"], {"Low", "Medium"})
        self.assertEqual(report["summary"]["tool_count"], 3)

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
        report = audit_inventory(load_inventory(SAMPLE))

        markdown = render_report(report, "markdown")
        self.assertIn("# HealthAI Audit Report", markdown)
        self.assertIn("## Framework Anchors", markdown)

        data = json.loads(render_report(report, "json"))
        self.assertEqual(data["summary"]["tool_count"], 3)

        csv_text = render_report(report, "csv")
        self.assertIn("risk_level", csv_text)
        self.assertIn("Claims Appeal Drafting Bot", csv_text)

    def test_cli_writes_outputs_and_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(main(["score", str(SAMPLE), "--format", "json", "--out", str(out / "report.json")]), 0)
            self.assertEqual(main(["template", "policy", "--out", str(out / "policy.md")]), 0)

            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["tool_count"], 3)
            self.assertIn("Small-Practice AI Use Policy", (out / "policy.md").read_text(encoding="utf-8"))

    def test_templates_exist(self) -> None:
        self.assertIn("vendor risk", TEMPLATES["questionnaire"]().lower())
        self.assertIn("tools", TEMPLATES["inventory"]())


if __name__ == "__main__":
    unittest.main()
