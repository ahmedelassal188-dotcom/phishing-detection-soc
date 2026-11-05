import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.report_generator import generate_incident_report


class TestPDFReports(unittest.TestCase):

    def test_generate_incident_report(self):
        analysis = {
            "sender": "test@example.com",
            "subject": "Synthetic Phishing Test",
            "final_assessment": "High Phishing Suspicion",
            "rule_based": {
                "risk_score": 75,
                "risk_level": "Critical",
                "reasons": ["Suspicious email content"],
                "url_analysis": [],
                "auth_results": {
                    "spf": "not_found",
                    "dkim": "not_found",
                    "dmarc": "not_found"
                },
                "auth_trusted": False
            },
            "machine_learning": {
                "prediction": "Phishing",
                "phishing_probability": 0.9463
            },
            "threat_intelligence": []
        }

        with TemporaryDirectory() as folder:
            with patch(
                "app.report_generator.REPORT_DIR",
                Path(folder)
            ):
                report = Path(generate_incident_report(analysis))

                self.assertTrue(report.is_file())
                self.assertRegex(
                    report.name,
                    r"^INC-[0-9A-F]{10}\.pdf$"
                )
                self.assertGreater(report.stat().st_size, 500)

                with report.open("rb") as pdf:
                    self.assertEqual(pdf.read(5), b"%PDF-")


if __name__ == "__main__":
    unittest.main()
