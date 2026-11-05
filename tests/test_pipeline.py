import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.auth import expected_username, expected_password
from app.main import app


class TestSOCPipeline(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.auth = (expected_username, expected_password)
        self.email = (
            b"From: test@example.com\n"
            b"Subject: SOC Test\n"
            b"\n"
            b"Synthetic test email."
        )

    def check_pipeline(self, assessment, alert_value):
        analysis = {
            "final_assessment": assessment
        }

        with (
            patch(
                "app.main.analyze_message",
                return_value=analysis
            ) as analyzer,
            patch(
                "app.main.write_siem_alert",
                return_value=alert_value
            ) as alert,
            patch(
                "app.main.generate_incident_report",
                return_value="/tmp/INC-ABCDEF1234.pdf"
            ) as report
        ):
            response = self.client.post(
                "/analyze",
                auth=self.auth,
                files={
                    "file": ("test.eml", self.email)
                }
            )

            self.assertEqual(response.status_code, 200)

            data = response.json()

            self.assertEqual(
                data["siem_alert_generated"],
                alert_value is not None
            )
            self.assertEqual(
                data["report_filename"],
                "INC-ABCDEF1234.pdf"
            )

            analyzer.assert_called_once()
            alert.assert_called_once()
            report.assert_called_once()

    def test_phishing_pipeline(self):
        self.check_pipeline(
            "High Phishing Suspicion",
            {"event_type": "phishing_detection"}
        )

    def test_benign_pipeline(self):
        self.check_pipeline(
            "Low Phishing Suspicion",
            None
        )


if __name__ == "__main__":
    unittest.main()
