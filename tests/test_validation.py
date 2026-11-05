import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from app.main import app
from app.auth import expected_username, expected_password


class TestEmailValidation(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.auth = (expected_username, expected_password)

    def check_rejected(self, filename, content, status):
        with (
            patch("app.main.analyze_message") as analyze,
            patch("app.main.write_siem_alert") as alert,
            patch("app.main.generate_incident_report") as report
        ):
            response = self.client.post(
                "/analyze",
                auth=self.auth,
                files={"file": (filename, content)}
            )

            self.assertEqual(response.status_code, status)
            analyze.assert_not_called()
            alert.assert_not_called()
            report.assert_not_called()

    def test_invalid_extension(self):
        self.check_rejected("test.txt", b"Test", 400)

    def test_empty_email(self):
        self.check_rejected("empty.eml", b"", 400)

    def test_malformed_email(self):
        self.check_rejected(
            "invalid.eml",
            b"This is not a valid email message.",
            400
        )

    def test_oversized_email(self):
        self.check_rejected(
            "oversize.eml",
            b"A" * (5 * 1024 * 1024 + 1),
            413
        )


if __name__ == "__main__":
    unittest.main()
