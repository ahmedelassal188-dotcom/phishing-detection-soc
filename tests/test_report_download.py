import unittest
from pathlib import Path
from secrets import token_hex

from fastapi.testclient import TestClient
from reportlab.pdfgen import canvas

from app.auth import expected_username, expected_password
from app.main import app


REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"


class TestReportDownload(unittest.TestCase):

    def test_authenticated_pdf_download(self):
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

        filename = f"INC-{token_hex(5).upper()}.pdf"
        report_path = REPORT_DIR / filename

        self.addCleanup(report_path.unlink, missing_ok=True)

        pdf = canvas.Canvas(str(report_path))
        pdf.drawString(72, 750, "SOC Test Incident Report")
        pdf.save()

        client = TestClient(app)

        response = client.get(
            f"/reports/{filename}",
            auth=(expected_username, expected_password)
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["content-type"],
            "application/pdf"
        )
        self.assertTrue(response.content.startswith(b"%PDF-"))
        self.assertIn(
            filename,
            response.headers["content-disposition"]
        )


if __name__ == "__main__":
    unittest.main()
