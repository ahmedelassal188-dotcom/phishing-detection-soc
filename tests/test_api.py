import unittest

from fastapi.testclient import TestClient
from app.main import app


class TestSOCAPI(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")

    def test_dashboard_requires_authentication(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 401)

    def test_analysis_requires_authentication(self):
        response = self.client.post(
            "/analyze",
            files={"file": ("test.eml", b"Test email")}
        )
        self.assertEqual(response.status_code, 401)

    def test_reports_require_authentication(self):
        response = self.client.get(
            "/reports/INC-0000000000.pdf"
        )
        self.assertEqual(response.status_code, 401)

    def test_wrong_password_is_rejected(self):
        response = self.client.get(
            "/dashboard",
            auth=("socadmin", "WrongPassword123")
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
