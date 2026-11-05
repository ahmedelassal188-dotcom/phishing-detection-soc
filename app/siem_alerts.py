import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "phishing_alerts.json"


def write_siem_alert(analysis):
    assessment = analysis.get("final_assessment", "")

    if assessment not in (
        "High Phishing Suspicion",
        "Manual Review Required"
    ):
        return None

    rules = analysis["rule_based"]
    ml = analysis["machine_learning"]

    alert = {
        "event_type": "phishing_detection",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "source": "Phishing Detection SOC",
        "sender": analysis.get("sender", ""),
        "subject": analysis.get("subject", ""),
        "risk_score": rules["risk_score"],
        "risk_level": rules["risk_level"],
        "ml_prediction": ml["prediction"],
        "ml_probability": ml["phishing_probability"],
        "assessment": assessment,
        "mitre_technique": "T1566",
        "findings": rules.get("reasons", [])
    }

    LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(alert) + "\n")

    return alert
