from app.threat_scoring import calculate_threat_score
from app.threat_intelligence import check_urlhaus
from app.email_parser import analyze_email
from app.detection_rules import detect_phishing
from app.ml_predictor import predict_email


def analyze_message(file_path):
    email_data = analyze_email(file_path)
    threat_intelligence = []

    for url in email_data.get("urls", []):
        result = check_urlhaus(url)
        threat_intelligence.append(result)
    rule_result = detect_phishing(email_data)
# Add confirmed threat intelligence findings
    threat_score = calculate_threat_score(threat_intelligence)

    combined_score = min(
        100,
        rule_result["risk_score"] + threat_score["risk_score"]
    )

    rule_result["risk_score"] = combined_score
    rule_result["threat_score"] = threat_score["risk_score"]

    rule_result["reasons"].extend(
        threat_score["findings"]
    )

    # Recalculate risk classification
    if combined_score >= 70:
        rule_result["risk_level"] = "Critical"
    elif combined_score >= 45:
        rule_result["risk_level"] = "High"
    elif combined_score >= 20:
        rule_result["risk_level"] = "Medium"
    else:
        rule_result["risk_level"] = "Low"
    ml_result = predict_email(file_path)

    rule_suspicious = rule_result["risk_level"] in (
        "High", "Critical"
    )

    ml_suspicious = (
        ml_result["prediction"] == "Phishing"
    )

    if rule_suspicious and ml_suspicious:
        assessment = "High Phishing Suspicion"

    elif rule_suspicious or ml_suspicious:
        assessment = "Manual Review Required"

    else:
        assessment = "Low Phishing Suspicion"

    return {
        "subject": email_data["subject"],
        "sender": email_data["sender"],
        "rule_based": rule_result,
        "machine_learning": ml_result,
        "final_assessment": assessment,
        "engines_agree": ( 
         rule_suspicious == ml_suspicious
        ),
        "threat_intelligence": threat_intelligence,
    }
