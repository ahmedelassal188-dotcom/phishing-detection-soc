from app.attachment_analyzer import analyze_attachments
from app.sender_analyzer import analyze_sender
from app.url_analyzer import analyze_url


def detect_phishing(email_data, trusted_auth=False):
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    urls = email_data.get("urls", [])
    text = f"{subject} {body}".lower()

    score = 0
    reasons = []

    # Rule 1: Urgency
    urgency_words = [
        "urgent",
        "immediate",
        "immediately"
    ]

    if any(word in text for word in urgency_words):
        score += 25
        reasons.append("Urgency language detected")

    # Rule 2: Account verification
    verification_words = [
        "verify account",
        "account verification",
        "requires verification"
    ]

    if any(word in text for word in verification_words):
        score += 20
        reasons.append("Account verification request detected")

    # Rule 3: Time pressure
    if "within 24 hours" in text:
        score += 15
        reasons.append("Time pressure detected")

    # Rule 4: URL analysis
    url_results = []

    for url in urls:
        analysis = analyze_url(url)
        url_results.append(analysis)

    # Use highest URL score to avoid double counting
    if url_results:
        highest_url_score = max(
            result["risk_score"]
            for result in url_results
        )

        score += highest_url_score

        for result in url_results:
            for reason in result["reasons"]:
                if reason not in reasons:
                    reasons.append(reason)
# Rule 5: Email authentication
    auth_results = email_data.get("auth_results", {})

    if trusted_auth:
        auth_weights = {
            "spf": 10,
            "dkim": 10,
            "dmarc": 25
        }

        for mechanism, points in auth_weights.items():
            if auth_results.get(mechanism) == "fail":
                score += points
                reasons.append(
                    f"{mechanism.upper()} authentication failed"
                )
# Rule 6: Reply-To mismatch
    sender_analysis = analyze_sender(
        email_data.get("sender", ""),
        email_data.get("reply_to", "")
    )

    if sender_analysis["reply_to_mismatch"]:
        score += 15
        reasons.append(sender_analysis["reason"])
# Rule 7: Attachment analysis
    attachment_analysis = analyze_attachments(
        email_data.get("attachments", [])
    )

    score += attachment_analysis["risk_score"]

    for finding in attachment_analysis["findings"]:
        if finding not in reasons:
            reasons.append(finding)
    score = min(score, 100)

    # Risk classification
    if score >= 70:
        risk = "Critical"
    elif score >= 45:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk_score": score,
        "risk_level": risk,
        "reasons": reasons,
        "url_analysis": url_results,
        "auth_results": auth_results,
        "auth_trusted": trusted_auth,
        "sender_analysis": sender_analysis,
        "attachment_analysis": attachment_analysis,
    }
