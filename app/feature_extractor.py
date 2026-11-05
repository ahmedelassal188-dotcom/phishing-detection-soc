from app.url_analyzer import analyze_url
from app.attachment_analyzer import analyze_attachments
from app.sender_analyzer import analyze_sender


def extract_features(email_data):
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    text = f"{subject} {body}".lower()

    urls = email_data.get("urls", [])
    attachments = email_data.get("attachments", [])

    url_scores = [
        analyze_url(url)["risk_score"]
        for url in urls
    ]

    attachment_result = analyze_attachments(attachments)

    sender_result = analyze_sender(
        email_data.get("sender", ""),
        email_data.get("reply_to", "")
    )

    features = {
        "text_length": len(text),
        "url_count": len(urls),
        "attachment_count": len(attachments),
        "has_urgency": int(
            any(word in text for word in [
                "urgent", "immediate", "immediately"
            ])
        ),
        "has_verification": int(
            any(word in text for word in [
                "verify account",
                "account verification",
                "requires verification"
            ])
        ),
        "has_time_pressure": int(
            "within 24 hours" in text
        ),
        "max_url_risk": max(url_scores, default=0),
        "attachment_risk": attachment_result["risk_score"],
        "reply_to_mismatch": int(
            sender_result["reply_to_mismatch"]
        )
    }

    return features
