import ipaddress
from urllib.parse import urlsplit


def analyze_url(url):
    score = 0
    reasons = []

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https") or not hostname:
            return {
                "url": url,
                "risk_score": 0,
                "reasons": ["Invalid or unsupported URL"]
            }

        # Rule 1: HTTP without HTTPS
        if parsed.scheme == "http":
            score += 10
            reasons.append("URL uses HTTP without HTTPS")

        # Rule 2: IP address instead of domain
        try:
            ipaddress.ip_address(hostname)
            score += 25
            reasons.append("IP address used instead of domain")
        except ValueError:
            pass

        # Rule 3: @ symbol in URL authority
        if parsed.username is not None:
            score += 20
            reasons.append("URL contains userinfo")

        # Rule 4: Suspicious keywords
        keywords = [
            "verify-account",
            "reset-password",
            "confirm-login",
            "update-credentials"
        ]

        path = parsed.path.lower()

        if any(word in path for word in keywords):
            score += 15
            reasons.append("Sensitive account action in URL path")

        return {
            "url": url,
            "risk_score": min(score, 100),
            "reasons": reasons
        }

    except ValueError:
        return {
            "url": url,
            "risk_score": 0,
            "reasons": ["Malformed URL"]
        }
