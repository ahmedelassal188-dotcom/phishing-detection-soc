def calculate_threat_score(results):
    score = 0
    findings = []

    for result in results:
        if (
            result.get("provider") == "URLhaus"
            and result.get("status") == "listed"
            and result.get("listed") is True
        ):
            score = 40
            findings.append(
                "URL confirmed listed in URLhaus"
            )

    return {
        "risk_score": score,
        "findings": findings
    }
