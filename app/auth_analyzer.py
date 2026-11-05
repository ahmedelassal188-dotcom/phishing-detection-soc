import re


def analyze_authentication(authentication_header):
    results = {
        "spf": "not_found",
        "dkim": "not_found",
        "dmarc": "not_found"
    }

    if not authentication_header:
        return results

    pattern = (
        r"\b(spf|dkim|dmarc)\s*=\s*"
        r"(pass|fail|softfail|neutral|none|"
        r"temperror|permerror)\b"
    )

    matches = re.findall(
        pattern,
        authentication_header,
        flags=re.IGNORECASE
    )

    for mechanism, status in matches:
        results[mechanism.lower()] = status.lower()

    return results
