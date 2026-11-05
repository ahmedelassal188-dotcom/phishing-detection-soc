from pathlib import PureWindowsPath


DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd",
    ".ps1", ".js", ".vbs", ".hta"
}


def analyze_attachments(attachments):
    score = 0
    findings = []

    for attachment in attachments:
        filename = PureWindowsPath(attachment).name
        name = filename.lower()

        extension = PureWindowsPath(name).suffix

        if extension in DANGEROUS_EXTENSIONS:
            score += 30
            findings.append(
                f"Potentially dangerous attachment: {filename}"
            )

        parts = name.split(".")

        if (
            len(parts) >= 3
            and parts[-2] in {"pdf", "doc", "docx", "jpg", "png"}
            and extension in DANGEROUS_EXTENSIONS
        ):
            score += 15
            findings.append(
                f"Double extension detected: {filename}"
            )

    return {
        "risk_score": min(score, 100),
        "findings": findings
    }
