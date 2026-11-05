from email import policy
from email.parser import BytesParser

from app.url_extractor import extract_urls
from app.html_extractor import extract_html_urls
from app.auth_analyzer import analyze_authentication

def analyze_email(file_path):
    with open(file_path, "rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    result = {
        "sender": str(message.get("From", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "recipient": str(message.get("To", "")),
        "subject": str(message.get("Subject", "")),
        "authentication": str(
            message.get("Authentication-Results", "")
        ),
        "body": "",
        "attachments": [],
        "urls": []
    }

    html_bodies = []

    for part in message.walk():
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            result["attachments"].append(
                part.get_filename() or "unknown"
            )
            continue

        content_type = part.get_content_type()

        if content_type == "text/plain":
            result["body"] += str(part.get_content())

        elif content_type == "text/html":
            html_bodies.append(str(part.get_content()))

    if not result["body"] and html_bodies:
        from bs4 import BeautifulSoup

        result["body"] = "\n".join(
            BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
            for html in html_bodies
        )

    result["urls"] = extract_urls(result["body"])

    for html in html_bodies:
        for url in extract_html_urls(html):
            if url not in result["urls"]:
                result["urls"].append(url)

    result["auth_results"] = analyze_authentication(
        result["authentication"]
    )

    return result
