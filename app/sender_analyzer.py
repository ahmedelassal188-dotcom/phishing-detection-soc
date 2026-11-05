from email.utils import parseaddr


def analyze_sender(sender, reply_to):
    sender_email = parseaddr(sender)[1].lower()
    reply_email = parseaddr(reply_to)[1].lower()

    result = {
        "sender_email": sender_email,
        "reply_to_email": reply_email,
        "reply_to_mismatch": False,
        "reason": ""
    }

    if not reply_email:
        return result

    if "@" not in sender_email or "@" not in reply_email:
        return result

    sender_domain = sender_email.rsplit("@", 1)[1]
    reply_domain = reply_email.rsplit("@", 1)[1]

    if sender_domain != reply_domain:
        result["reply_to_mismatch"] = True
        result["reason"] = "Reply-To domain differs from sender domain"

    return result
