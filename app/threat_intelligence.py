from dotenv import load_dotenv
import os
import json
load_dotenv()
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def check_urlhaus(url):
    result = {
        "provider": "URLhaus",
        "url": url,
        "status": "not_checked",
        "listed": None
    }

    api_key = os.getenv("URLHAUS_AUTH_KEY")

    if not api_key:
        result["status"] = "not_configured"
        return result

    request = Request(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data=urlencode({"url": url}).encode(),
        headers={"Auth-Key": api_key},
        method="POST"
    )

    try:
        with urlopen(request, timeout=10) as response:
            data = json.load(response)

        query_status = data.get("query_status")

        if query_status == "ok":
            result["status"] = "listed"
            result["listed"] = True

        elif query_status == "no_results":
            result["status"] = "not_listed"
            result["listed"] = False

        else:
            result["status"] = "unknown"

    except (HTTPError, URLError, TimeoutError, ValueError):
        result["status"] = "unavailable"

    return result
