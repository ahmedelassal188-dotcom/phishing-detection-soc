import re


def extract_urls(text):
    pattern = r"https?://[^\s<>\"']+"

    urls = re.findall(pattern, text)

    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls
