from bs4 import BeautifulSoup
from app.url_extractor import extract_urls


def extract_html_urls(html):
    soup = BeautifulSoup(html, "html.parser")
    urls = []

    for tag in soup.find_all(href=True):
        url = tag["href"].strip()

        if url.lower().startswith(("http://", "https://")):
            if url not in urls:
                urls.append(url)

    text_urls = extract_urls(
        soup.get_text(" ", strip=True)
    )

    for url in text_urls:
        if url not in urls:
            urls.append(url)

    return urls
        
