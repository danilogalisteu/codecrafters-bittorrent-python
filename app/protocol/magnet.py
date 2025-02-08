from base64 import b32decode
from urllib.parse import parse_qs, urlparse


def parse_magnet(url: str) -> tuple[str, list[str], str]:
    result = urlparse(url)
    assert result.scheme == "magnet"

    query = parse_qs(result.query)

    display_name = query["dn"][0] if "dn" in query else ""
    tracker_urls = query.get("tr", [])
    info_hash_str = query["xt"][0]

    assert info_hash_str[:9] == "urn:btih:"
    info_hash_str = info_hash_str[9:]

    if len(info_hash_str) == 32:
        info_hash_str = b32decode(info_hash_str, casefold=True).hex()
    assert len(info_hash_str) == 40

    return display_name, tracker_urls, info_hash_str
