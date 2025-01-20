from urllib.parse import parse_qs, urlparse


def parse_magnet(url: str) -> tuple[str, str]:
    result = urlparse(url)
    assert result.scheme == "magnet"

    query = parse_qs(result.query)

    name = query["dn"][0] if "dn" in query else ""
    trackers = query["tr"] if "tr" in query else []
    info_hash = query["xt"][0]

    assert len(info_hash) == 49
    assert info_hash[:9] == "urn:btih:"

    return name, trackers, info_hash[9:]
