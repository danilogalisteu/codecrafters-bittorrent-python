"""
The BitTorrent Protocol Specification
https://www.bittorrent.org/beps/bep_0003.html

Tracker Returns Compact Peer Lists
https://www.bittorrent.org/beps/bep_0023.html
"""

from typing import Any
from urllib.parse import urlencode

import aiohttp

from app.protocol import TCP_ANNOUNCE_DICT, AnnounceEvent
from app.protocol.bencode import decode_bencode


async def announce_tcp(
    url: str,
    info_hash: bytes,
    client_id: bytes,
    client_port: int,
    downloaded: int,
    left: int,
    uploaded: int,
    event: AnnounceEvent = AnnounceEvent.NONE,
) -> tuple[float, int, int, bytes]:
    query = {
        "info_hash": info_hash,
        "peer_id": client_id,
        "port": client_port,
        "uploaded": uploaded,
        "downloaded": downloaded,
        "left": left,
        "compact": 1,
    }
    if event != AnnounceEvent.NONE:
        query["event"] = TCP_ANNOUNCE_DICT[event].value

    url = url + "?" + urlencode(query)
    res: dict[str | bytes, Any] | None = None
    async with aiohttp.ClientSession() as session, session.get(url) as response:
        data, _ = decode_bencode(await response.read())
        assert isinstance(data, dict)
        res = data

    if not isinstance(res, dict):
        raise TypeError(f"unhandled tracker response:\n{res!r}")

    # BEP0003
    assert "peers" in res
    assert "interval" in res
    return float(res["interval"]), res.get("incomplete", 0), res.get("complete", 0), res["peers"]
