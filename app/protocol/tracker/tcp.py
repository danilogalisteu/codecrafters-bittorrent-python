"""
The BitTorrent Protocol Specification
https://www.bittorrent.org/beps/bep_0003.html

Tracker Returns Compact Peer Lists
https://www.bittorrent.org/beps/bep_0023.html
"""

from typing import Any
from urllib.parse import urlencode

import aiohttp

from app.protocol import address_list_from_bytes
from app.protocol.bencode import decode_bencode

from .announce import TCP_ANNOUNCE_DICT, AnnounceEvent


async def announce_tcp(
    url: str,
    info_hash: bytes,
    client_id: bytes,
    client_port: int,
    downloaded: int,
    left: int,
    uploaded: int,
    event: AnnounceEvent = AnnounceEvent.NONE,
) -> tuple[float, int, int, list[tuple[str, int]]]:
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

    assert left == 0 or "peers" in res  # a tracker might send no peers when left = 0
    assert "interval" in res

    peers = []
    if "peers" in res:
        # BEP0003
        if isinstance(res["peers"], list):
            assert all("ip" in p for p in res["peers"])
            assert all("port" in p for p in res["peers"])
            peers = [(p["ip"], p["port"]) for p in res["peers"]]

        # BEP 0023
        elif isinstance(res["peers"], bytes):
            peers = address_list_from_bytes(res["peers"])

        else:
            print("Unexpected peer format from tracker:")
            print(res)

    return float(res["interval"]), res.get("incomplete", 0), res.get("complete", 0), peers
