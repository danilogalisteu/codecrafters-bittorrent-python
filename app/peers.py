import urllib.parse
import urllib.request

from bencode import decode_bencode
from metainfo import get_infohash


def get_peers(metainfo: dict, peer_id: bytes, port: int=6881) -> list[tuple[str, int]]:
    query = {
        "info_hash": get_infohash(metainfo),
        "peer_id": peer_id,
        "port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": metainfo['info']['length'],
        "compact": 1,
    }
    url = metainfo['announce'] + "?" + urllib.parse.urlencode(query)
    res, _ = decode_bencode(urllib.request.urlopen(url).read())

    peers = []
    if "peers" in res:
        pos = 0
        while pos < len(res["peers"]):
            peer_ip = ".".join(map(str, res['peers'][pos:pos+4]))
            peer_port = int.from_bytes(res['peers'][pos+4:pos+6], 'big')
            peers.append((peer_ip, peer_port))
            pos += 6

    return peers


def print_peers(peers: list[tuple[str, int]]):
    for peer in peers:
        print(f"{peer[0]}:{peer[1]}")
