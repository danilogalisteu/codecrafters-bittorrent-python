import urllib.parse
import urllib.request

from .bencode import decode_bencode
from .udp import announce_udp, connect_udp


def peer_list_from_bytes(peers_bytes: bytes) -> list[tuple[str, int]]:
    pos = 0
    peers = []
    while pos < len(peers_bytes):
        peer_ip = ".".join(map(str, peers_bytes[pos:pos+4]))
        peer_port = int.from_bytes(peers_bytes[pos+4:pos+6], "big")
        peers.append((peer_ip, peer_port))
        pos += 6
    return peers


class Tracker:
    def __init__(self, url: str, info_hash: bytes, file_length: int, client_id: bytes) -> None:
        self.url = url
        self.info_hash = info_hash
        self.file_length = file_length
        self.client_id = client_id
        self.port: int = 6881
        self.connection_id = None
        self.peers: list[tuple[str, int]] | None = None
        self.interval = None
        self.leechers = None
        self.seeders = None

    def print_peers(self) -> None:
        for peer in self.peers:
            print(f"{peer[0]}:{peer[1]}")

    async def _get_peers_tcp(self) -> None:
        query = {
            "info_hash": self.info_hash,
            "peer_id": self.client_id,
            "port": self.port,
            "uploaded": 0,
            "downloaded": 0,
            "left": self.file_length,
            "compact": 1,
        }
        url = self.url + "?" + urllib.parse.urlencode(query)
        res, _ = decode_bencode(urllib.request.urlopen(url).read())

        self.peers = []
        if isinstance(res, dict):
            if "peers" in res:
                self.peers = peer_list_from_bytes(res["peers"])
            else:
                raise ValueError(f"invalid tracker response, missing 'peers':\n{res}")
        else:
            raise TypeError(f"unhandled tracker response:\n{res}")

    async def _get_peers_udp(self) -> None:
        url_info = urllib.parse.urlparse(self.url)
        tracker_address = url_info.netloc.split(":")
        self.connection_id = await connect_udp(tracker_address)
        self.interval, self.leechers, self.seeders, peers_bytes = await announce_udp(tracker_address, connection_id, self.info_hash, self.client_id, self.port, 0, self.file_length, 0)
        self.peers = peer_list_from_bytes(peers_bytes)

    async def get_peers(self) -> list[tuple[str, int]]:
        if self.url.startswith("http"):
            await self._get_peers_tcp()
            return self.peers

        if self.url.startswith("udp"):
            await self._get_peers_udp()
            return self.peers

        raise ValueError(f"unknown tracker protocol {self.url}")
