from typing import Any
import urllib.parse

import aiohttp

from .. import address_str_to_tuple
from ..bencode import decode_bencode
from ..magnet import parse_magnet
from ..metainfo import load_metainfo
from .messages import announce_udp, connect_udp


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
        self.connection_id: int | None = None
        self.peers: list[tuple[str, int]] | None = None
        self.interval: int | None = None
        self.leechers: int | None = None
        self.seeders: int | None = None
        # from torrent
        self.pieces_hash: bytes | None = None
        self.file_name: str | None = None
        self.piece_length: int | None = None

    @classmethod
    def from_torrent(cls, torrent_file: str, client_id: bytes):
        infodata = load_metainfo(torrent_file)
        assert infodata is not None
        url, info_hash, pieces_hash, file_name, file_length, piece_length = infodata
        tracker = Tracker(url, info_hash, file_length, client_id)
        tracker.pieces_hash = pieces_hash
        tracker.file_name = file_name
        tracker.piece_length = piece_length
        return tracker

    @classmethod
    def from_magnet(cls, magnet_link: str, client_id: bytes, unknown_length: int=1024):
        _, tracker_urls, info_hash_str = parse_magnet(magnet_link)
        info_hash = bytes.fromhex(info_hash_str)
        return [
            Tracker(url, info_hash, unknown_length, client_id)
            for url in tracker_urls
        ]

    def print_peers(self) -> None:
        assert self.peers is not None
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
        res: dict[str | bytes, Any] | None = None
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                data, _ = decode_bencode(await response.read())
                assert isinstance(data, dict)
                res = data

        self.peers = []
        if isinstance(res, dict):
            if "peers" in res:
                self.peers = peer_list_from_bytes(res["peers"])
            else:
                raise ValueError(f"invalid tracker response, missing 'peers':\n{res}")
        else:
            raise TypeError(f"unhandled tracker response:\n{res!r}")

    async def _get_peers_udp(self) -> None:
        url_info = urllib.parse.urlparse(self.url)
        tracker_address = address_str_to_tuple(url_info.netloc)
        self.connection_id = await connect_udp(tracker_address)
        self.interval, self.leechers, self.seeders, peers_bytes = await announce_udp(tracker_address, self.connection_id, self.info_hash, self.client_id, self.port, 0, self.file_length, 0)
        self.peers = peer_list_from_bytes(peers_bytes)

    async def get_peers(self) -> list[tuple[str, int]]:
        if self.url.startswith("http"):
            await self._get_peers_tcp()
            return self.peers or []

        if self.url.startswith("udp"):
            await self._get_peers_udp()
            return self.peers or []

        raise ValueError(f"unknown tracker protocol {self.url}")
