from base64 import b32decode
from typing import Any, Self
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from app.protocol import address_str_to_tuple
from app.protocol.bencode import decode_bencode
from app.protocol.metainfo import load_metainfo

from .messages import announce_udp, connect_udp


def peer_list_from_bytes(peers_bytes: bytes) -> list[tuple[str, int]]:
    pos = 0
    peers = []
    while pos < len(peers_bytes):
        peer_ip = ".".join(map(str, peers_bytes[pos : pos + 4]))
        peer_port = int.from_bytes(peers_bytes[pos + 4 : pos + 6], "big")
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
        self.peer_addresses: list[tuple[str, int]] | None = None
        self.interval: int | None = None
        self.leechers: int | None = None
        self.seeders: int | None = None
        # from torrent or peer
        self.file_name: str | None = None
        self.piece_length: int | None = None
        self.pieces_hash: bytes | None = None
        self.num_pieces: int | None = None
        self.last_piece_length: int | None = None

    def init_pieces(self, file_name: str, file_length: int, piece_length: int, pieces_hash: bytes) -> None:
        self.file_name = file_name
        self.file_length = file_length
        self.piece_length = piece_length
        self.pieces_hash = pieces_hash
        self.num_pieces = len(self.pieces_hash) // 20
        self.last_piece_length = self.file_length - self.piece_length * (self.num_pieces - 1)

    @staticmethod
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

    @classmethod
    def from_torrent(cls, torrent_file: str, client_id: bytes) -> Self:
        infodata = load_metainfo(torrent_file)
        assert infodata is not None
        url, info_hash, pieces_hash, file_name, file_length, piece_length = infodata
        tracker = cls(url, info_hash, file_length, client_id)
        tracker.init_pieces(file_name, file_length, piece_length, pieces_hash)
        return tracker

    @classmethod
    def from_magnet(cls, magnet_link: str, client_id: bytes, unknown_length: int = 1024) -> list[Self]:
        _, tracker_urls, info_hash_str = cls.parse_magnet(magnet_link)
        info_hash = bytes.fromhex(info_hash_str)
        return [cls(url, info_hash, unknown_length, client_id) for url in tracker_urls]

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
        url = self.url + "?" + urlencode(query)
        res: dict[str | bytes, Any] | None = None
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                data, _ = decode_bencode(await response.read())
                assert isinstance(data, dict)
                res = data

        self.peer_addresses = []
        if isinstance(res, dict):
            if "peers" in res:
                self.peer_addresses = peer_list_from_bytes(res["peers"])
            else:
                raise ValueError(f"invalid tracker response, missing 'peers':\n{res}")
        else:
            raise TypeError(f"unhandled tracker response:\n{res!r}")

    async def _get_peers_udp(self) -> None:
        url_info = urlparse(self.url)
        tracker_address = address_str_to_tuple(url_info.netloc)
        self.connection_id = await connect_udp(tracker_address)
        self.interval, self.leechers, self.seeders, peers_bytes = await announce_udp(
            tracker_address, self.connection_id, self.info_hash, self.client_id, self.port, 0, self.file_length, 0
        )
        self.peer_addresses = peer_list_from_bytes(peers_bytes)

    async def get_peers(self) -> list[tuple[str, int]]:
        if self.url.startswith("http"):
            await self._get_peers_tcp()
            return self.peer_addresses or []

        if self.url.startswith("udp"):
            await self._get_peers_udp()
            return self.peer_addresses or []

        raise ValueError(f"unknown tracker protocol {self.url}")

    def print_peers(self) -> None:
        assert self.peer_addresses is not None
        for address in self.peer_addresses:
            print(f"{address[0]}:{address[1]}")
