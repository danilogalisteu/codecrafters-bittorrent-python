"""
Tracker Returns Compact Peer Lists
https://www.bittorrent.org/beps/bep_0023.html
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Self

from app.protocol import AnnounceEvent
from app.protocol.metainfo import TorrentInfo

from .tcp import announce_tcp
from .udp import announce_udp


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
    def __init__(self, url: str, info_hash: bytes, total_length: int, client_id: bytes) -> None:
        self.url = url
        self.info_hash = info_hash
        self.client_id = client_id
        self.total_length = total_length
        self.downloaded_length: int = 0
        self.uploaded_length: int = 0
        self.port: int = 6881
        self.timeout = 15.0
        self.connection_id: int | None = None
        self.peer_addresses: list[tuple[str, int]] | None = None
        self.interval: float = 0.0
        self.leechers: int | None = None
        self.seeders: int | None = None
        self.next_announce: datetime = datetime.min.replace(tzinfo=UTC)

    @classmethod
    def from_torrent(cls, torrent_file: str, client_id: bytes) -> Self:
        torrent_info = TorrentInfo.from_file(torrent_file)
        assert torrent_info is not None
        return cls(torrent_info.tracker, torrent_info.info_hash, torrent_info.total_length, client_id)

    @classmethod
    def from_magnet(cls, magnet_link: str, client_id: bytes, unknown_length: int = 1024) -> list[Self]:
        torrent_info = TorrentInfo.from_magnet(magnet_link)
        assert torrent_info is not None
        tracker_list = torrent_info.tracker_list[0]
        return [cls(url, torrent_info.info_hash, unknown_length, client_id) for url in tracker_list]

    async def get_peers(self, event: AnnounceEvent = AnnounceEvent.NONE, n_retry_max: int = 9) -> list[tuple[str, int]]:
        if self.url.startswith("http"):
            announce_cb = announce_tcp
        elif self.url.startswith("udp"):
            announce_cb = announce_udp
        elif self.url.startswith("wss"):
            # TODO handle wss protocol
            print(f"unhandled tracker protocol {self.url}")
            return []
        else:
            print(f"unknown tracker protocol {self.url}")
            return []

        n_retry = 0
        while True:
            try:
                async with asyncio.timeout(self.timeout * 2**n_retry):
                    self.interval, self.leechers, self.seeders, peers_bytes = await announce_cb(
                        self.url,
                        self.info_hash,
                        self.client_id,
                        self.port,
                        self.downloaded_length,
                        self.total_length - self.downloaded_length,
                        self.uploaded_length,
                        event,
                    )
            except TimeoutError:
                if n_retry < n_retry_max:
                    print(f"Tracker '{self.url}' is not responding, trying again...")
                    n_retry += 1
                else:
                    print(f"Tracker '{self.url}' is not active...")
                    break
            else:
                self.peer_addresses = peer_list_from_bytes(peers_bytes)
                self.next_announce = datetime.now(UTC) + timedelta(seconds=self.interval)
                break

        return self.peer_addresses or []

    def print_peers(self) -> None:
        assert self.peer_addresses is not None
        for address in self.peer_addresses:
            print(f"{address[0]}:{address[1]}")
