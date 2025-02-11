import asyncio
import math
from typing import Self

from .peer import Peer
from .tracker import Tracker


class Client:
    def __init__(
        self,
        info_hash: bytes,
        client_id: bytes,
    ) -> None:
        self.info_hash = info_hash
        self.client_id = client_id
        self.client_bitfield: bytearray | None = None

        self.file_name: str | None = None
        self.file_length: int | None = None
        self.piece_length: int | None = None
        self.pieces_hash: bytes | None = None
        self.last_piece_length: int | None = None
        self.num_pieces: int | None = None

        self.trackers: list[Tracker] | None = None
        self.peer_addresses: set[tuple[str, int]] | None = None
        self.peers: dict[tuple[str, int], Peer] = {}

        self.event_pieces = asyncio.Event()

    def init_pieces(self, file_name: str, file_length: int, piece_length: int, pieces_hash: bytes) -> None:
        self.file_name = file_name
        self.file_length = file_length
        self.piece_length = piece_length
        self.pieces_hash = pieces_hash
        self.num_pieces = len(self.pieces_hash) // 20
        self.last_piece_length = self.file_length - self.piece_length * (self.num_pieces - 1)

        self.client_bitfield = bytearray((0).to_bytes(math.ceil(self.num_pieces / 8), byteorder="big", signed=False))
        self.event_pieces.set()

    @classmethod
    def from_torrent(cls, torrent_file: str, client_id: bytes) -> Self:
        tracker = Tracker.from_torrent(torrent_file, client_id)
        client = cls(tracker.info_hash, client_id)
        client.trackers = [tracker]
        assert tracker.file_name is not None
        assert tracker.piece_length is not None
        assert tracker.pieces_hash is not None
        client.init_pieces(tracker.file_name, tracker.file_length, tracker.piece_length, tracker.pieces_hash)
        return client

    @classmethod
    def from_magnet(cls, magnet_link: str, client_id: bytes, unknown_length: int = 1024) -> Self:
        trackers = Tracker.from_magnet(magnet_link, client_id, unknown_length=unknown_length)
        client = cls(trackers[0].info_hash, client_id)
        client.trackers = trackers
        return client

    async def get_peers(self) -> None:
        if self.peer_addresses is None:
            self.peer_addresses = set()
        if self.trackers is not None:
            for addresses in await asyncio.gather(*[tracker.get_peers() for tracker in self.trackers]):
                self.peer_addresses.update(addresses)

    async def init_peers(self) -> None:
        if self.peer_addresses is None:
            self.peer_addresses = set()
            await self.get_peers()

        for address in self.peer_addresses:
            if self.peers.get(address, None) is None:
                self.peers[address] = Peer(address, self.info_hash, self.client_id).run_task()
