import asyncio
import math
from typing import Any, Self

from .peer import Peer
from .tracker import Tracker


class Client:
    def __init__(
        self,
        info_hash: bytes,
        client_id: bytes,
        client_reserved: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict[str | bytes, Any] | None = None,
    ) -> None:
        self.info_hash = info_hash
        self.client_id = client_id
        self.client_reserved = client_reserved
        self.client_ext_support = client_ext_support
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
        self.pieces: dict[int, bytes] = {}
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
    def from_torrent(
        cls,
        torrent_file: str,
        client_id: bytes,
        client_reserved: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict[str | bytes, Any] | None = None,
    ) -> Self:
        tracker = Tracker.from_torrent(torrent_file, client_id)
        client = cls(tracker.info_hash, client_id, client_reserved, client_ext_support)
        client.trackers = [tracker]
        assert tracker.file_name is not None
        assert tracker.piece_length is not None
        assert tracker.pieces_hash is not None
        client.init_pieces(tracker.file_name, tracker.file_length, tracker.piece_length, tracker.pieces_hash)
        return client

    @classmethod
    def from_magnet(
        cls,
        magnet_link: str,
        client_id: bytes,
        client_reserved: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict[str | bytes, Any] | None = None,
        unknown_length: int = 1024,
    ) -> Self:
        trackers = Tracker.from_magnet(magnet_link, client_id, unknown_length=unknown_length)
        client = cls(trackers[0].info_hash, client_id, client_reserved, client_ext_support)
        client.trackers = trackers
        return client

    def set_bitfield(self, piece_index: int) -> None:
        assert self.client_bitfield is not None
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        self.client_bitfield[bitfield_index] |= byte_mask

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
                self.peers[address] = Peer(
                    address,
                    self.info_hash,
                    self.client_id,
                    self.client_reserved,
                    self.client_ext_support,
                ).run_task()

    async def wait_pieces(self) -> None:
        if self.peer_addresses is None:
            await self.init_peers()

        while not self.event_pieces.is_set():
            await asyncio.sleep(0)
            for peer in self.peers.values():
                if peer.event_pieces.is_set():
                    assert peer.file_name is not None
                    assert peer.file_length is not None
                    assert peer.piece_length is not None
                    assert peer.pieces_hash is not None
                    self.init_pieces(peer.file_name, peer.file_length, peer.piece_length, peer.pieces_hash)
                    break

        assert self.file_name is not None
        assert self.file_length is not None
        assert self.piece_length is not None
        assert self.pieces_hash is not None
        for peer in self.peers.values():
            await peer.init_pieces(self.pieces_hash, self.file_length, self.piece_length, self.file_name)

    async def get_piece(self, piece_index: int) -> bool:
        for peer in self.peers.values():
            if peer.has_piece(piece_index):
                piece = await peer.get_piece(piece_index)
                if piece is not None:
                    self.pieces[piece_index] = piece
                    self.set_bitfield(piece_index)
                    break

        if piece_index in self.pieces:
            for peer in self.peers.values():
                if peer.event_pieces.is_set():
                    await peer.send_have(piece_index)

        return piece_index in self.pieces

    async def get_all(self) -> bool:
        assert self.num_pieces is not None

        await asyncio.gather(*[self.get_piece(piece_index) for piece_index in range(self.num_pieces)])

        return (
            len([piece_index for piece_index in range(self.num_pieces) if piece_index in self.pieces])
            == self.num_pieces
        )
