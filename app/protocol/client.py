import asyncio
import math
from typing import Any, Self

from .metainfo import TorrentInfo
from .peer import Peer
from .tracker import Tracker


class Client:
    def __init__(
        self,
        torrent: TorrentInfo,
        client_id: bytes,
        client_reserved: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict[str | bytes, Any] | None = None,
    ) -> None:
        self.torrent = torrent
        self.client_id = client_id
        self.client_reserved = client_reserved
        self.client_ext_support = client_ext_support
        self.client_bitfield: bytearray | None = None

        self.trackers: list[Tracker] | None = None
        self.peer_addresses: set[tuple[str, int]] | None = None
        self.peers: dict[tuple[str, int], Peer] = {}
        self.pieces: dict[int, bytes] = {}
        self.event_pieces = asyncio.Event()

    @classmethod
    def from_torrent(
        cls,
        torrent_file: str,
        client_id: bytes,
        client_reserved: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict[str | bytes, Any] | None = None,
    ) -> Self:
        torrent_info = TorrentInfo.from_file(torrent_file)
        assert torrent_info is not None
        client = cls(torrent_info, client_id, client_reserved, client_ext_support)
        client.trackers = [Tracker(torrent_info.tracker, torrent_info.info_hash, torrent_info.total_length, client_id)]
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
        torrent_info = TorrentInfo.from_magnet(magnet_link)
        client = cls(torrent_info, client_id, client_reserved, client_ext_support)
        client.trackers = Tracker.from_magnet(magnet_link, client_id, unknown_length=unknown_length)
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
                    self.torrent,
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
                    self.torrent = peer.torrent
                    self.client_bitfield = bytearray(
                        (0).to_bytes(math.ceil(self.torrent.num_pieces / 8), byteorder="big", signed=False),
                    )
                    self.event_pieces.set()
                    break

        for peer in self.peers.values():
            if not peer.event_pieces.is_set():
                peer.torrent = self.torrent
                peer.event_pieces.set()

    async def get_piece(self, piece_index: int) -> bool:
        for peer in self.peers.values():
            if peer.event_bitfield.is_set() and peer.get_bitfield_piece(piece_index):
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
        assert self.torrent.num_pieces is not None

        await asyncio.gather(*[self.get_piece(piece_index) for piece_index in range(self.torrent.num_pieces)])

        return (
            len([piece_index for piece_index in range(self.torrent.num_pieces) if piece_index in self.pieces])
            == self.torrent.num_pieces
        )
