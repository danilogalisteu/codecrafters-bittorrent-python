import asyncio
import copy
import hashlib
import math
import pathlib
from typing import Any, Self

from .metainfo import FileInfo, TorrentInfo
from .peer import Peer
from .tracker import Tracker


class Client:
    def __init__(
        self,
        torrent: TorrentInfo,
        client_id: bytes,
        client_reserved: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict[str | bytes, Any] | None = None,
        download_folder: str = "./download",
        completed_folder: str = "./completed",
    ) -> None:
        self.torrent = torrent
        self.client_id = client_id
        self.client_reserved = client_reserved
        self.client_ext_support = client_ext_support
        self.client_bitfield: bytearray | None = None

        self.download_folder = pathlib.Path(download_folder) / self.torrent.info_hash.hex()
        self.completed_folder = pathlib.Path(completed_folder) / self.torrent.info_hash.hex()

        self.trackers: list[Tracker] | None = None
        self.peer_addresses: set[tuple[str, int]] | None = None
        self.peers: dict[tuple[str, int], Peer] = {}

        self._task: asyncio.Task[None] | None = None
        self._running: bool = False
        self._abort: bool = False
        self._peer_request_cancellations: dict[tuple[str, int], list[tuple[int, int, int]]] = {}

        self.event_pieces = asyncio.Event()
        self.event_complete = asyncio.Event()

        self._load_torrent()

        if self.torrent.num_pieces > 0:
            self._init_bitfield()
            self.event_pieces.set()
            self._init_files()
            self._check_pieces()

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

    def get_bitfield(self, piece_index: int) -> bool:
        assert self.client_bitfield is not None
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (self.client_bitfield[bitfield_index] & byte_mask) != 0

    def set_bitfield(self, piece_index: int) -> None:
        assert self.client_bitfield is not None
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        self.client_bitfield[bitfield_index] |= byte_mask

    def clear_bitfield(self, piece_index: int) -> None:
        assert self.client_bitfield is not None
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        self.client_bitfield[bitfield_index] &= ~byte_mask

    async def get_peers(self) -> None:
        if self.peer_addresses is None:
            self.peer_addresses = set()
        if self.trackers is not None:
            for addresses in await asyncio.gather(*[tracker.get_peers() for tracker in self.trackers]):
                self.peer_addresses.update(addresses)

    async def init_peers(self) -> None:
        if self.peer_addresses is None:
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

    def _init_bitfield(self) -> None:
        assert self.torrent.num_pieces > 0
        self.client_bitfield = bytearray(
            (0).to_bytes(math.ceil(self.torrent.num_pieces / 8), byteorder="big", signed=False),
        )

    async def wait_peer(self) -> None:
        if self.peer_addresses is None:
            await self.init_peers()
        await asyncio.wait(
            (asyncio.create_task(peer.event_bitfield.wait()) for peer in self.peers.values()),
            return_when=asyncio.FIRST_COMPLETED,
        )

    async def wait_metadata(self) -> None:
        await self.wait_peer()

        await asyncio.wait(
            (asyncio.create_task(peer.event_metadata.wait()) for peer in self.peers.values()),
            return_when=asyncio.FIRST_COMPLETED,
        )

        if self.torrent.num_pieces == 0:
            for peer in self.peers.values():
                if peer.event_metadata.is_set():
                    self.torrent = copy.deepcopy(peer.torrent)
                    self._init_bitfield()
                    self.event_pieces.set()
                    break

        self._save_torrent()
        self._init_files()
        self._check_pieces()

        for peer in self.peers.values():
            if not peer.event_pieces.is_set():
                peer.torrent = self.torrent
                peer.event_pieces.set()

    async def _comm_trackers(self) -> None:
        while not self._abort:
            await asyncio.sleep(1)

    async def _comm_peers(self) -> None:
        while not self._abort:
            await asyncio.sleep(1)

    async def _comm_task(self) -> None:
        await self.wait_peer()
        if self.torrent.num_pieces == 0:
            await self.wait_metadata()

        self._abort = False
        self._running = True

        async with asyncio.TaskGroup() as tg:
            _ = tg.create_task(self._comm_trackers())
            _ = tg.create_task(self._comm_peers())

        self._running = False

    def run_task(self) -> Self:
        self._task = asyncio.create_task(self._comm_task())
        return self

    def cancel_task(self) -> None:
        if self._task is not None:
            self._task.cancel()

    def abort(self) -> None:
        self._abort = True

    def _get_torrent_path(self) -> pathlib.Path:
        return self.download_folder.parent / f"{self.torrent.info_hash.hex()}.torrent"

    def _save_torrent(self, overwrite: bool = False) -> int | None:
        assert self.torrent.num_pieces > 0
        torrent_path = self._get_torrent_path()
        torrent_path.parent.mkdir(parents=True, exist_ok=True)
        if not torrent_path.exists() or overwrite:
            return self.torrent.to_file(torrent_path)
        return None

    def _load_torrent(self) -> None:
        torrent_path = self._get_torrent_path()
        if torrent_path.is_file():
            torrent_info = TorrentInfo.from_file(str(torrent_path))
            assert torrent_info is not None
            if torrent_info.info_hash == self.torrent.info_hash:
                print(f"Loading torrent file: {torrent_path}")
                self.torrent = torrent_info
                self._init_bitfield()
                self.event_pieces.set()
            else:
                print(f"Invalid torrent file: {torrent_path}")
                print(f"Expected info_hash: {self.torrent.info_hash.hex()}")
                print(f"Existing info_hash: {torrent_info.info_hash.hex()}")
                print("Removing file...")
                torrent_path.unlink()

    def _get_file_path(self, file_info: FileInfo) -> pathlib.Path:
        return self.download_folder / file_info.path

    def _init_files(self) -> None:
        assert self.torrent.files
        for file_info in self.torrent.files:
            file_path = self._get_file_path(file_info)
            if not file_path.exists():
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_bytes(b"\x00" * file_info.length)

    def _write_piece(self, piece_index: int, piece: bytes) -> int:
        assert self.torrent.num_pieces > 0
        piece_offset = piece_index * self.torrent.piece_length
        piece_start = 0
        for file_info in self.torrent.find_piece(piece_index):
            file_path = self._get_file_path(file_info)
            file_start = max(piece_offset - file_info.offset, 0)
            write_length = min(self.torrent.piece_length, file_info.length - file_start)
            with file_path.open("r+b") as fp:
                fp.seek(file_start)
                fp.write(piece[piece_start : piece_start + write_length])
            piece_offset += write_length
            piece_start += write_length
        return piece_start

    def _read_piece(self, piece_index: int) -> bytes:
        assert self.torrent.num_pieces > 0
        piece_offset = piece_index * self.torrent.piece_length
        piece = bytearray()
        for file_info in self.torrent.find_piece(piece_index):
            file_path = self._get_file_path(file_info)
            file_start = max(piece_offset - file_info.offset, 0)
            read_length = min(self.torrent.piece_length, file_info.length - file_start)
            with file_path.open("rb") as fp:
                fp.seek(file_start)
                piece.extend(fp.read(read_length))
        return bytes(piece)

    def _check_piece(self, piece_index: int) -> bool:
        piece = self._read_piece(piece_index)
        piece_hash = self.torrent.pieces_hash[piece_index * 20 : (piece_index + 1) * 20]
        return hashlib.sha1(piece).digest() == piece_hash

    def _check_pieces(self) -> None:
        assert self.torrent.num_pieces > 0
        for piece_index in range(self.torrent.num_pieces):
            if self._check_piece(piece_index):
                self.set_bitfield(piece_index)
            else:
                self.clear_bitfield(piece_index)

    async def get_piece(self, piece_index: int) -> bool:
        if self.get_bitfield(piece_index):
            return True

        for peer in self.peers.values():
            if peer.event_bitfield.is_set() and peer.get_bitfield_piece(piece_index):
                piece = await peer.get_piece(piece_index)
                if piece is not None:
                    self._write_piece(piece_index, piece)
                    self.set_bitfield(piece_index)
                    break

        if self.get_bitfield(piece_index):
            for peer in self.peers.values():
                if peer.event_pieces.is_set():
                    await peer.send_have(piece_index)

        return self.get_bitfield(piece_index)

    async def get_all(self) -> bool:
        assert self.torrent.num_pieces > 0

        await asyncio.gather(
            *[
                self.get_piece(piece_index)
                for piece_index in range(self.torrent.num_pieces)
                if not self.get_bitfield(piece_index)
            ],
        )

        return (
            len([piece_index for piece_index in range(self.torrent.num_pieces) if self.get_bitfield(piece_index)])
            == self.torrent.num_pieces
        )
