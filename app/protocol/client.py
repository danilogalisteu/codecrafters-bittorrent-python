import asyncio
import copy
from datetime import UTC, datetime
from typing import Any, Self

from .files import FileManager
from .metainfo import TorrentInfo
from .peer import Peer
from .tracker import Tracker


class Client(FileManager):
    def __init__(
        self,
        torrent: TorrentInfo,
        client_id: bytes,
        trackers: list[Tracker] | None = None,
        client_reserved: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict[str | bytes, Any] | None = None,
        download_folder: str = "./download",
        completed_folder: str = "./completed",
    ) -> None:
        super().__init__(torrent, download_folder, completed_folder)

        self.client_id = client_id
        self.client_reserved = client_reserved
        self.client_ext_support = client_ext_support

        self.trackers: list[Tracker] = trackers if trackers is not None else []
        self.peer_addresses: set[tuple[str, int]] = set()
        self.peers: dict[tuple[str, int], Peer] = {}

        self._task: asyncio.Task[None] | None = None
        self._running: bool = False
        self._abort: bool = False
        self._peer_request_cancellations: dict[tuple[str, int], list[tuple[int, int, int]]] = {}

        self.event_connected = asyncio.Event()
        self.event_failed = asyncio.Event()

        self._load_torrent()

        if self.torrent.num_pieces > 0:
            if not self._get_torrent_path().exists():
                self._save_torrent()
            self._init_bitfield()
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
        trackers = [Tracker(torrent_info.tracker, torrent_info.info_hash, torrent_info.total_length, client_id)]
        return cls(torrent_info, client_id, trackers, client_reserved, client_ext_support)

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
        trackers = Tracker.from_magnet(magnet_link, client_id, unknown_length=unknown_length)
        return cls(torrent_info, client_id, trackers, client_reserved, client_ext_support)

    async def get_peers(self) -> None:
        for addresses in await asyncio.gather(*[tracker.get_peers() for tracker in self.trackers]):
            self.peer_addresses.update(addresses)

    async def init_peers(self) -> None:
        if len(self.peer_addresses) == 0:
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

    async def wait_peer(self) -> None:
        if len(self.peer_addresses) == 0:
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
            dt_now = datetime.now(UTC)
            min_next = min(tracker.next_announce for tracker in self.trackers)
            if min_next > dt_now:
                await asyncio.sleep((min_next - dt_now).total_seconds())

            pending = {
                asyncio.create_task(tracker.get_peers()) for tracker in self.trackers if tracker.next_announce <= dt_now
            }

            for timeout in [5, 20, 35]:
                if pending:
                    done, pending = await asyncio.wait(
                        pending,
                        timeout=timeout,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task_peer_addresses in done:
                        self.peer_addresses.update(task_peer_addresses.result())

            for task in pending:
                task.cancel()

    async def _comm_peers(self) -> None:
        while not self._abort:
            await asyncio.sleep(1)

            # init local data
            if self.torrent.num_pieces == 0:
                for peer in self.peers.values():
                    if peer.event_pieces.is_set():
                        self.torrent = copy.deepcopy(peer.torrent)
                        self._init_bitfield()
                        break

                if self.torrent.num_pieces > 0:
                    self._save_torrent()
                    self._init_files()
                    self._check_pieces()

            # init new peers
            for address in self.peer_addresses:
                if address not in self.peers:
                    self.peers[address] = Peer(
                        address,
                        self.torrent,
                        self.client_id,
                        self.client_reserved,
                        self.client_ext_support,
                    ).run_task()

            # update connection status
            if not self.event_connected.is_set() and any(peer.event_bitfield.is_set() for peer in self.peers.values()):
                self.event_connected.set()

    async def _comm_download(self) -> None:
        while not self._abort:
            await self.event_connected.wait()

            if self.event_files.is_set():
                missing_pieces = [
                    piece_index for piece_index in range(self.torrent.num_pieces) if not self.get_bitfield(piece_index)
                ]
                if len(missing_pieces) == 0:
                    self.event_complete.set()
                    break

                # get available pieces
                piece_count: dict[int, int] = {piece_index: 0 for piece_index in missing_pieces}
                for peer in self.peers.values():
                    if peer.event_bitfield.is_set():
                        for piece_index in missing_pieces:
                            if peer.get_bitfield_piece(piece_index):
                                piece_count[piece_index] += 1

                # sort by least available
                sorted_pieces = sorted(piece_count, key=lambda p: piece_count[p])
                download_tasks = {}
                for peer in self.peers.values():
                    peer_pieces = [
                        piece
                        for piece in sorted_pieces
                        if peer.event_bitfield.is_set() and peer.get_bitfield_piece(piece)
                    ]
                    if len(peer_pieces) > 0:
                        next_piece = peer_pieces.pop(0)
                        sorted_pieces.remove(next_piece)
                        download_tasks[next_piece] = peer.download_piece(next_piece)

                # download pieces
                if download_tasks:
                    download_pieces = dict(
                        zip(download_tasks.keys(), await asyncio.gather(*download_tasks.values()), strict=True),
                    )
                    for piece_index, piece in download_pieces.items():
                        if piece is not None:
                            self._write_piece(piece_index, piece)
                            self.set_bitfield(piece_index)

            await asyncio.sleep(1)

    async def _comm_task(self) -> None:
        self._abort = False
        self._running = True

        # unless DHT is implemented, we need to get peers from trackers
        if len(self.trackers) > 0:
            async with asyncio.TaskGroup() as tg:
                _ = tg.create_task(self._comm_trackers())
                _ = tg.create_task(self._comm_peers())
                _ = tg.create_task(self._comm_download())
        else:
            print("No trackers available, aborting...")
            self.event_failed.set()

        self._abort = False
        self._running = False

    def run_task(self) -> Self:
        self._task = asyncio.create_task(self._comm_task())
        return self

    def cancel_task(self) -> None:
        if self._task is not None:
            self._task.cancel()

    def abort(self) -> None:
        self._abort = True

    async def download_piece(self, piece_index: int) -> bool:
        if self.get_bitfield(piece_index):
            return True

        for peer in self.peers.values():
            if peer.event_bitfield.is_set() and peer.get_bitfield_piece(piece_index):
                piece = await peer.download_piece(piece_index)
                if piece is not None:
                    self._write_piece(piece_index, piece)
                    self.set_bitfield(piece_index)
                    break

        if self.get_bitfield(piece_index):
            for peer in self.peers.values():
                if peer.event_pieces.is_set():
                    await peer.send_have(piece_index)

        return self.get_bitfield(piece_index)

    async def download_all(self) -> bool:
        assert self.torrent.num_pieces > 0

        await asyncio.gather(
            *[
                self.download_piece(piece_index)
                for piece_index in range(self.torrent.num_pieces)
                if not self.get_bitfield(piece_index)
            ],
        )

        return (
            len([piece_index for piece_index in range(self.torrent.num_pieces) if self.get_bitfield(piece_index)])
            == self.torrent.num_pieces
        )
