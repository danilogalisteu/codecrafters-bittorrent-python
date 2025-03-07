import asyncio
import hashlib
import math
import pathlib

from .metainfo import FileInfo, TorrentInfo


class FileManager:
    def __init__(
        self,
        torrent: TorrentInfo,
        download_folder: str = "./download",
        completed_folder: str = "./completed",
    ) -> None:
        self.torrent = torrent
        self.bitfield: bytearray | None = None
        self.download_folder = pathlib.Path(download_folder) / self.torrent.info_hash.hex()
        self.completed_folder = pathlib.Path(completed_folder) / self.torrent.info_hash.hex()

        self.event_bitfield = asyncio.Event()
        self.event_files = asyncio.Event()
        self.event_complete = asyncio.Event()

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
                self._init_files()
            else:
                print(f"Invalid torrent file: {torrent_path}")
                print(f"Expected info_hash: {self.torrent.info_hash.hex()}")
                print(f"Existing info_hash: {torrent_info.info_hash.hex()}")
                print("Removing file...")
                torrent_path.unlink()

    def _init_bitfield(self) -> None:
        assert self.torrent.num_pieces > 0
        self.bitfield = bytearray(
            (0).to_bytes(math.ceil(self.torrent.num_pieces / 8), byteorder="big", signed=False),
        )
        self.event_bitfield.set()

    def get_bitfield(self, piece_index: int) -> bool:
        assert self.event_bitfield.is_set()
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (self.bitfield[bitfield_index] & byte_mask) != 0

    def set_bitfield(self, piece_index: int) -> None:
        assert self.event_bitfield.is_set()
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        self.bitfield[bitfield_index] |= byte_mask

    def clear_bitfield(self, piece_index: int) -> None:
        assert self.event_bitfield.is_set()
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        self.bitfield[bitfield_index] &= ~byte_mask

    def _get_file_path(self, file_info: FileInfo) -> pathlib.Path:
        return self.download_folder / file_info.path

    def _init_files(self) -> None:
        assert self.torrent.files
        for file_info in self.torrent.files:
            file_path = self._get_file_path(file_info)
            if not file_path.exists():
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_bytes(b"\x00" * file_info.length)
        self.event_files.set()

    def _write_piece(self, piece_index: int, piece: bytes) -> int:
        assert self.event_files.is_set()
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
        assert self.event_files.is_set()
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
        for piece_index in range(self.torrent.num_pieces):
            if self._check_piece(piece_index):
                self.set_bitfield(piece_index)

        if all(self.get_bitfield(piece_index) for piece_index in range(self.torrent.num_pieces)):
            self.event_complete.set()
