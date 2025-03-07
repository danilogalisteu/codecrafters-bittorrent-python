import hashlib
import math
import pathlib
from base64 import b32decode
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Self
from urllib.parse import parse_qs, urlparse

from .bencode import decode_bencode, encode_bencode


@dataclass
class FileInfo:
    path: str
    length: int
    offset: int
    pieces: list[int] = field(default_factory=list)
    md5: str = ""
    sha1: str = ""
    crc32: str = ""
    mtime: datetime = datetime.min


@dataclass
class TorrentMeta:
    info_hash: bytes = b""
    name: str = ""
    private: bool = False
    total_length: int = 0
    num_pieces: int = 0
    piece_length: int = 0
    last_piece_length: int = 0
    pieces_hash: bytes = b""
    num_files: int = 0
    files: list[FileInfo] = field(default_factory=list)

    @staticmethod
    def parse_files(meta_info: dict[str | bytes, Any]) -> tuple[list[FileInfo], int]:
        display_name = meta_info.get("name", "")
        num_pieces = len(meta_info["pieces"]) // 20
        piece_length = meta_info["piece length"]

        if "length" in meta_info:
            total_length = meta_info["length"]
            return [
                FileInfo(path=display_name, length=total_length, offset=0, pieces=list(range(num_pieces))),
            ], total_length

        files = []
        file_offset = 0
        for file in meta_info["files"]:
            file_length = file["length"]
            file_path = "/".join(file["path"])
            if display_name:
                file_path = display_name + "/" + file_path
            file_info = FileInfo(
                path=file_path,
                length=file_length,
                offset=file_offset,
                pieces=list(
                    range(
                        int(math.floor(file_offset / piece_length)),
                        int(math.floor((file_offset + file_length) / piece_length)),
                    ),
                ),
                mtime=datetime.fromtimestamp(float(file["mtime"]), UTC) if "mtime" in file else datetime.min,
                md5=file.get("md5", ""),
                sha1=file.get("sha1", ""),
                crc32=file.get("crc32", ""),
            )
            files.append(file_info)
            file_offset += file_length

        return files, file_offset

    def find_piece(self, piece_index: int) -> list[FileInfo]:
        assert piece_index >= 0
        assert piece_index < self.num_pieces
        return [file_info for file_info in self.files if piece_index in file_info.pieces]

    def update_info(self, metadata: bytes) -> None:
        assert self.info_hash == hashlib.sha1(metadata).digest()
        meta_info, _ = decode_bencode(metadata, 0)
        assert isinstance(meta_info, dict)
        self.name = meta_info.get("name", "")
        self.private = meta_info.get("private", "0") == "1"
        self.piece_length = meta_info["piece length"]
        self.pieces_hash = meta_info["pieces"]
        self.files, self.total_length = self.parse_files(meta_info)
        self.num_files = len(self.files)
        self.num_pieces = len(meta_info["pieces"]) // 20
        self.last_piece_length = self.total_length - (self.num_pieces - 1) * self.piece_length


@dataclass
class TorrentInfo(TorrentMeta):
    tracker: str = ""
    tracker_list: list[list[str]] = field(default_factory=list)
    encoding: str = ""
    comment: str = ""
    created_by: str = ""
    creation_date: datetime = datetime.min

    @classmethod
    def from_file(cls, file_name: str) -> Self | None:
        with pathlib.Path(file_name).open("rb") as metadata:
            metainfo, _ = decode_bencode(metadata.read())
            assert isinstance(metainfo, dict)

            files, total_length = cls.parse_files(metainfo["info"])
            num_pieces = len(metainfo["info"]["pieces"]) // 20
            last_piece_length = total_length - (num_pieces - 1) * metainfo["info"]["piece length"]
            return cls(
                tracker=metainfo.get("announce", ""),
                tracker_list=metainfo.get("announce-list", []),
                info_hash=hashlib.sha1(encode_bencode(metainfo["info"])).digest(),
                name=metainfo["info"].get("name", ""),
                total_length=total_length,
                piece_length=metainfo["info"]["piece length"],
                last_piece_length=last_piece_length,
                num_pieces=num_pieces,
                pieces_hash=metainfo["info"]["pieces"],
                num_files=len(files),
                files=files,
                private=metainfo["info"].get("private", "0") == "1",
                encoding=metainfo.get("encoding", ""),
                comment=metainfo.get("comment", ""),
                created_by=metainfo.get("created by", ""),
                creation_date=datetime.fromtimestamp(float(metainfo["creation date"]), UTC)
                if "creation date" in metainfo
                else datetime.min,
            )

    @staticmethod
    def parse_magnet(url: str) -> tuple[str, list[str], bytes]:
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

        return display_name, tracker_urls, bytes.fromhex(info_hash_str)

    @classmethod
    def from_magnet(cls, magnet_link: str) -> Self:
        display_name, tracker_urls, info_hash = cls.parse_magnet(magnet_link)
        return cls(
            tracker_list=[tracker_urls],
            info_hash=info_hash,
            name=display_name,
        )

    def to_file(self, file_name: pathlib.Path) -> int | None:
        metadata: dict[str | bytes, Any] = {}
        if self.tracker:
            metadata["announce"] = self.tracker
        if self.tracker_list:
            metadata["announce-list"] = self.tracker_list
        if self.encoding:
            metadata["encoding"] = self.encoding
        if self.comment:
            metadata["comment"] = self.comment
        if self.created_by:
            metadata["created by"] = self.created_by
        if self.creation_date != datetime.min:
            metadata["creation date"] = int(self.creation_date.timestamp())

        metadata["info"] = {}
        if self.name:
            metadata["info"]["name"] = self.name
        if self.private:
            metadata["info"]["private"] = "1"
        metadata["info"]["piece length"] = self.piece_length
        metadata["info"]["pieces"] = self.pieces_hash
        if self.num_files > 1:
            metadata["info"]["files"] = []
            for file in self.files:
                path = file.path.split("/")
                if self.name in path:
                    path.remove(self.name)
                file_info = {
                    "path": path,
                    "length": file.length,
                }
                if file.md5:
                    file_info["md5"] = file.md5
                if file.sha1:
                    file_info["sha1"] = file.sha1
                if file.crc32:
                    file_info["crc32"] = file.crc32
                if file.mtime != datetime.min:
                    file_info["mtime"] = int(file.mtime.timestamp())

                metadata["info"]["files"].append(file_info)
        else:
            metadata["info"]["length"] = self.total_length

        with file_name.open("wb") as fp:
            return fp.write(encode_bencode(metadata))

    def show_info(self) -> None:
        print(f"Tracker URL: {self.tracker}")
        print(f"Display name: {self.name}")
        print(f"Length: {self.files[0].length}")
        print(f"Info Hash: {self.info_hash.hex()}")
        print(f"Piece Length: {self.piece_length}")
        print("Piece Hashes:")
        for piece_index in range(len(self.pieces_hash) // 20):
            print(self.pieces_hash[piece_index * 20 : piece_index * 20 + 20].hex())
