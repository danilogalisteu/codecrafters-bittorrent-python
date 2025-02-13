import hashlib
import pathlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self

from .bencode import decode_bencode, encode_bencode


@dataclass
class FileInfo:
    path: str
    length: int
    offset: int = 0
    mtime: datetime = datetime.min
    md5: str = ""
    sha1: str = ""
    crc32: str = ""


@dataclass
class TorrentInfo:
    tracker: str
    tracker_list: list[list[str]]

    comment: str
    created_by: str
    creation_date: datetime
    encoding: str

    info_hash: bytes
    name: str
    private: bool
    piece_length: int
    pieces_hash: bytes
    files: list[FileInfo]

    @classmethod
    def from_file(cls, file_name: str) -> Self | None:
        with pathlib.Path(file_name).open("rb") as metadata:
            metainfo, _ = decode_bencode(metadata.read())
            assert isinstance(metainfo, dict)

            display_name = metainfo["info"].get("name", "")

            if "length" in metainfo["info"]:
                # single
                files = [FileInfo(path=display_name, length=metainfo["info"]["length"])]
            else:
                # multi
                files = []
                file_offset = 0
                for file in metainfo["info"]["files"]:
                    file_length = file["length"]
                    file_path = "/".join(file["path"])
                    if display_name:
                        file_path = display_name + "/" + file_path
                    torrent_file = FileInfo(
                        path=file_path,
                        length=file_length,
                        offset=file_offset,
                        mtime=datetime.fromtimestamp(int(file.get("mtime")), UTC) if "mtime" in file else datetime.min,
                        md5=file.get("md5", ""),
                        sha1=file.get("sha1", ""),
                        crc32=file.get("crc32", ""),
                    )
                    files.append(torrent_file)
                    file_offset += file_length

            return cls(
                tracker=metainfo.get("announce", ""),
                tracker_list=metainfo.get("announce-list", []),
                comment=metainfo.get("comment", ""),
                created_by=metainfo.get("created by", ""),
                creation_date=datetime.fromtimestamp(int(metainfo.get("creation date", "0")), UTC),
                encoding=metainfo.get("encoding", ""),
                info_hash=hashlib.sha1(encode_bencode(metainfo["info"])).digest(),
                name=metainfo["info"].get("name", ""),
                private=metainfo["info"].get("private", "0") == "1",
                piece_length=metainfo["info"]["piece length"],
                pieces_hash=metainfo["info"]["pieces"],
                files=files,
            )

    def show_info(self) -> None:
        print(f"Tracker URL: {self.tracker}")
        print(f"File name: {self.name}")
        print(f"Length: {self.files[0].length}")
        print(f"Info Hash: {self.info_hash.hex()}")
        print(f"Piece Length: {self.piece_length}")
        print("Piece Hashes:")
        for piece_index in range(len(self.pieces_hash) // 20):
            print(self.pieces_hash[piece_index * 20 : piece_index * 20 + 20].hex())
