import hashlib
import pathlib
from base64 import b32decode
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Self
from urllib.parse import parse_qs, urlparse

from .bencode import decode_bencode, encode_bencode


@dataclass
class FileInfo:
    path: str
    length: int
    offset: int
    md5: str = ""
    sha1: str = ""
    crc32: str = ""
    mtime: datetime = datetime.min


@dataclass
class TorrentInfo:
    tracker: str = ""
    tracker_list: list[list[str]] = field(default_factory=list)

    info_hash: bytes = b""
    name: str = ""
    piece_length: int = 0
    pieces_hash: bytes = b""
    files: list[FileInfo] = field(default_factory=list)

    private: bool = False
    encoding: str = ""
    comment: str = ""
    created_by: str = ""
    creation_date: datetime = datetime.min

    @classmethod
    def from_file(cls, file_name: str) -> Self | None:
        with pathlib.Path(file_name).open("rb") as metadata:
            metainfo, _ = decode_bencode(metadata.read())
            assert isinstance(metainfo, dict)

            display_name = metainfo["info"].get("name", "")

            if "length" in metainfo["info"]:
                # single
                files = [FileInfo(path=display_name, length=metainfo["info"]["length"], offset=0)]
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
                info_hash=hashlib.sha1(encode_bencode(metainfo["info"])).digest(),
                name=display_name,
                piece_length=metainfo["info"]["piece length"],
                pieces_hash=metainfo["info"]["pieces"],
                files=files,
                private=metainfo["info"].get("private", "0") == "1",
                encoding=metainfo.get("encoding", ""),
                comment=metainfo.get("comment", ""),
                created_by=metainfo.get("created by", ""),
                creation_date=datetime.fromtimestamp(int(metainfo.get("creation date", "0")), UTC),
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

    def show_info(self) -> None:
        print(f"Tracker URL: {self.tracker}")
        print(f"File name: {self.name}")
        print(f"Length: {self.files[0].length}")
        print(f"Info Hash: {self.info_hash.hex()}")
        print(f"Piece Length: {self.piece_length}")
        print("Piece Hashes:")
        for piece_index in range(len(self.pieces_hash) // 20):
            print(self.pieces_hash[piece_index * 20 : piece_index * 20 + 20].hex())
