import hashlib
import pathlib

from .bencode import decode_bencode, encode_bencode


def load_metainfo(file_name: str, show_info: bool=False) -> tuple[str, bytes, bytes, int, int] | None:
    with pathlib.Path(file_name).open("rb") as file:
        metainfo, _ = decode_bencode(file.read())
        assert isinstance(metainfo, dict)
        tracker = metainfo["announce"]
        info_hash = hashlib.sha1(encode_bencode(metainfo["info"])).digest()
        pieces_hash = metainfo["info"]["pieces"]
        file_length = metainfo["info"]["length"]
        piece_length = metainfo["info"]["piece length"]

        if show_info:
            print(f"Tracker URL: {tracker}")
            print(f"Length: {file_length}")
            print(f"Info Hash: {info_hash.hex()}")
            print(f"Piece Length: {piece_length}")
            print("Piece Hashes:")
            for piece_index in range(len(pieces_hash) // 20):
                print(pieces_hash[piece_index*20:piece_index*20+20].hex())

        return tracker, info_hash, pieces_hash, file_length, piece_length
