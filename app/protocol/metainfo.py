import hashlib

from .bencode import encode_bencode, decode_bencode


def parse_metainfo_pieces(pieces: bytes) -> list[bytes]:
    pos = 0
    pieces_list = []
    while pos < len(pieces):
        pieces_list.append(pieces[pos:pos+20])
        pos += 20
    return pieces_list


def load_metainfo(file_name: str, show_info=False) -> tuple[dict, str, bytes, bytes, int, int] | None:
    with open(file_name, "rb") as file:
        metainfo, _ = decode_bencode(file.read())
        tracker = metainfo['announce']
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
            for piece in parse_metainfo_pieces(pieces_hash):
                print(piece.hex())

        return tracker, info_hash, pieces_hash, file_length, piece_length
