import hashlib

from bencode import encode_bencode, decode_bencode


def parse_metainfo_pieces(pieces: bytes) -> list[bytes]:
    pos = 0
    pieces_list = []
    while pos < len(pieces):
        pieces_list.append(pieces[pos:pos+20])
        pos += 20
    return pieces_list


def get_metainfo(file_name: str) -> dict:
    with open(file_name, "rb") as file:
        metainfo, _ = decode_bencode(file.read())
        return metainfo


def print_info(metainfo: dict):
    hash = hashlib.sha1(encode_bencode(metainfo["info"])).hexdigest()
    print(f"Tracker URL: {metainfo['announce']}")
    print(f"Length: {metainfo['info']['length']}")
    print(f"Info Hash: {hash}")
    print(f"Piece Length: {metainfo['info']['piece length']}")
    print("Piece Hashes:")
    for piece in parse_metainfo_pieces(metainfo["info"]["pieces"]):
        print(piece.hex())
