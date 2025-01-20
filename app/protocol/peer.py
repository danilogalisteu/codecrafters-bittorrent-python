import socket
import urllib.parse
import urllib.request

from .bencode import decode_bencode
from .handshake import do_handshake
from .message import MsgID, recv_message, send_message
from .metainfo import get_infohash, parse_metainfo_pieces
from .piece import recv_piece


def get_peers(tracker: str, info_hash: bytes, length: int, peer_id: bytes, port: int=6881):
    query = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": length,
        "compact": 1,
    }
    url = tracker + "?" + urllib.parse.urlencode(query)
    res, _ = decode_bencode(urllib.request.urlopen(url).read())

    peers = []
    if "peers" in res:
        pos = 0
        while pos < len(res["peers"]):
            peer_ip = ".".join(map(str, res['peers'][pos:pos+4]))
            peer_port = int.from_bytes(res['peers'][pos+4:pos+6], 'big')
            peers.append((peer_ip, peer_port))
            pos += 6

    return peers


def get_peers_from_metainfo(metainfo: dict, peer_id: bytes, port: int=6881) -> list[tuple[str, int]]:
    return get_peers(
        metainfo['announce'],
        get_infohash(metainfo),
        metainfo['info']['length'],
        peer_id,
        port,
    )


def print_peers(peers: list[tuple[str, int]]):
    for peer in peers:
        print(f"{peer[0]}:{peer[1]}")


class Peer():
    def __init__(
        self,
        address: tuple[str, int],
        metainfo: dict,
        client_id: bytes,
        client_reserved: bytes=b"\x00\x00\x00\x00\x00\x00\x00\x00"
    ) -> None:
        self.address = address
        self.client_id = client_id
        self.client_reserved = client_reserved
        self.info_hash = get_infohash(metainfo)
        self.pieces_hash = metainfo["info"]["pieces"]
        self.num_pieces = len(self.pieces_hash) // 20
        self.file_length = metainfo["info"]["length"]
        self.piece_length = metainfo["info"]["piece length"]
        self.last_piece_length = self.file_length - self.piece_length * (self.num_pieces - 1)
        self.peer_id = None
        self.reserved = None
        self.bitfield = None
        self.peer_pieces = None
        self._comm_buffer = b""
        self._sock = None
        self._initialized = False

    def __del__(self):
        if self._sock:
            self._sock.close()

    def _has_bitfield_piece(self, bitfield: bytes, piece_index: int) -> bool:
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (bitfield[bitfield_index] & byte_mask) != 0

    def initialize(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect(self.address)

        # Get peer info
        self.peer_id, self.reserved = do_handshake(self._sock, self.info_hash, self.client_id, self.client_reserved)
        self.bitfield = recv_message(MsgID.BITFIELD, self._sock, self._comm_buffer)

        self.peer_pieces = [
            piece_index
            for piece_index in range(self.num_pieces)
            if self._has_bitfield_piece(self.bitfield, piece_index)
        ]

        self._initialized = True

    def has_piece(self, piece_index: int) -> bool:
        if piece_index < 0 or piece_index >= self.num_pieces:
            return False
        if not self._initialized:
            self.initialize()
        return piece_index in self.peer_pieces

    def get_piece(self, piece_index: int) -> bytes | None:
        if not self.has_piece(piece_index):
            return

        send_message(MsgID.INTERESTED, self._sock)

        payload = recv_message(MsgID.UNCHOKE, self._sock, self._comm_buffer)
        assert len(payload) == 0

        piece_length = self.piece_length if piece_index < self.num_pieces - 1 else self.last_piece_length

        return recv_piece(self._sock, piece_index, self.pieces_hash[piece_index*20: piece_index*20+20], piece_length)
