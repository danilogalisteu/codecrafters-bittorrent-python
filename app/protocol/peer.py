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
    def __init__(self, address: tuple[str, int], metainfo: dict, client_id: bytes) -> None:
        self.address = address
        self.metainfo = metainfo
        self.client_id = client_id
        self.info_hash = get_infohash(self.metainfo)
        self.pieces_hash = parse_metainfo_pieces(self.metainfo["info"]["pieces"])
        self.num_pieces = len(self.pieces_hash)
        self.piece_length = self.metainfo["info"]["piece length"]
        self.last_piece_length = self.metainfo["info"]["length"] - self.metainfo["info"]["piece length"] * (self.num_pieces - 1)
        self.peer_info = None
        self.peer_pieces = None
        self._initialized = False

    def _get_peer_info(self) -> tuple[bytes, bytes]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(self.address)
            r_peer_id, _ = do_handshake(sock, self.info_hash, self.client_id)
            comm_buffer = b""
            r_bitfield = recv_message(MsgID.BITFIELD, sock, comm_buffer)
            return r_peer_id, r_bitfield

    def _has_bitfield_piece(self, bitfield: bytes, piece_index: int) -> bool:
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (bitfield[bitfield_index] & byte_mask) != 0

    def initialize(self) -> None:
        self.peer_info = self._get_peer_info()
        self.peer_pieces = [
            piece_index
            for piece_index in range(self.num_pieces)
            if self._has_bitfield_piece(self.peer_info[1], piece_index)
        ]

    def valid_piece(self, piece_index: int) -> bool:
        return piece_index >= 0 and piece_index < self.num_pieces

    def has_piece(self, piece_index: int) -> bool:
        if not self.valid_piece(piece_index):
            return False
        if not self._initialized:
            self.initialize()
            self._initialized = True
        return piece_index in self.peer_pieces

    def get_piece(self, piece_index: int) -> bytes | None:
        if not self._initialized:
            self.initialize()
            self._initialized = True

        if self.has_piece(piece_index):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(self.address)

                _, _ = do_handshake(sock, self.info_hash, self.client_id)

                comm_buffer = b""

                bitfield = recv_message(MsgID.BITFIELD, sock, comm_buffer)
                assert self._has_bitfield_piece(bitfield, piece_index)

                send_message(MsgID.INTERESTED, sock)

                payload = recv_message(MsgID.UNCHOKE, sock, comm_buffer)
                assert len(payload) == 0

                piece_length = self.piece_length if piece_index < self.num_pieces - 1 else self.last_piece_length
                
                return recv_piece(sock, piece_index, self.pieces_hash[piece_index], piece_length)
