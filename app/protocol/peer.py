import hashlib
import queue
import socket
import struct
import threading
import urllib.parse
import urllib.request

from .bencode import decode_bencode, encode_bencode
from .handshake import do_handshake
from .message import MsgID, recv_message, send_message


def get_peers(tracker: str, info_hash: bytes, file_length: int, peer_id: bytes, port: int=6881) -> list[tuple[str, int]]:
    query = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": file_length,
        "compact": 1,
    }
    url = tracker + "?" + urllib.parse.urlencode(query)
    res, _ = decode_bencode(urllib.request.urlopen(url).read())

    peers = []
    if "peers" in res:
        pos = 0
        while pos < len(res["peers"]):
            peer_ip = ".".join(map(str, res["peers"][pos:pos+4]))
            peer_port = int.from_bytes(res["peers"][pos+4:pos+6], "big")
            peers.append((peer_ip, peer_port))
            pos += 6

    return peers


def print_peers(peers: list[tuple[str, int]]) -> None:
    for peer in peers:
        print(f"{peer[0]}:{peer[1]}")


class Peer:
    def __init__(
        self,
        address: tuple[str, int],
        info_hash: bytes,
        client_id: bytes,
        client_reserved: bytes=b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_extension_support: dict | None=None,
    ) -> None:
        self.address = address
        self.client_id = client_id
        self.client_reserved = client_reserved
        self.info_hash = info_hash
        self.pieces_hash = None
        self.num_pieces = None
        self.file_length = None
        self.piece_length = None
        self.last_piece_length = None
        self.peer_id = None
        self.reserved = None
        self.supports_extension = None
        self.client_extension_support = client_extension_support
        self.extension_support = None
        self.extension_meta_id = None
        self.extension_meta_info = None
        self.bitfield = None
        self.peer_pieces = None
        self._comm_buffer = b""
        self._recv_length = 1024
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._send_queue = queue.Queue()
        self._recv_queue = queue.Queue()
        self._am_choke = True
        self._am_interested = False
        self._is_choke = True
        self._is_interested = False
        self._init_handshake = False
        self._init_bitfield = False
        self._init_extension = False
        self._init_meta = False
        self._init_download = False
        self._init_pieces = False
        self._init_comm = False
        self._stop_comm = False

    def __del__(self) -> None:
        if self._sock:
            self._sock.close()

    def _has_piece(self, piece_index: int) -> bool:
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (self.bitfield[bitfield_index] & byte_mask) != 0

    def initialize_pieces(self, pieces_hash: bytes, file_length: int, piece_length: int) -> None:
        if not self._init_comm:
            self.initialize()
        self.pieces_hash = pieces_hash
        self.num_pieces = len(self.pieces_hash) // 20
        self.file_length = file_length
        self.piece_length = piece_length
        self.last_piece_length = self.file_length - self.piece_length * (self.num_pieces - 1)
        self.peer_pieces = [
            piece_index
            for piece_index in range(self.num_pieces)
            if self._has_piece(piece_index)
        ]

        self._init_pieces = True

    def _recv_thread(self) -> None:
        while not self._stop_comm:
            try:
                recv_id, payload, self._comm_buffer = recv_message(self._sock, self._comm_buffer, self._recv_length)
            except TimeoutError:
                pass
            else:
                match recv_id:
                    case MsgID.KEEPALIVE:
                        pass
                    case MsgID.CHOKE:
                        assert len(payload) == 0
                        self._am_choke = True
                    case MsgID.UNCHOKE:
                        assert len(payload) == 0
                        self._am_choke = False
                    case MsgID.INTERESTED:
                        assert len(payload) == 0
                        self._is_interested = True
                    case MsgID.NOTINTERESTED:
                        assert len(payload) == 0
                        self._is_interested = False
                    case MsgID.BITFIELD:
                        self.bitfield = payload
                        self._init_bitfield = True
                    case MsgID.PIECE:
                        index = struct.unpack("!I", payload[0:4])[0]
                        begin = struct.unpack("!I", payload[4:8])[0]
                        block = payload[8:]
                        self._recv_queue.put((index, begin, block))
                    case MsgID.EXTENSION:
                        ext_id = payload[0]
                        ext_payload = decode_bencode(payload[1:])[0]

                        # handshake
                        if ext_id == 0:
                            self.extension_support = ext_payload

                            if "ut_metadata" in self.extension_support["m"]:
                                self.extension_meta_id = self.extension_support["m"]["ut_metadata"]
                                meta_dict = encode_bencode({"msg_type": 0, "piece": 0})
                                self._send_queue.put((MsgID.EXTENSION, self.extension_meta_id.to_bytes(1) + meta_dict))

                            self._init_extension = True
                        # metadata
                        elif self.extension_meta_id and ext_id == self.extension_meta_id:
                            self.extension_meta_info = ext_payload

                        else:
                            print("new ext msg", ext_id, ext_payload)

                    case _:
                        print("_recv_thread received unexpected", recv_id, MsgID(recv_id).name, len(payload), payload)

    def _send_thread(self) -> None:
        # Get peer info
        self.peer_id, self.reserved = do_handshake(self._sock, self.info_hash, self.client_id, self.client_reserved)
        self._init_handshake = True

        self.supports_extension = ((self.reserved[5] >> 4) & 1) == 1

        if self.supports_extension and self.client_extension_support:
            self._send_queue.put((MsgID.EXTENSION, b"\x00" + encode_bencode({"m": self.client_extension_support})))
        else:
            self._init_extension = True

        self._init_comm = True

        threading.Thread(target=self._recv_thread, daemon=True).start()

        while not self._stop_comm:
            if not self._send_queue.empty():
                send_id, send_payload = self._send_queue.get()
                send_message(send_id, self._sock, send_payload)

    def initialize(self) -> None:
        self._sock.connect(self.address)

        threading.Thread(target=self._send_thread, daemon=True).start()

        while not self._init_extension:
            pass

    def has_piece(self, piece_index: int) -> bool:
        if not self._init_comm:
            self.initialize()
        if not self._init_pieces:
            raise ValueError("piece info not initialized")
        if piece_index < 0 or piece_index >= self.num_pieces:
            return False
        return piece_index in self.peer_pieces

    def get_piece(self, piece_index: int) -> bytes | None:
        if not self.has_piece(piece_index):
            return None

        if not self._am_interested:
            self._am_interested = True
            self._send_queue.put((MsgID.INTERESTED, b""))

        while self._am_choke:
            pass

        piece_length = self.piece_length if piece_index < self.num_pieces - 1 else self.last_piece_length
        assert piece_length > 0

        piece = b""
        self._recv_length = 4*1024
        chunk_length = 16*1024
        current_begin = 0
        while current_begin < piece_length:
            eff_chunk_length = min(chunk_length, piece_length - current_begin)
            self._send_queue.put((MsgID.REQUEST, struct.pack("!III", piece_index, current_begin, eff_chunk_length)))

            while True:
                if not self._recv_queue.empty():
                    r_index, r_begin, r_block = self._recv_queue.get()
                    if r_index == piece_index and r_begin == current_begin:
                        piece += r_block
                        current_begin += len(r_block)
                        break
                    self._recv_queue.put((r_index, r_begin, r_block))

        self._recv_length = 1024

        r_piece_hash = hashlib.sha1(piece).digest()
        if r_piece_hash == self.pieces_hash[piece_index*20: piece_index*20+20]:
            return piece

        return None
