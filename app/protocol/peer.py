import asyncio
import hashlib
import queue
import struct
import threading

from .bencode import decode_bencode, encode_bencode
from .handshake import decode_handshake, encode_handshake
from .message import MsgID, decode_message, encode_message


class Peer:
    def __init__(
        self,
        address: tuple[str, int],
        info_hash: bytes,
        client_id: bytes,
        client_reserved: bytes=b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict | None=None,
    ) -> None:
        self.address = address
        self.info_hash = info_hash
        self.client_id = client_id
        self.client_reserved = client_reserved

        # handshake
        self.peer_id = None
        self.peer_reserved = None

        self.bitfield = None
        self.peer_supports_extension = None
        self.client_ext_support = client_ext_support
        self.peer_ext_support = None
        self.peer_ext_meta_id = None
        self.peer_ext_meta_info = None

        self.pieces_hash = None
        self.num_pieces = None
        self.file_length = None
        self.piece_length = None
        self.last_piece_length = None

        self._comm_task = None
        self._running = False
        self._abort = False
        self._reader = None
        self._writer = None
        self._comm_buffer = b""
        self._recv_length = 1024
        self._send_queue = queue.Queue()
        self._recv_queue = queue.Queue()

        self._am_choke = True
        self._am_interested = False
        self._is_choke = True
        self._is_interested = False

        self._init_handshake = False
        self._init_extension = False
        self._init_metadata = False
        self._init_pieces = False

    def _bitfield_has_piece(self, piece_index: int) -> bool:
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (self.bitfield[bitfield_index] & byte_mask) != 0

    async def _handshake(self) -> None:
        pstr = b"BitTorrent protocol"
        handshake_len = len(pstr) + 1 + 8 + 20 + 20

        self._writer.write(encode_handshake(pstr, self.info_hash, self.client_id, self.client_reserved))
        await self._writer.drain()

        while not self._init_handshake:
            self._comm_buffer += await self._reader.read(handshake_len)
            try:
                r_pstr, self.peer_reserved, r_info_hash, self.peer_id = decode_handshake(self._comm_buffer)
                assert pstr == r_pstr
                assert self.info_hash == r_info_hash
                self._comm_buffer = self._comm_buffer[handshake_len:]
                self._init_handshake = True
                print("handshake OK")
            except IndexError:
                pass

    async def _ext_handshake(self) -> None:
        self.supports_extension = ((self.peer_reserved[5] >> 4) & 1) == 1
        if self.supports_extension and self.client_ext_support:
            ext_handshake_payload = b"\x00" + encode_bencode({"m": self.client_ext_support})
            self._send_queue.put((MsgID.EXTENSION, ext_handshake_payload))
        else:
            self._init_extension = True
            print("ext handshake NOK")

    async def _comm_loop(self) -> None:
            # send one message from queue
            if not self._send_queue.empty():
                send_id, send_payload = self._send_queue.get()
                print("sending", send_id, MsgID(send_id).name, len(send_payload), send_payload)
                self._writer.write(encode_message(send_id, send_payload))
                await self._writer.drain()

            # try to parse one message
            try:
                recv_id, recv_payload, self._comm_buffer = decode_message(self._comm_buffer)
                print("received", recv_id, MsgID(recv_id).name, len(recv_payload), recv_payload)
            except IndexError:
                # Incomplete message
                self._comm_buffer += await self._reader.read(self._recv_length)
            else:
                match recv_id:
                    case MsgID.KEEPALIVE:
                        pass
                    case MsgID.CHOKE:
                        assert len(recv_payload) == 0
                        self._am_choke = True
                    case MsgID.UNCHOKE:
                        assert len(recv_payload) == 0
                        self._am_choke = False
                    case MsgID.INTERESTED:
                        assert len(recv_payload) == 0
                        self._is_interested = True
                    case MsgID.NOTINTERESTED:
                        assert len(recv_payload) == 0
                        self._is_interested = False
                    case MsgID.BITFIELD:
                        self.bitfield = recv_payload
                    case MsgID.PIECE:
                        index = struct.unpack("!I", recv_payload[0:4])[0]
                        begin = struct.unpack("!I", recv_payload[4:8])[0]
                        block = recv_payload[8:]
                        self._recv_queue.put((index, begin, block))
                    case MsgID.EXTENSION:
                        ext_id = recv_payload[0]
                        ext_payload = decode_bencode(recv_payload[1:])[0]
                        # handshake
                        if ext_id == 0:
                            self.peer_ext_support = ext_payload
                            if "ut_metadata" in self.peer_ext_support["m"]:
                                self.peer_ext_meta_info = b""
                                self.peer_ext_meta_id = self.peer_ext_support["m"]["ut_metadata"]
                                meta_dict = encode_bencode({"msg_type": 0, "piece": 0})
                                self._send_queue.put((MsgID.EXTENSION, self.peer_ext_meta_id.to_bytes(1) + meta_dict))
                            self._init_extension = True
                            print("ext handshake OK")
                        # metadata
                        elif self.peer_ext_meta_id and ext_id == self.peer_ext_meta_id:
                            self.peer_ext_meta_info += ext_payload
                            self._init_metadata = True
                        # unexpected
                        else:
                            print("new ext msg", ext_id, ext_payload)

                    case _:
                        print("received unexpected", recv_id, MsgID(recv_id).name, len(recv_payload), recv_payload)

    async def _initialize(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(*self.address)
        await self._handshake()
        await self._ext_handshake()

        self._abort = False
        self._running = True

        while not self._abort:
            await asyncio.sleep(0.1)
            await self._comm_loop()

        self._running = False

    def initialize(self) -> None:
        self._comm_task = threading.Thread(target=asyncio.run, args=(self._initialize(),), daemon=True)
        self._comm_task.start()

    def abort(self) -> None:
        self._abort = True
        while self._running:
            pass

    def initialize_pieces(self, pieces_hash: bytes, file_length: int, piece_length: int) -> None:
        while not self.bitfield:
            pass

        self.pieces_hash = pieces_hash
        self.num_pieces = len(self.pieces_hash) // 20
        self.file_length = file_length
        self.piece_length = piece_length
        self.last_piece_length = self.file_length - self.piece_length * (self.num_pieces - 1)
        self.peer_pieces = [
            piece_index
            for piece_index in range(self.num_pieces)
            if self._bitfield_has_piece(piece_index)
        ]

        self._init_pieces = True

    def has_piece(self, piece_index: int) -> bool:
        if not self._init_pieces:
            raise ValueError("pieces info not initialized")
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
