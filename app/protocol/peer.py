import asyncio
import hashlib
import queue
import struct
from typing import Any

from .bencode import decode_bencode, encode_bencode
from .handshake import decode_handshake, encode_handshake
from .message import MsgID, decode_message, encode_message


class Peer:
    def __init__(
        self,
        address: tuple[str, int],
        info_hash: bytes,
        client_id: bytes,
        client_reserved: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00",
        client_ext_support: dict[str | bytes, Any] | None = None,
    ) -> None:
        self.address = address
        self.info_hash = info_hash
        self.client_id = client_id
        self.client_reserved = client_reserved
        self.client_bitfield: bytes | None = None
        self.client_ext_support = client_ext_support

        # handshake
        self.peer_id: bytes | None = None
        self.peer_reserved: bytes | None = None
        self.peer_bitfield: bytes | None = None

        self.peer_supports_extension: bool | None = None
        self.peer_ext_support: dict[str | bytes, Any] | None = None
        self.peer_ext_meta_id = None
        self.peer_ext_meta_info = None

        self.file_name: str | None = None
        self.file_length: int | None = None
        self.piece_length: int | None = None
        self.pieces_hash: bytes | None = None
        self.num_pieces: int | None = None
        self.last_piece_length: int | None = None

        self._running: bool = False
        self._abort: bool = False
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._comm_buffer: bytes = b""
        self._recv_length: int = 1024
        self._send_queue: queue.Queue[tuple[MsgID, bytes]] = queue.Queue()
        self._recv_queue: queue.Queue[tuple[int, int, bytes]] = queue.Queue()

        self.event_am_interested = asyncio.Event()
        self.event_am_unchoke = asyncio.Event()
        self.event_is_interested = asyncio.Event()
        self.event_is_unchoke = asyncio.Event()

        self.event_handshake = asyncio.Event()
        self.event_extension = asyncio.Event()
        self.event_bitfield = asyncio.Event()
        self.event_metadata = asyncio.Event()
        self.event_pieces = asyncio.Event()

    def _client_has_piece(self, piece_index: int) -> bool:
        if self.client_bitfield is None:
            return False
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (self.client_bitfield[bitfield_index] & byte_mask) != 0

    def _peer_has_piece(self, piece_index: int) -> bool:
        assert self.peer_bitfield is not None
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (self.peer_bitfield[bitfield_index] & byte_mask) != 0

    async def _handshake(self) -> None:
        assert self._reader is not None
        assert self._writer is not None
        pstr = b"BitTorrent protocol"
        handshake_len = len(pstr) + 1 + 8 + 20 + 20

        self._writer.write(encode_handshake(pstr, self.info_hash, self.client_id, self.client_reserved))
        await self._writer.drain()

        while not self.event_handshake.is_set():
            self._comm_buffer += await self._reader.read(handshake_len)
            try:
                r_pstr, self.peer_reserved, r_info_hash, self.peer_id = decode_handshake(self._comm_buffer)
                assert pstr == r_pstr
                assert self.info_hash == r_info_hash
                self._comm_buffer = self._comm_buffer[handshake_len:]
                self.event_handshake.set()
            except IndexError:
                pass

    async def _ext_handshake(self) -> None:
        assert self.peer_reserved is not None
        self.supports_extension = ((self.peer_reserved[5] >> 4) & 1) == 1
        if self.supports_extension and self.client_ext_support:
            ext_handshake_payload = b"\x00" + encode_bencode(self.client_ext_support)
            self._send_queue.put((MsgID.EXTENSION, ext_handshake_payload))
        else:
            self.event_extension.set()

    async def _parse_message(self, recv_id: int, recv_payload: bytes) -> None:
        match recv_id:
            case MsgID.KEEPALIVE:
                pass
            case MsgID.CHOKE:
                assert len(recv_payload) == 0
                self.event_am_unchoke.clear()
            case MsgID.UNCHOKE:
                assert len(recv_payload) == 0
                self.event_am_unchoke.set()
            case MsgID.INTERESTED:
                assert len(recv_payload) == 0
                self.event_is_interested.set()
            case MsgID.NOTINTERESTED:
                assert len(recv_payload) == 0
                self.event_is_interested.clear()
            case MsgID.BITFIELD:
                self.peer_bitfield = recv_payload
                self.event_bitfield.set()
                # if self.client_bitfield is None:
                #     self.client_bitfield = int(0).to_bytes(len(self.peer_bitfield))
                # self._send_queue.put((MsgID.BITFIELD, self.client_bitfield))
            case MsgID.PIECE:
                index = struct.unpack("!I", recv_payload[0:4])[0]
                begin = struct.unpack("!I", recv_payload[4:8])[0]
                block = recv_payload[8:]
                self._recv_queue.put((index, begin, block))
            case MsgID.EXTENSION:
                ext_id = recv_payload[0]
                ext_payload = recv_payload[1:]
                # handshake
                if ext_id == 0:
                    payload = decode_bencode(ext_payload)[0]
                    assert isinstance(payload, dict)
                    self.peer_ext_support = payload
                    if "ut_metadata" in self.peer_ext_support["m"]:
                        self.peer_ext_meta_id = self.peer_ext_support["m"]["ut_metadata"]
                        assert self.peer_ext_meta_id is not None
                        meta_dict = encode_bencode({"msg_type": 0, "piece": 0})
                        self._send_queue.put((MsgID.EXTENSION, self.peer_ext_meta_id.to_bytes(1) + meta_dict))
                    self.event_extension.set()
                # metadata
                elif self.peer_ext_meta_id and ext_id == self.client_ext_support["m"]["ut_metadata"]:
                    payload_length = len(ext_payload)
                    peer_meta_dict, payload_counter = decode_bencode(ext_payload)
                    if peer_meta_dict["msg_type"] == 1 and payload_counter < payload_length:
                        self.peer_ext_meta_info, _ = decode_bencode(ext_payload, payload_counter)
                        await self.initialize_pieces(
                            self.peer_ext_meta_info["pieces"],
                            self.peer_ext_meta_info["length"],
                            self.peer_ext_meta_info["piece length"],
                            self.peer_ext_meta_info["name"],
                        )
                        self.event_metadata.set()
                # unexpected
                else:
                    print("new ext msg id", ext_id, ext_payload)

            case _:
                print("received unexpected", recv_id, MsgID(recv_id).name, len(recv_payload), recv_payload)

    async def _comm_recv(self) -> None:
        assert self._reader is not None
        while not self._abort:
            await asyncio.sleep(0)
            # try to parse one message
            try:
                recv_id, recv_payload, self._comm_buffer = decode_message(self._comm_buffer)
            except IndexError:
                # Incomplete message
                self._comm_buffer += await self._reader.read(self._recv_length)
            else:
                # print("received", recv_id, MsgID(recv_id).name, len(recv_payload), recv_payload)
                await self._parse_message(recv_id, recv_payload)

    async def _comm_send(self) -> None:
        assert self._writer is not None
        while not self._abort:
            await asyncio.sleep(0)
            # send one message from queue
            if not self._send_queue.empty():
                send_id, send_payload = self._send_queue.get()
                # print("sending", send_id, MsgID(send_id).name, len(send_payload), send_payload)
                self._writer.write(encode_message(send_id, send_payload))
                await self._writer.drain()

    async def _comm_task(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(*self.address)
        await self._handshake()
        await self._ext_handshake()

        self._abort = False
        self._running = True

        async with asyncio.TaskGroup() as tg:
            _ = tg.create_task(self._comm_recv())
            _ = tg.create_task(self._comm_send())

        self._running = False

    def run_task(self) -> asyncio.Task[None]:
        return asyncio.create_task(self._comm_task())

    def abort(self) -> None:
        self._abort = True

    async def initialize_pieces(
        self, pieces_hash: bytes, file_length: int, piece_length: int, file_name: str = ""
    ) -> None:
        await self.event_bitfield.wait()

        self.file_name = file_name
        self.pieces_hash = pieces_hash
        self.num_pieces = len(self.pieces_hash) // 20
        self.file_length = file_length
        self.piece_length = piece_length
        self.last_piece_length = self.file_length - self.piece_length * (self.num_pieces - 1)
        self.peer_pieces = [piece_index for piece_index in range(self.num_pieces) if self._peer_has_piece(piece_index)]

        self.event_pieces.set()

    def has_piece(self, piece_index: int) -> bool:
        assert self.num_pieces is not None
        if not self.event_pieces.is_set():
            raise ValueError("pieces info not initialized")
        if piece_index < 0 or piece_index >= self.num_pieces:
            return False
        return piece_index in self.peer_pieces

    async def get_piece(self, piece_index: int) -> bytes | None:
        assert self.pieces_hash is not None
        assert self.num_pieces is not None
        assert self.piece_length is not None
        assert self.last_piece_length is not None

        if not self.has_piece(piece_index):
            return None

        if not self.event_am_interested.is_set():
            self.event_am_interested.set()
            self._send_queue.put((MsgID.INTERESTED, b""))

        await self.event_unchoke.wait()

        piece_length = self.piece_length if piece_index < self.num_pieces - 1 else self.last_piece_length
        assert piece_length > 0

        piece = b""
        self._recv_length = 4 * 1024
        chunk_length = 16 * 1024
        current_begin = 0
        while current_begin < piece_length:
            eff_chunk_length = min(chunk_length, piece_length - current_begin)
            self._send_queue.put((MsgID.REQUEST, struct.pack("!III", piece_index, current_begin, eff_chunk_length)))

            while True:
                await asyncio.sleep(0)
                if not self._recv_queue.empty():
                    r_index, r_begin, r_block = self._recv_queue.get()
                    if r_index == piece_index and r_begin == current_begin:
                        piece += r_block
                        current_begin += len(r_block)
                        break
                    self._recv_queue.put((r_index, r_begin, r_block))

        self._recv_length = 1024

        r_piece_hash = hashlib.sha1(piece).digest()
        if r_piece_hash == self.pieces_hash[piece_index * 20 : piece_index * 20 + 20]:
            return piece

        return None
