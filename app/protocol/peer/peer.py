"""
https://www.bittorrent.org/beps/bep_0010.html
https://www.bittorrent.org/beps/bep_0009.html
"""

import asyncio
import hashlib
import math
import struct
from typing import Any, Self

from app.protocol.bencode import decode_bencode, encode_bencode

from .handshake import decode_handshake, encode_handshake
from .messages import METADATA_BLOCK_SIZE, MSG_ID_EXT_HANDSHAKE, MsgExtType, MsgID, decode_message, encode_message


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
        self.client_ext_support = client_ext_support

        # handshake
        self.peer_id: bytes | None = None
        self.peer_reserved: bytes | None = None
        self.peer_bitfield: bytearray | None = None

        self.peer_supports_extension: bool | None = None
        self.peer_ext_support: dict[str | bytes, Any] | None = None
        self.peer_ext_meta_id: int | None = None
        self.peer_ext_meta_size: int | None = None
        self.peer_ext_meta_data: dict[int, bytes] | None = None
        self.peer_ext_meta_info: dict[str | bytes, Any] | None = None

        self.file_name: str | None = None
        self.file_length: int | None = None
        self.piece_length: int | None = None
        self.pieces_hash: bytes | None = None
        self.last_piece_length: int | None = None
        self.num_pieces: int | None = None

        self._task: asyncio.Task[None] | None = None
        self._running: bool = False
        self._abort: bool = False
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._comm_buffer: bytes = b""
        self._recv_length: int = 1024
        self._send_queue: asyncio.Queue[tuple[MsgID, bytes]] = asyncio.Queue()
        self._recv_queue: asyncio.Queue[tuple[int, int, bytes]] = asyncio.Queue()

        self.event_am_interested = asyncio.Event()
        self.event_am_unchoke = asyncio.Event()
        self.event_is_interested = asyncio.Event()
        self.event_is_unchoke = asyncio.Event()

        self.event_handshake = asyncio.Event()
        self.event_extension = asyncio.Event()
        self.event_bitfield = asyncio.Event()
        self.event_metadata = asyncio.Event()
        self.event_pieces = asyncio.Event()

    def init_pieces(
        self,
        file_name: str,
        file_length: int,
        piece_length: int,
        pieces_hash: bytes,
    ) -> None:
        self.file_name = file_name
        self.pieces_hash = pieces_hash
        self.num_pieces = len(self.pieces_hash) // 20
        self.file_length = file_length
        self.piece_length = piece_length
        self.last_piece_length = self.file_length - self.piece_length * (self.num_pieces - 1)
        self.event_pieces.set()

    def get_bitfield_piece(self, piece_index: int) -> bool:
        assert self.peer_bitfield is not None
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        return (self.peer_bitfield[bitfield_index] & byte_mask) != 0

    def set_bitfield_piece(self, piece_index: int) -> None:
        assert self.peer_bitfield is not None
        bitfield_index = piece_index // 8
        byte_mask = 1 << (7 - piece_index % 8)
        self.peer_bitfield[bitfield_index] |= byte_mask

    async def send_keepalive(self) -> None:
        await self._send_queue.put((MsgID.KEEPALIVE, b""))

    async def send_is_choke(self) -> None:
        await self._send_queue.put((MsgID.CHOKE, b""))
        self.event_is_unchoke.clear()

    async def send_is_unchoke(self) -> None:
        await self._send_queue.put((MsgID.UNCHOKE, b""))
        self.event_is_unchoke.set()

    async def send_am_interested(self) -> None:
        await self._send_queue.put((MsgID.INTERESTED, b""))
        self.event_am_interested.set()

    async def send_am_notinterested(self) -> None:
        await self._send_queue.put((MsgID.NOTINTERESTED, b""))
        self.event_am_interested.clear()

    async def send_have(self, piece_index: int) -> None:
        await self._send_queue.put((MsgID.HAVE, piece_index.to_bytes(4, byteorder="big", signed=False)))

    async def send_bitfield(self, client_bitfield: bytes) -> None:
        await self._send_queue.put((MsgID.BITFIELD, client_bitfield))

    async def send_request(self, piece_index: int, begin: int, length: int) -> None:
        await self._send_queue.put((MsgID.REQUEST, struct.pack("!III", piece_index, begin, length)))

    async def send_piece(self, piece_index: int, begin: int, block: bytes) -> None:
        await self._send_queue.put((MsgID.PIECE, struct.pack(f"!II{len(block)}s", piece_index, begin, block)))

    async def send_cancel(self, piece_index: int, begin: int, length: int) -> None:
        await self._send_queue.put((MsgID.CANCEL, struct.pack("!III", piece_index, begin, length)))

    async def send_port(self, port: int) -> None:
        await self._send_queue.put((MsgID.PORT, struct.pack("!H", port)))

    async def send_extension(self, ext_id: int, ext_payload: bytes) -> None:
        await self._send_queue.put((MsgID.EXTENSION, struct.pack(f"!B{len(ext_payload)}s", ext_id, ext_payload)))

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
            await self.send_extension(MSG_ID_EXT_HANDSHAKE, encode_bencode(self.client_ext_support))
        else:
            self.event_extension.set()

    async def _parse_ext_handshake(self, ext_payload: bytes) -> int:
        payload, payload_counter = decode_bencode(ext_payload)

        # BEP0010
        assert isinstance(payload, dict)
        self.peer_ext_support = payload
        assert "m" in self.peer_ext_support

        # BEP0009
        if "ut_metadata" in self.peer_ext_support["m"] and "metadata_size" in self.peer_ext_support:
            self.peer_ext_meta_id = self.peer_ext_support["m"]["ut_metadata"]
            self.peer_ext_meta_size = self.peer_ext_support["metadata_size"]
            assert isinstance(self.peer_ext_meta_id, int)
            assert isinstance(self.peer_ext_meta_size, int)

            self.peer_ext_meta_data = {}
            num_meta_pieces = math.ceil(self.peer_ext_meta_size / METADATA_BLOCK_SIZE)
            for piece_index in range(num_meta_pieces):
                await self.send_extension(
                    self.peer_ext_meta_id,
                    encode_bencode({"msg_type": MsgExtType.REQUEST, "piece": piece_index}),
                )
                self.peer_ext_meta_data[piece_index] = b""

        self.event_extension.set()
        return payload_counter

    async def _parse_ext_metadata(self, ext_payload: bytes) -> int:
        payload_length = len(ext_payload)
        payload, payload_counter = decode_bencode(ext_payload)

        # BEP0009
        assert isinstance(payload, dict)
        peer_meta_dict = payload
        assert "msg_type" in peer_meta_dict
        assert "piece" in peer_meta_dict
        assert "total_size" in peer_meta_dict
        assert isinstance(self.peer_ext_meta_data, dict)

        if peer_meta_dict["msg_type"] == MsgExtType.DATA and peer_meta_dict["total_size"] == self.peer_ext_meta_size:
            piece_index = peer_meta_dict["piece"]
            metadata_payload_length = min(self.peer_ext_meta_size, METADATA_BLOCK_SIZE)
            assert payload_counter + metadata_payload_length <= payload_length
            self.peer_ext_meta_data[piece_index] = ext_payload[
                payload_counter : payload_counter + metadata_payload_length
            ]
            payload_counter += metadata_payload_length

        assert isinstance(self.peer_ext_meta_data, dict)
        if len([True for value in self.peer_ext_meta_data.values() if value == b""]) == 0:
            metadata = b""
            for piece_index in sorted(self.peer_ext_meta_data.keys()):
                metadata += self.peer_ext_meta_data[piece_index]

            assert hashlib.sha1(metadata).digest() == self.info_hash
            metadata_value, _ = decode_bencode(metadata, 0)
            assert isinstance(metadata_value, dict)
            self.peer_ext_meta_info = metadata_value
            self.init_pieces(
                self.peer_ext_meta_info["name"],
                self.peer_ext_meta_info["length"],
                self.peer_ext_meta_info["piece length"],
                self.peer_ext_meta_info["pieces"],
            )
            self.event_metadata.set()

        return payload_counter

    async def _parse_extension(self, ext_id: int, ext_payload: bytes) -> None:
        payload_length = len(ext_payload)
        # handshake
        if ext_id == MSG_ID_EXT_HANDSHAKE:
            payload_counter = await self._parse_ext_handshake(ext_payload)
            while payload_length > payload_counter:
                payload, payload_counter = decode_bencode(ext_payload, payload_counter)
                print("ext handshake extra", payload_length, payload_counter, payload)

        # metadata
        elif self.peer_ext_meta_id and ext_id == self.peer_ext_meta_id:
            payload_counter = await self._parse_ext_metadata(ext_payload)
            while payload_length > payload_counter:
                payload, payload_counter = decode_bencode(ext_payload, payload_counter)
                print("ext metadata extra", payload_length, payload_counter, payload)

        # unexpected
        else:
            print("unexpected peer ext msg id", ext_id, ext_payload)
            payload_counter = 0
            while payload_length > payload_counter:
                payload, payload_counter = decode_bencode(ext_payload, payload_counter)
                print("ext unexpected", payload_length, payload_counter, payload)

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
            case MsgID.HAVE:
                assert len(recv_payload) == 4
                piece_index = struct.unpack("!I", recv_payload[0:4])[0]
                self.set_bitfield_piece(piece_index)
            case MsgID.BITFIELD:
                self.peer_bitfield = bytearray(recv_payload)
                self.event_bitfield.set()
            case MsgID.REQUEST:
                assert len(recv_payload) == 12
                # TODO handle request
                # index, begin, length = struct.unpack("!III", recv_payload)
            case MsgID.PIECE:
                assert len(recv_payload) > 8
                index, begin, block = struct.unpack(f"!II{len(recv_payload) - 8}s", recv_payload)
                await self._recv_queue.put((index, begin, block))
            case MsgID.CANCEL:
                assert len(recv_payload) == 12
                # TODO handle request
                # index, begin, length = struct.unpack("!III", recv_payload)
            case MsgID.PORT:
                assert len(recv_payload) == 2
                # TODO handle request
                # port = struct.unpack("!H", recv_payload)
            case MsgID.EXTENSION:
                assert len(recv_payload) > 1
                await self._parse_extension(recv_payload[0], recv_payload[1:])
            case _:
                print("unexpected peer msg id", recv_id, MsgID(recv_id).name, len(recv_payload), recv_payload)

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
                send_id, send_payload = await self._send_queue.get()
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

    def run_task(self) -> Self:
        self._task = asyncio.create_task(self._comm_task())
        return self

    def cancel_task(self) -> None:
        if self._task is not None:
            self._task.cancel()

    def abort(self) -> None:
        self._abort = True

    async def get_piece(self, piece_index: int) -> bytes | None:
        assert self.pieces_hash is not None
        assert self.num_pieces is not None
        assert self.piece_length is not None
        assert self.last_piece_length is not None

        if (
            (not self.event_pieces.is_set())
            or (piece_index < 0 or piece_index >= self.num_pieces)
            or (not self.get_bitfield_piece(piece_index))
        ):
            return None

        if not self.event_am_interested.is_set():
            await self.send_am_interested()

        await self.event_am_unchoke.wait()

        piece_length = self.piece_length if piece_index < self.num_pieces - 1 else self.last_piece_length
        assert piece_length > 0

        piece = b""
        self._recv_length = 4 * 1024
        chunk_length = 16 * 1024
        current_begin = 0
        while current_begin < piece_length:
            eff_chunk_length = min(chunk_length, piece_length - current_begin)

            await self.send_request(piece_index, current_begin, eff_chunk_length)

            while True:
                await asyncio.sleep(0)
                if not self._recv_queue.empty():
                    r_index, r_begin, r_block = await self._recv_queue.get()
                    if r_index == piece_index and r_begin == current_begin:
                        piece += r_block
                        current_begin += len(r_block)
                        break
                    await self._recv_queue.put((r_index, r_begin, r_block))

        self._recv_length = 1024

        r_piece_hash = hashlib.sha1(piece).digest()
        if r_piece_hash == self.pieces_hash[piece_index * 20 : piece_index * 20 + 20]:
            return piece

        return None
