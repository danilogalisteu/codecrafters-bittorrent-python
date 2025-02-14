import struct
from enum import IntEnum

MSG_ID_EXT_HANDSHAKE = 0
METADATA_BLOCK_SIZE = 16384


class MsgID(IntEnum):
    KEEPALIVE = -1
    CHOKE = 0
    UNCHOKE = 1
    INTERESTED = 2
    NOTINTERESTED = 3
    HAVE = 4
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7
    CANCEL = 8
    PORT = 9
    EXTENSION = 20


class MsgExtType(IntEnum):
    REQUEST = 0
    DATA = 1
    REJECT = 2


def encode_message(send_id: int, payload: bytes = b"") -> bytes:
    if send_id == MsgID.KEEPALIVE:
        return struct.pack("!I", 0)

    if send_id in (MsgID.CHOKE, MsgID.UNCHOKE, MsgID.INTERESTED, MsgID.NOTINTERESTED):
        return struct.pack("!IB", 1, send_id)

    payload_length = len(payload)
    return struct.pack(f"!IB{payload_length}s", 1 + payload_length, send_id, payload)


def decode_message(buffer: bytes) -> tuple[int, bytes, bytes]:
    len_buffer = len(buffer)

    if len_buffer < 4:
        # Signal incomplete message
        raise IndexError

    payload_length = struct.unpack("!I", buffer[:4])[0]
    if payload_length > len_buffer - 4:
        # Signal incomplete message
        raise IndexError

    recv_id, payload = MsgID.KEEPALIVE, b""
    if payload_length > 0:
        recv_id = MsgID(buffer[4])
    if payload_length > 1:
        payload = buffer[5 : 4 + payload_length]

    # Drop parsed data from buffer
    buffer = buffer[4 + payload_length :]

    return recv_id, payload, buffer
