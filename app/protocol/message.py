import struct
from enum import IntEnum


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


def encode_message(send_id: int | None=None, payload: bytes=b"") -> bytes:
    payload_length = len(payload)
    buffer = bytearray(4 + (1 if send_id else 0) + payload_length)
    buffer[:4] = struct.pack("!I", (1 if send_id else 0) + payload_length)
    if send_id:
        buffer[4] = send_id
    if payload_length > 0:
        buffer[5:] = payload
    return buffer


def decode_message(buffer: bytes) -> tuple[int, bytes, bytes]:
    len_buffer = len(buffer)

    if len_buffer < 4:
        # Signal incomplete message
        raise IndexError
    payload_length = struct.unpack("!I", buffer[:4])[0]

    if payload_length > len_buffer - 4:
        # Signal incomplete message
        raise IndexError

    recv_id, payload = -1, b""
    if payload_length > 0:
        recv_id = buffer[4]
    if payload_length > 1:
        payload = buffer[5:4+payload_length]

    # Drop parsed data from buffer
    buffer = buffer[4+payload_length:]

    return recv_id, payload, buffer
