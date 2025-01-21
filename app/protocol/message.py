from enum import IntEnum
import socket
import struct


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


def encode_message(id: int=None, payload: bytes=b"") -> bytes:
    payload_length = len(payload)
    buffer = bytearray(4 + (1 if id else 0) + payload_length)
    buffer[:4] = struct.pack("!I", (1 if id else 0) + payload_length)
    if id:
        buffer[4] = id
    if payload_length > 0:
        buffer[5:] = payload
    return buffer


def decode_message(buffer: bytes) -> tuple[int, bytes]:
    len_buffer = len(buffer)

    if len_buffer < 4:
        # Signal incomplete message
        raise IndexError
    payload_length = struct.unpack("!I", buffer[:4])[0]

    if payload_length > len_buffer - 4:
        # Signal incomplete message
        raise IndexError

    id, payload = -1, b""
    if payload_length > 0:
        id = buffer[4]
    if payload_length > 1:
        payload = buffer[5:4+payload_length]

    # Drop parsed data from buffer
    buffer = buffer[4+payload_length:]

    return id, payload, buffer


def recv_message(sock: socket.SocketType, buffer: bytes, recv_length: int=1024) -> tuple[int, bytes, bytes]:
    while True:
        try:
            id, payload, buffer = decode_message(buffer)
        except IndexError:
            # Incomplete message
            buffer += sock.recv(recv_length)
            continue
        print("received", id, MsgID(id).name, len(payload), payload)
        break
    return id, payload, buffer


def send_message(send_id: int, sock: socket.SocketType, payload: bytes=b""):
    print("sending", send_id, MsgID(send_id).name, len(payload), payload)
    sock.send(encode_message(send_id, payload))
