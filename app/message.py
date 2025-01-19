from enum import IntEnum
import socket
import struct


class MsgID(IntEnum):
    KEEPALIVE = -1
    UNCHOKE = 1
    INTERESTED = 2
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7


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
    return id, payload


def recv_message(recv_id: int, sock: socket.SocketType, buffer: bytes) -> bytes:
    while True:
        try:
            id, payload = decode_message(buffer)
            # Drop parsed data
            parsed_length = 4 + (1 if id > -1 else 0) + len(payload)
            buffer = buffer[parsed_length:] if len(buffer) > parsed_length else b""
        except IndexError:
            # Incomplete message
            buffer += sock.recv(1024)
            continue
        if id == recv_id:
            break
    return payload


def send_message(send_id: int, sock: socket.SocketType, payload: bytes=b""):
    sock.send(encode_message(send_id, payload))


def send_request(sock: socket.SocketType, index: int, begin: int, length: int) -> None:
    msg_req = struct.pack("!IbIII", 13, MsgID.REQUEST, index, begin, length)
    sock.send(msg_req)
