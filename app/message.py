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
    message = bytearray(4 + (1 if id else 0) + payload_length)
    message[:4] = struct.pack("!I", (1 if id else 0) + payload_length)
    if id:
        message[4] = id
    if payload_length > 0:
        message[5:] = payload
    return message


def decode_message(message: bytes) -> tuple[int, bytes]:
    if len(message) < 4:
        # Signal incomplete message
        raise IndexError
    payload_length = struct.unpack("!I", message[:4])[0]
    if payload_length > 0:
        id = message[4] if payload_length > 1 else  -1
        payload = message[5:4+payload_length] if payload_length > 1 else b""
    return id, payload


def recv_bitfield(sock: socket.SocketType) -> bytes:
    id, bitfield = decode_message(sock.recv(1024))
    assert id == MsgID.BITFIELD
    return bitfield


def send_interested(sock: socket.SocketType) -> None:
    sock.send(encode_message(MsgID.INTERESTED, b""))


def recv_unchoke(sock: socket.SocketType) -> None:
    id, payload = decode_message(sock.recv(1024))
    assert id == MsgID.UNCHOKE
    assert len(payload) == 0


def send_request(sock: socket.SocketType, index: int, begin: int, length: int) -> None:
    msg_req = struct.pack("!IbIII", 13, MsgID.REQUEST, index, begin, length)
    sock.send(msg_req)
