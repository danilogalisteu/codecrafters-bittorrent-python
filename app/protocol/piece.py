import hashlib
import socket
import struct

from .message import MsgID, recv_message, send_message
from .metainfo import parse_metainfo_pieces


def send_request(sock: socket.SocketType, index: int, begin: int, length: int) -> None:
    payload = struct.pack("!III", index, begin, length)
    send_message(MsgID.REQUEST, sock, payload)


def recv_piece_chunk(sock: socket.SocketType, buffer: bytes, recv_length: int=4*1024):
    payload = recv_message(MsgID.PIECE, sock, buffer, recv_length)
    index = struct.unpack("!I", payload[0:4])[0]
    begin = struct.unpack("!I", payload[4:8])[0]
    block = payload[8:]
    return index, begin, block


def recv_piece(sock: socket.SocketType, metainfo: dict, piece_index: int) -> bytes:
    pieces = parse_metainfo_pieces(metainfo["info"]["pieces"])
    assert piece_index < len(pieces)
    piece_hash = pieces[piece_index]

    if piece_index < len(pieces) - 1:
        total_length = metainfo["info"]["piece length"]
    else:
        total_length = metainfo["info"]["length"] - metainfo["info"]["piece length"] * (len(pieces) - 1)

    piece = b""
    msg_length = 4*1024
    chunk_length = 16*1024
    current_begin = 0
    while current_begin < total_length:
        eff_chunk_length = min(chunk_length, total_length - current_begin)

        send_request(sock, piece_index, current_begin, eff_chunk_length)

        comm_buffer = b""
        r_index, r_begin, r_block = recv_piece_chunk(sock, comm_buffer, msg_length)
        assert r_index == piece_index
        assert r_begin == current_begin

        piece += r_block
        current_begin += len(r_block)

    r_piece_hash = hashlib.sha1(piece).digest()
    assert r_piece_hash == piece_hash

    return piece
