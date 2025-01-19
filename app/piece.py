import hashlib
import socket
import struct

from message import MsgID, decode_message, send_request
from metainfo import parse_metainfo_pieces


def recv_piece_chunk(sock: socket.SocketType, msg_length: int, chunk_length: int) -> tuple[int, int, bytes]:
    msg = b""
    msg_total = 0
    while msg_total < chunk_length:
        chunk = sock.recv(msg_length)
        msg += chunk
        msg_total += len(chunk)
        try:
            id, payload = decode_message(msg)
            assert id == MsgID.PIECE
        except AssertionError:
            # Unexpected message, discard data
            print("MsgID", id)
            msg_length = 5 + len(payload)
            msg = msg[msg_length:]
            msg_total -= msg_length
        except IndexError:
            # Incomplete message
            continue

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

        r_index, r_begin, r_block = recv_piece_chunk(sock, msg_length, eff_chunk_length)
        assert r_index == piece_index
        assert r_begin == current_begin

        piece += r_block
        current_begin += len(r_block)

    r_piece_hash = hashlib.sha1(piece).digest()
    assert r_piece_hash == piece_hash

    return piece
