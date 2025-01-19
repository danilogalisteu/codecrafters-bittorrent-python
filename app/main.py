import json
import sys
import hashlib
import secrets
import socket
import struct
from enum import IntEnum

from bencode import decode_bencode
from handshake import do_handshake
from metainfo import get_infohash, get_metainfo, parse_metainfo_pieces, print_info
from peers import get_peers, print_peers


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


def get_peers_info(peers: list[tuple[str, int]], info_hash: bytes, peer_id: bytes) -> dict[tuple[str, int], tuple[bytes, bytes]]:
    peers_info = {}
    for peer in peers:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(peer)
            r_peer_id, _ = do_handshake(sock, info_hash, peer_id)
            r_bitfield = recv_bitfield(sock)
            sock.close()
            peers_info[peer] = (r_peer_id, r_bitfield)
    return peers_info


def has_bitfield_piece(bitfield: bytes, piece_index: int) -> bool:
    bitfield_index = piece_index // 8
    byte_mask = 1 << (7 - piece_index % 8)
    return (bitfield[bitfield_index] & byte_mask) != 0


def send_interested(sock: socket.SocketType) -> None:
    sock.send(encode_message(MsgID.INTERESTED, b""))


def recv_unchoke(sock: socket.SocketType) -> None:
    id, payload = decode_message(sock.recv(1024))
    assert id == MsgID.UNCHOKE
    assert len(payload) == 0


def send_request(sock: socket.SocketType, index: int, begin: int, length: int) -> None:
    msg_req = struct.pack("!IbIII", 13, MsgID.REQUEST, index, begin, length)
    sock.send(msg_req)


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


def main() -> None:
    peer_id = secrets.token_bytes(20)

    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value)[0], default=bytes_to_str))
    
    elif command == "info":
        file_name = sys.argv[2]
        metainfo = get_metainfo(file_name)
        if metainfo:
            print_info(metainfo)
    
    elif command == "peers":
        file_name = sys.argv[2]
        metainfo = get_metainfo(file_name)
        if metainfo:
            peers = get_peers(metainfo, peer_id, port=6881)
            print_peers(peers)

    elif command == "handshake":
        file_name = sys.argv[2]
        peer_host_port = sys.argv[3]
        peer_sep_index = peer_host_port.find(":")
        peer_host = peer_host_port[:peer_sep_index]
        peer_port = int(peer_host_port[peer_sep_index+1:])
        metainfo = get_metainfo(file_name)
        if metainfo:
            info_hash = get_infohash(metainfo)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((peer_host, peer_port))
                r_peer_id, _ = do_handshake(sock, info_hash, peer_id)
                sock.close()
            print(f"Peer ID: {r_peer_id.hex()}")

    elif command == "download_piece":
        piece_file_name = sys.argv[3]
        torrent_file_name = sys.argv[4]
        piece_index = int(sys.argv[5])
        metainfo = get_metainfo(torrent_file_name)
        if metainfo:
            info_hash = get_infohash(metainfo)
            if piece_index >= len(metainfo["info"]["pieces"]):
                print(f"Piece {piece_index} not found in torrent")

            peers = get_peers(metainfo, peer_id)
            peers_info = get_peers_info(peers, info_hash, peer_id)
            peers_valid = [peer for peer in peers if has_bitfield_piece(peers_info[peer][1], piece_index)]
            if peers_valid:
                peer = peers_valid[0]

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect(peer)

                    _, _ = do_handshake(sock, info_hash, peer_id)
                    
                    bitfield = recv_bitfield(sock)
                    assert has_bitfield_piece(bitfield, piece_index)

                    send_interested(sock)

                    recv_unchoke(sock)

                    piece = recv_piece(sock, metainfo, piece_index)

                    sock.close()

                    with open(piece_file_name, "wb") as file:
                        file.write(piece)

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
