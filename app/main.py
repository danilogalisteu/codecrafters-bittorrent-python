import json
import sys
import hashlib
import secrets
import socket
import struct

from bencode import decode_bencode
from handshake import do_handshake
from message import MsgID, decode_message, recv_bitfield, recv_unchoke, send_interested, send_request
from metainfo import get_infohash, get_metainfo, parse_metainfo_pieces, print_info
from peers import get_peer_info, get_peers, has_bitfield_piece, print_peers


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
            peers_info = {peer: get_peer_info(peer, info_hash, peer_id) for peer in peers}
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
