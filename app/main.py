import argparse
import json
import secrets
import socket
import sys

from .protocol.bencode import decode_bencode
from .protocol.handshake import do_handshake
from .protocol.message import MsgID, recv_message, send_message
from .protocol.metainfo import get_infohash, get_metainfo, print_info
from .protocol.peers import get_peer_info, get_peers, has_bitfield_piece, print_peers
from .protocol.piece import recv_piece


def run_decode(value: str):
    bencoded_value = value.encode()

    def bytes_to_str(data):
        if isinstance(data, bytes):
            return data.decode()

        raise TypeError(f"Type not serializable: {type(data)}")

    print(json.dumps(decode_bencode(bencoded_value)[0], default=bytes_to_str))


def run_info(torrent_name: str):
    metainfo = get_metainfo(torrent_name)
    if metainfo:
        print_info(metainfo)


def run_peers(torrent_name: str, peer_id: bytes):
    metainfo = get_metainfo(torrent_name)
    if metainfo:
        peers = get_peers(metainfo, peer_id, port=6881)
        print_peers(peers)


def run_handshake(torrent_name: str, peer_address: str, peer_id: bytes):
    peer_address = peer_address.split(":")
    peer = peer_address[0], int(peer_address[1])
    metainfo = get_metainfo(torrent_name)
    if metainfo:
        info_hash = get_infohash(metainfo)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(peer)
            r_peer_id, _ = do_handshake(sock, info_hash, peer_id)
            sock.close()
            print(f"Peer ID: {r_peer_id.hex()}")


def run_download_piece(piece_name: str, piece_index: int, torrent_name: str, peer_id: bytes):
    metainfo = get_metainfo(torrent_name)
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

                comm_buffer = b""

                bitfield = recv_message(MsgID.BITFIELD, sock, comm_buffer)
                assert has_bitfield_piece(bitfield, piece_index)

                send_message(MsgID.INTERESTED, sock)

                payload = recv_message(MsgID.UNCHOKE, sock, comm_buffer)
                assert len(payload) == 0

                piece = recv_piece(sock, metainfo, piece_index)

                sock.close()

                with open(piece_name, "wb") as file:
                    file.write(piece)


def main() -> None:
    peer_id = secrets.token_bytes(20)

    parser = argparse.ArgumentParser(prog='bittorrent', description='Simple bittorrent client')
    parser.add_argument("command")

    command = sys.argv[1]

    if command == "decode":
        run_decode(sys.argv[2])
    
    elif command == "info":
        run_info(sys.argv[2])
    
    elif command == "peers":
        run_peers(sys.argv[2], peer_id)

    elif command == "handshake":
        run_handshake(sys.argv[2], sys.argv[3], peer_id)

    elif command == "download_piece":
        run_download_piece(sys.argv[3], int(sys.argv[5]), sys.argv[4], peer_id)

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
