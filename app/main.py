import sys
import json
import secrets
import socket

from .protocol.bencode import decode_bencode
from .protocol.handshake import do_handshake
from .protocol.message import MsgID, recv_message, send_message
from .protocol.metainfo import get_infohash, get_metainfo, print_info
from .protocol.peers import get_peer_info, get_peers, has_bitfield_piece, print_peers
from .protocol.piece import recv_piece


def main() -> None:
    peer_id = secrets.token_bytes(20)

    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

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
        peer_host_port = sys.argv[3].split(":")
        peer = peer_host_port[0], int(peer_host_port[1])
        metainfo = get_metainfo(file_name)
        if metainfo:
            info_hash = get_infohash(metainfo)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(peer)
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

                    comm_buffer = b""

                    bitfield = recv_message(MsgID.BITFIELD, sock, comm_buffer)
                    assert has_bitfield_piece(bitfield, piece_index)

                    send_message(MsgID.INTERESTED, sock)

                    payload = recv_message(MsgID.UNCHOKE, sock, comm_buffer)
                    assert len(payload) == 0

                    piece = recv_piece(sock, metainfo, piece_index)

                    sock.close()

                    with open(piece_file_name, "wb") as file:
                        file.write(piece)

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
