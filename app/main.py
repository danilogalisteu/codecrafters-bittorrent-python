import argparse
import json
import secrets
import socket
import sys

from .protocol.bencode import decode_bencode
from .protocol.handshake import do_handshake
from .protocol.message import MsgID, recv_message, send_message
from .protocol.metainfo import get_infohash, get_metainfo, parse_metainfo_pieces, print_info
from .protocol.peers import get_peer_info, get_peers, has_bitfield_piece, print_peers
from .protocol.piece import recv_piece


def run_decode(value: str):
    bencoded_value = value.encode()

    def bytes_to_str(data):
        if isinstance(data, bytes):
            return data.decode()

        raise TypeError(f"Type not serializable: {type(data)}")

    print(json.dumps(decode_bencode(bencoded_value)[0], default=bytes_to_str))


def run_info(torrent_file: str):
    metainfo = get_metainfo(torrent_file)
    if metainfo:
        print_info(metainfo)


def run_peers(torrent_file: str, peer_id: bytes):
    metainfo = get_metainfo(torrent_file)
    if metainfo:
        peers = get_peers(metainfo, peer_id, port=6881)
        print_peers(peers)


def run_handshake(torrent_file: str, peer_address: str, peer_id: bytes):
    peer_address = peer_address.split(":")
    peer = peer_address[0], int(peer_address[1])
    metainfo = get_metainfo(torrent_file)
    if metainfo:
        info_hash = get_infohash(metainfo)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(peer)
            r_peer_id, _ = do_handshake(sock, info_hash, peer_id)
            sock.close()
            print(f"Peer ID: {r_peer_id.hex()}")


def run_download_piece(piece_file: str, piece_index: int, torrent_file: str, peer_id: bytes):
    metainfo = get_metainfo(torrent_file)
    if metainfo:
        info_hash = get_infohash(metainfo)
        pieces_hash = parse_metainfo_pieces(metainfo["info"]["pieces"])
        if piece_index >= len(pieces_hash):
            raise IndexError(f"Piece {piece_index} not found in torrent")

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

                with open(piece_file, "wb") as file:
                    file.write(piece)


def make_parser(peer_id: bytes):
    parser = argparse.ArgumentParser(prog="app.main", description="Basic bittorrent client")
    subparsers = parser.add_subparsers(title="command", description="valid commands", required=True)

    parser_decode = subparsers.add_parser(
        "decode",
        description="decode data in bencode format",
        help="decode data in bencode format",
    )
    parser_decode.add_argument("value", type=str, help="string to be decoded")
    parser_decode.set_defaults(command_cb=run_decode)

    parser_info = subparsers.add_parser(
        "info",
        description="show torrent information",
        help="show torrent information",
    )
    parser_info.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_info.set_defaults(command_cb=run_info)

    parser_peers = subparsers.add_parser(
        "peers",
        description="get peers in torrent tracker and show addresses",
        help="get peers in torrent tracker and show addresses",
    )
    parser_peers.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_peers.set_defaults(command_cb=run_peers, peer_id=peer_id)

    parser_handshake = subparsers.add_parser(
        "handshake",
        description="do handshake with peer",
        help="do handshake with peer",
    )
    parser_handshake.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_handshake.add_argument("peer_address", type=str, help="address of the peer as <IP>:<PORT>")
    parser_handshake.set_defaults(command_cb=run_handshake, peer_id=peer_id)

    parser_piece = subparsers.add_parser(
        "download_piece",
        description="download piece of file",
        help="download piece of file",
    )
    parser_piece.add_argument("-o", type=str, required=True, dest="piece_file", metavar="piece_file", help="path to piece file (will be overwritten)")
    parser_piece.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_piece.add_argument("piece_index", type=int, help="index of the piece (starting at 0)")
    parser_piece.set_defaults(command_cb=run_download_piece, peer_id=peer_id)

    return parser


def main() -> None:
    peer_id = secrets.token_bytes(20)

    parser = make_parser(peer_id)
    args = parser.parse_args(sys.argv[1:])
    command_cb = args.command_cb
    args = {k:v for k, v in vars(args).items() if k != "command_cb"}
    command_cb(**args)


if __name__ == "__main__":
    main()
