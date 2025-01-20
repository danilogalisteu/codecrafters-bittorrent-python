import argparse
import json
import queue
import secrets
import socket
import sys
import threading

from .protocol.bencode import decode_bencode
from .protocol.handshake import do_handshake
from .protocol.magnet import parse_magnet
from .protocol.metainfo import get_infohash, get_metainfo, parse_metainfo_pieces, print_info
from .protocol.peer import Peer, get_peers, get_peers_from_metainfo, print_peers


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
        peers = get_peers_from_metainfo(metainfo, peer_id, port=6881)
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
        pieces_hash = parse_metainfo_pieces(metainfo["info"]["pieces"])
        if piece_index >= len(pieces_hash):
            raise IndexError(f"Piece {piece_index} not found in torrent")

        peers = get_peers_from_metainfo(metainfo, peer_id)

        for address in peers:
            peer = Peer(address, metainfo, peer_id)
            piece = peer.get_piece(piece_index)
            if piece is not None:
                break

        if piece is not None:
            with open(piece_file, "wb") as file:
                file.write(piece)
        else:
            print(f"Piece {piece_index} not found in any peer")


def run_download(out_file: str, torrent_file: str, peer_id: bytes):
    metainfo = get_metainfo(torrent_file)
    if metainfo:
        num_pieces = len(parse_metainfo_pieces(metainfo["info"]["pieces"]))

        jobs = queue.Queue()
        for piece_index in range(num_pieces):
            jobs.put(piece_index)
            
        pieces = [None] * num_pieces

        def piece_worker(address: tuple[str, int], metainfo, peer_id):
            peer = Peer(address, metainfo, peer_id)
            while True:
                piece_index = jobs.get()
                piece = peer.get_piece(piece_index)
                if piece is not None:
                    pieces[piece_index] = piece
                    jobs.task_done()

        for address in get_peers_from_metainfo(metainfo, peer_id):
            threading.Thread(
                target=piece_worker,
                args=(address, metainfo, peer_id,),
                daemon=True
            ).start()

        jobs.join()

        missing_pieces = [piece_index for piece_index, piece in enumerate(pieces) if piece is None]
        if missing_pieces:
            print("Some pieces are missing:", ", ".join(missing_pieces))
        else:
            with open(out_file, "wb") as file:
                for piece in pieces:
                    file.write(piece)


def run_magnet_parse(magnet_link: str):
    _, trackers, info_hash = parse_magnet(magnet_link)
    print("Tracker URL:", trackers[0])
    print("Info Hash:", info_hash)


def run_magnet_handshake(magnet_link: str, peer_id: bytes):
    unknown_length = 1024
    _, trackers, info_hash_str = parse_magnet(magnet_link)
    info_hash = bytes.fromhex(info_hash_str)
    peers = get_peers(trackers[0], info_hash, unknown_length, peer_id)
    if peers:
        peer = peers[0]
        reserved_extensions = (1 << 20).to_bytes(8, "big", signed=False)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(peer)
            r_peer_id, _ = do_handshake(sock, info_hash, peer_id, reserved_extensions)
            sock.close()
            print(f"Peer ID: {r_peer_id.hex()}")


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

    parser_file = subparsers.add_parser(
        "download",
        description="download file",
        help="download file",
    )
    parser_file.add_argument("-o", type=str, required=True, dest="out_file", metavar="out_file", help="path to piece file (will be overwritten)")
    parser_file.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_file.set_defaults(command_cb=run_download, peer_id=peer_id)

    parser_magnet_parse = subparsers.add_parser(
        "magnet_parse",
        description="parse magnet link",
        help="parse magnet link",
    )
    parser_magnet_parse.add_argument("magnet_link", type=str, help="magnet link")
    parser_magnet_parse.set_defaults(command_cb=run_magnet_parse)

    parser_magnet_handshake = subparsers.add_parser(
        "magnet_handshake",
        description="do handshake with magnet tracker",
        help="do handshake with magnet tracker",
    )
    parser_magnet_handshake.add_argument("magnet_link", type=str, help="magnet link")
    parser_magnet_handshake.set_defaults(command_cb=run_magnet_handshake, peer_id=peer_id)

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
