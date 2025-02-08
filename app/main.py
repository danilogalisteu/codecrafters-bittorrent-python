import argparse
import asyncio
import secrets
import sys

from .app import (
    run_decode,
    run_info,
    run_peers,
    run_handshake,
    run_download_piece,
    run_download,
    run_magnet_parse,
    run_magnet_handshake,
    run_magnet_info,
    run_magnet_piece,
    run_magnet_download,
)


def make_parser(client_id: bytes) -> argparse.ArgumentParser:
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
    parser_peers.set_defaults(command_cb=run_peers, client_id=client_id)

    parser_handshake = subparsers.add_parser(
        "handshake",
        description="do handshake with peer",
        help="do handshake with peer",
    )
    parser_handshake.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_handshake.add_argument("peer_address", type=str, help="address of the peer as <IP>:<PORT>")
    parser_handshake.set_defaults(command_cb=run_handshake, client_id=client_id)

    parser_piece = subparsers.add_parser(
        "download_piece",
        description="download piece of file",
        help="download piece of file",
    )
    parser_piece.add_argument(
        "-o",
        type=str,
        required=False,
        dest="piece_file",
        metavar="piece_file",
        help="path to piece file (will be overwritten)",
    )
    parser_piece.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_piece.add_argument("piece_index", type=int, help="index of the piece (starting at 0)")
    parser_piece.set_defaults(command_cb=run_download_piece, client_id=client_id)

    parser_file = subparsers.add_parser(
        "download",
        description="download file",
        help="download file",
    )
    parser_file.add_argument(
        "-o",
        type=str,
        required=False,
        dest="out_file",
        metavar="out_file",
        help="path to file (will be overwritten)",
    )
    parser_file.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_file.set_defaults(command_cb=run_download, client_id=client_id)

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
    parser_magnet_handshake.set_defaults(command_cb=run_magnet_handshake, client_id=client_id)

    parser_magnet_info = subparsers.add_parser(
        "magnet_info",
        description="get torrent information from tracker",
        help="get torrent information from tracker",
    )
    parser_magnet_info.add_argument("magnet_link", type=str, help="magnet link")
    parser_magnet_info.set_defaults(command_cb=run_magnet_info, client_id=client_id)

    parser_magnet_piece = subparsers.add_parser(
        "magnet_download_piece",
        description="download piece of file from magnet link",
        help="download piece of file from magnet link",
    )
    parser_magnet_piece.add_argument(
        "-o",
        type=str,
        required=False,
        dest="piece_file",
        metavar="piece_file",
        help="path to piece file (will be overwritten)",
    )
    parser_magnet_piece.add_argument("magnet_link", type=str, help="magnet link")
    parser_magnet_piece.add_argument("piece_index", type=int, help="index of the piece (starting at 0)")
    parser_magnet_piece.set_defaults(command_cb=run_magnet_piece, client_id=client_id)

    parser_magnet_download = subparsers.add_parser(
        "magnet_download",
        description="download file from magnet link",
        help="download file from magnet link",
    )
    parser_magnet_download.add_argument(
        "-o",
        type=str,
        required=False,
        dest="out_file",
        metavar="out_file",
        help="path to file (will be overwritten)",
    )
    parser_magnet_download.add_argument("magnet_link", type=str, help="magnet link")
    parser_magnet_download.set_defaults(command_cb=run_magnet_download, client_id=client_id)

    return parser


def main() -> None:
    client_id = secrets.token_bytes(20)

    parser = make_parser(client_id)
    args = parser.parse_args(sys.argv[1:])
    command_cb = args.command_cb

    asyncio.run(command_cb(**{k: v for k, v in vars(args).items() if k != "command_cb"}))


if __name__ == "__main__":
    main()
