import argparse
import asyncio
import json
import pathlib
import queue
import secrets
import socket
import sys
from typing import Any

from .protocol import address_str_to_tuple
from .protocol.bencode import decode_bencode
from .protocol.handshake import decode_handshake, encode_handshake
from .protocol.magnet import parse_magnet
from .protocol.metainfo import load_metainfo
from .protocol.peer import Peer
from .protocol.tracker import Tracker


async def run_decode(value: str) -> None:
    bencoded_value = value.encode()

    def bytes_to_str(data: bytes) -> str:
        if isinstance(data, bytes):
            return data.decode()
        raise TypeError(f"Type not serializable: {type(data)}")

    print(json.dumps(decode_bencode(bencoded_value)[0], default=bytes_to_str))


async def run_info(torrent_file: str) -> None:
    _ = load_metainfo(torrent_file, show_info=True)


async def run_peers(torrent_file: str, client_id: bytes) -> None:
    tracker = Tracker.from_torrent(torrent_file, client_id)
    _ = await tracker.get_peers()
    tracker.print_peers()


async def run_handshake(torrent_file: str, peer_address: str, client_id: bytes) -> None:
    peer = address_str_to_tuple(peer_address)
    infodata = load_metainfo(torrent_file)
    assert infodata is not None
    info_hash = infodata[1]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(peer)
        protocol = b"BitTorrent protocol"
        sock.send(encode_handshake(protocol, info_hash, client_id))
        r_pstr, _, r_info_hash, r_peer_id = decode_handshake(sock.recv(1024))
        assert protocol == r_pstr
        assert info_hash == r_info_hash
        print(f"Peer ID: {r_peer_id.hex()}")


async def run_download_piece(piece_file: str, piece_index: int, torrent_file: str, client_id: bytes) -> None:
    tracker = Tracker.from_torrent(torrent_file, client_id)
    addresses = await tracker.get_peers()

    for address in addresses:
        peer = Peer(address, tracker.info_hash, client_id)
        peer_task = peer.run_task()

        await peer.initialize_pieces(tracker.pieces_hash, tracker.file_length, tracker.piece_length)
        piece = await peer.get_piece(piece_index)
        peer_task.cancel()
        if piece is not None:
            break

    if piece is not None:
        if tracker.file_name and not piece_file:
            piece_file = tracker.file_name + f"_piece{piece_index}"
        with pathlib.Path(piece_file).open("wb") as file:
            file.write(piece)
    else:
        print(f"Piece {piece_index} not found in any peer")


async def run_download(out_file: str, torrent_file: str, client_id: bytes) -> None:
    tracker = Tracker.from_torrent(torrent_file, client_id)
    num_pieces = len(tracker.pieces_hash) // 20
    addresses = await tracker.get_peers()

    worker_task:dict[tuple[str, int], asyncio.Task[None]] = {}
    results: dict[int, bytes] = {}
    jobs: queue.Queue[int] = queue.Queue()
    workers: queue.Queue[tuple[str, int]] = queue.Queue()

    # print("adding workers")
    for address in addresses:
        workers.put(address)

    # print("scheduling jobs")
    for piece_index in range(num_pieces):
        jobs.put(piece_index)

    async def peer_worker(address: tuple[str, int], piece_index: int) -> None:
        # print("peer", address, "received job", piece_index)
        peer = Peer(address, tracker.info_hash, client_id)
        peer_task = peer.run_task()
        await peer.initialize_pieces(tracker.pieces_hash, tracker.file_length, tracker.piece_length)
        piece = await peer.get_piece(piece_index)
        peer_task.cancel()
        if piece is not None:
            results[piece_index] = piece
            # print("peer", address, "finished job", piece_index)
        workers.put(address)
        worker_task[address].cancel()
        del worker_task[address]

    while True:
        if len(results) == num_pieces:
            break
        if not jobs.empty():
            piece_index = jobs.get()
            while workers.empty():
                await asyncio.sleep(0)
            address = workers.get()
            worker_task[address] = asyncio.create_task(peer_worker(address, piece_index))
        await asyncio.sleep(0)

    missing_pieces = [piece_index for piece_index in range(num_pieces) if piece_index not in results]
    if missing_pieces:
        print("Some pieces are missing:", ", ".join(map(str, missing_pieces)))
    else:
        if tracker.file_name and not out_file:
            out_file = tracker.file_name
        with pathlib.Path(out_file).open("wb") as file:
            for piece_index in sorted(results):
                file.write(results[piece_index])


async def run_magnet_parse(magnet_link: str) -> None:
    _, tracker_urls, info_hash_str = parse_magnet(magnet_link)
    print("Tracker URL:", tracker_urls[0])
    print("Info Hash:", info_hash_str)


async def run_magnet_handshake(magnet_link: str, client_id: bytes) -> None:
    """
    Test links:
    - magnet1.gif.torrent: magnet:?xt=urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165&dn=magnet1.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    - magnet2.gif.torrent: magnet:?xt=urn:btih:3f994a835e090238873498636b98a3e78d1c34ca&dn=magnet2.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    - magnet3.gif.torrent: magnet:?xt=urn:btih:c5fb9894bdaba464811b088d806bdd611ba490af&dn=magnet3.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    """
    unknown_length = 1024
    extension_reserved = (1 << 20).to_bytes(8, "big", signed=False)
    extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}

    _, tracker_urls, info_hash_str = parse_magnet(magnet_link)
    info_hash = bytes.fromhex(info_hash_str)

    tracker = Tracker(tracker_urls[0], info_hash, unknown_length, client_id)
    addresses = await tracker.get_peers()

    peer = Peer(addresses[0], info_hash, client_id, extension_reserved, extension_support)
    peer_task = peer.run_task()

    await peer.event_extension.wait()
    print("peer_ext_support", peer.peer_ext_support)

    peer_task.cancel()

    assert peer.peer_id is not None
    assert peer.peer_ext_support is not None
    print(f"Peer ID: {peer.peer_id.hex()}")
    print("Peer Metadata Extension ID:", peer.peer_ext_support["m"]["ut_metadata"])


async def run_magnet_info(magnet_link: str, client_id: bytes) -> None:
    unknown_length = 1024
    extension_reserved = (1 << 20).to_bytes(8, "big", signed=False)
    extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}

    _, tracker_urls, info_hash_str = parse_magnet(magnet_link)
    info_hash = bytes.fromhex(info_hash_str)

    tracker = Tracker(tracker_urls[0], info_hash, unknown_length, client_id)
    addresses = await tracker.get_peers()

    peer = Peer(addresses[0], info_hash, client_id, extension_reserved, extension_support)
    peer_task = peer.run_task()

    await peer.event_metadata.wait()
    print("peer_ext_meta_info", peer.peer_ext_meta_info)

    peer_task.cancel()

    assert peer.peer_id is not None
    assert peer.peer_ext_support is not None
    print("Peer ID:", peer.peer_id.hex())
    print("Peer Metadata Extension ID:", peer.peer_ext_support["m"]["ut_metadata"])

    assert peer.pieces_hash is not None
    assert peer.file_length is not None
    assert peer.piece_length is not None
    assert peer.num_pieces is not None
    print("Tracker URL:", tracker_urls[0])
    print("File name:", peer.file_name)
    print("Length:", peer.file_length)
    print("Info Hash:", info_hash_str)
    print("Piece Length:", peer.piece_length)
    print("Piece Hashes:")
    for piece_index in range(peer.num_pieces):
        print(peer.pieces_hash[piece_index*20:piece_index*20+20].hex())


async def run_magnet_piece(piece_file: str, piece_index: int, magnet_link: str, client_id: bytes) -> None:
    unknown_length = 1024
    extension_reserved = (1 << 20).to_bytes(8, "big", signed=False)
    extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}

    _, tracker_urls, info_hash_str = parse_magnet(magnet_link)
    info_hash = bytes.fromhex(info_hash_str)

    tracker = Tracker(tracker_urls[0], info_hash, unknown_length, client_id)
    addresses = await tracker.get_peers()

    for address in addresses:
        peer = Peer(address, info_hash, client_id, extension_reserved, extension_support)
        peer_task = peer.run_task()

        await peer.event_pieces.wait()
        piece = await peer.get_piece(piece_index)
        peer_task.cancel()
        if piece is not None:
            break

    if piece is not None:
        if peer.file_name and not piece_file:
            piece_file = peer.file_name + f"_piece{piece_index}"
        with pathlib.Path(piece_file).open("wb") as file:
            file.write(piece)
    else:
        print(f"Piece {piece_index} not found in any peer")


async def run_magnet_download(out_file: str, magnet_link: str, client_id: bytes) -> None:
    unknown_length = 1024
    extension_reserved = (1 << 20).to_bytes(8, "big", signed=False)
    extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}

    _, tracker_urls, info_hash_str = parse_magnet(magnet_link)
    info_hash = bytes.fromhex(info_hash_str)

    tracker = Tracker(tracker_urls[0], info_hash, unknown_length, client_id)
    addresses = await tracker.get_peers()

    peers = {}
    peers_task = {}
    worker_task:dict[tuple[str, int], asyncio.Task[None]] = {}
    results: dict[int, bytes] = {}
    jobs: queue.Queue[int] = queue.Queue()
    workers: queue.Queue[tuple[str, int]] = queue.Queue()

    for address in addresses:
        peers[address] = Peer(address, info_hash, client_id, extension_reserved, extension_support)
        peers_task[address] = peers[address].run_task()

    for address in addresses:
        await peers[address].event_pieces.wait()

    num_pieces = peers[addresses[0]].num_pieces
    assert num_pieces is not None

    # print("adding workers")
    for address in peers:
        workers.put(address)

    # print("scheduling jobs")
    for piece_index in range(num_pieces):
        jobs.put(piece_index)

    async def peer_worker(address: tuple[str, int], piece_index: int) -> None:
        # print("peer", address, "received job", piece_index)
        peer = peers[address]
        piece = await peer.get_piece(piece_index)
        if piece is not None:
            results[piece_index] = piece
            # print("peer", address, "finished job", piece_index)
        workers.put(address)
        worker_task[address].cancel()
        del worker_task[address]

    while True:
        if len(results) == num_pieces:
            break
        if not jobs.empty():
            piece_index = jobs.get()
            while workers.empty():
                await asyncio.sleep(0)
            address = workers.get()
            worker_task[address] = asyncio.create_task(peer_worker(address, piece_index))
        await asyncio.sleep(0)

    for address in addresses:
        peers_task[address].cancel()

    missing_pieces = [piece_index for piece_index in range(num_pieces) if piece_index not in results]
    if missing_pieces:
        print("Some pieces are missing:", ", ".join(map(str, missing_pieces)))
    else:
        if peers[addresses[0]].file_name and not out_file:
            out_file = peers[addresses[0]].file_name
        with pathlib.Path(out_file).open("wb") as file:
            for piece_index in sorted(results):
                file.write(results[piece_index])



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
    parser_piece.add_argument("-o", type=str, required=False, dest="piece_file", metavar="piece_file", help="path to piece file (will be overwritten)")
    parser_piece.add_argument("torrent_file", type=str, help="path to torrent file")
    parser_piece.add_argument("piece_index", type=int, help="index of the piece (starting at 0)")
    parser_piece.set_defaults(command_cb=run_download_piece, client_id=client_id)

    parser_file = subparsers.add_parser(
        "download",
        description="download file",
        help="download file",
    )
    parser_file.add_argument("-o", type=str, required=False, dest="out_file", metavar="out_file", help="path to file (will be overwritten)")
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
    parser_magnet_piece.add_argument("-o", type=str, required=False, dest="piece_file", metavar="piece_file", help="path to piece file (will be overwritten)")
    parser_magnet_piece.add_argument("magnet_link", type=str, help="magnet link")
    parser_magnet_piece.add_argument("piece_index", type=int, help="index of the piece (starting at 0)")
    parser_magnet_piece.set_defaults(command_cb=run_magnet_piece, client_id=client_id)

    parser_magnet_download = subparsers.add_parser(
        "magnet_download",
        description="download file from magnet link",
        help="download file from magnet link",
    )
    parser_magnet_download.add_argument("-o", type=str, required=False, dest="out_file", metavar="out_file", help="path to file (will be overwritten)")
    parser_magnet_download.add_argument("magnet_link", type=str, help="magnet link")
    parser_magnet_download.set_defaults(command_cb=run_magnet_download, client_id=client_id)

    return parser


def main() -> None:
    client_id = secrets.token_bytes(20)

    parser = make_parser(client_id)
    args = parser.parse_args(sys.argv[1:])
    command_cb = args.command_cb

    asyncio.run(command_cb(**{k:v for k, v in vars(args).items() if k != "command_cb"}))


if __name__ == "__main__":
    main()
