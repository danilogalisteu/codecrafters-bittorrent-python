import asyncio
import json
import pathlib
import queue
import socket
from typing import Any

from .protocol import address_str_to_tuple
from .protocol.bencode import decode_bencode
from .protocol.handshake import decode_handshake, encode_handshake
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
    assert tracker.pieces_hash is not None
    assert tracker.piece_length is not None

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
    assert tracker.pieces_hash is not None
    assert tracker.piece_length is not None

    worker_task: dict[tuple[str, int], asyncio.Task[None]] = {}
    results: dict[int, bytes] = {}
    jobs: queue.Queue[int] = queue.Queue()
    workers: queue.Queue[tuple[str, int]] = queue.Queue()

    # print("adding workers")
    addresses = await tracker.get_peers()
    for address in addresses:
        workers.put(address)

    # print("scheduling jobs")
    num_pieces = len(tracker.pieces_hash) // 20
    for piece_index in range(num_pieces):
        jobs.put(piece_index)

    async def peer_worker(tracker: Tracker, address: tuple[str, int], piece_index: int) -> None:
        assert tracker.pieces_hash is not None
        assert tracker.piece_length is not None
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
            worker_task[address] = asyncio.create_task(peer_worker(tracker, address, piece_index))
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
    _, tracker_urls, info_hash_str = Tracker.parse_magnet(magnet_link)
    print("Tracker URL:", tracker_urls[0])
    print("Info Hash:", info_hash_str)


async def run_magnet_handshake(magnet_link: str, client_id: bytes) -> None:
    """
    Test links:
    - magnet1.gif.torrent: magnet:?xt=urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165&dn=magnet1.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    - magnet2.gif.torrent: magnet:?xt=urn:btih:3f994a835e090238873498636b98a3e78d1c34ca&dn=magnet2.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    - magnet3.gif.torrent: magnet:?xt=urn:btih:c5fb9894bdaba464811b088d806bdd611ba490af&dn=magnet3.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    """
    extension_reserved = (1 << 20).to_bytes(8, "big", signed=False)
    extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}

    tracker = Tracker.from_magnet(magnet_link, client_id)[0]
    addresses = await tracker.get_peers()

    peer = Peer(
        addresses[0],
        tracker.info_hash,
        client_id,
        extension_reserved,
        extension_support,
    )
    peer_task = peer.run_task()

    await peer.event_extension.wait()
    print("peer_ext_support", peer.peer_ext_support)

    peer_task.cancel()

    assert peer.peer_id is not None
    assert peer.peer_ext_support is not None
    print(f"Peer ID: {peer.peer_id.hex()}")
    print("Peer Metadata Extension ID:", peer.peer_ext_support["m"]["ut_metadata"])


async def run_magnet_info(magnet_link: str, client_id: bytes) -> None:
    extension_reserved = (1 << 20).to_bytes(8, "big", signed=False)
    extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}

    tracker = Tracker.from_magnet(magnet_link, client_id)[0]
    addresses = await tracker.get_peers()

    peer = Peer(
        addresses[0],
        tracker.info_hash,
        client_id,
        extension_reserved,
        extension_support,
    )
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
    print("Tracker URL:", tracker.url)
    print("File name:", peer.file_name)
    print("Length:", peer.file_length)
    print("Info Hash:", tracker.info_hash.hex())
    print("Piece Length:", peer.piece_length)
    print("Piece Hashes:")
    for piece_index in range(peer.num_pieces):
        print(peer.pieces_hash[piece_index * 20 : piece_index * 20 + 20].hex())


async def run_magnet_piece(piece_file: str, piece_index: int, magnet_link: str, client_id: bytes) -> None:
    extension_reserved = (1 << 20).to_bytes(8, "big", signed=False)
    extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}

    tracker = Tracker.from_magnet(magnet_link, client_id)[0]
    addresses = await tracker.get_peers()

    for address in addresses:
        peer = Peer(address, tracker.info_hash, client_id, extension_reserved, extension_support)
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
    extension_reserved = (1 << 20).to_bytes(8, "big", signed=False)
    extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}

    tracker = Tracker.from_magnet(magnet_link, client_id)[0]
    addresses = await tracker.get_peers()

    peers = {}
    peers_task = {}
    worker_task: dict[tuple[str, int], asyncio.Task[None]] = {}
    results: dict[int, bytes] = {}
    jobs: queue.Queue[int] = queue.Queue()
    workers: queue.Queue[tuple[str, int]] = queue.Queue()

    for address in addresses:
        peers[address] = Peer(address, tracker.info_hash, client_id, extension_reserved, extension_support)
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
        file_name = peers[addresses[0]].file_name
        if file_name and not out_file:
            out_file = file_name
        with pathlib.Path(out_file).open("wb") as file:
            for piece_index in sorted(results):
                file.write(results[piece_index])
