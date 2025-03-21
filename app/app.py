import asyncio
import json
import pathlib
import socket

from .protocol import address_from_str, address_to_str
from .protocol.bencode import decode_bencode
from .protocol.client import Client
from .protocol.metainfo import TorrentInfo
from .protocol.peer.handshake import decode_handshake, encode_handshake
from .protocol.tracker import Tracker


def stdlib_write(data: bytes, file_name: str, mode: str = "wb") -> int:
    with pathlib.Path(file_name).open(mode) as fp:
        return fp.write(data)


async def run_decode(value: str) -> None:
    bencoded_value = value.encode()

    def bytes_to_str(data: bytes) -> str:
        if isinstance(data, bytes):
            return data.decode()
        raise TypeError(f"Type not serializable: {type(data)}")

    print(json.dumps(decode_bencode(bencoded_value)[0], default=bytes_to_str))


async def run_info(torrent_file: str) -> None:
    torrent_info = TorrentInfo.from_file(torrent_file)
    assert torrent_info is not None
    print(torrent_info)


async def run_peers(torrent_file: str, client_id: bytes) -> None:
    tracker = Tracker.from_torrent(torrent_file, client_id)
    _ = await tracker.get_peers()
    for address in tracker.peer_addresses:
        print(address_to_str(address))


async def run_handshake(torrent_file: str, peer_address: str, client_id: bytes) -> None:
    peer = address_from_str(peer_address)
    torrent_info = TorrentInfo.from_file(torrent_file)
    assert torrent_info is not None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(peer)
        protocol = b"BitTorrent protocol"
        sock.send(encode_handshake(protocol, torrent_info.info_hash, client_id))
        r_pstr, _, r_info_hash, r_peer_id = decode_handshake(sock.recv(1024))
        assert r_pstr == protocol
        assert r_info_hash == torrent_info.info_hash
        print(f"Peer ID: {r_peer_id.hex()}")


async def run_download_piece(piece_file: str, piece_index: int, torrent_file: str, client_id: bytes) -> None:
    client = Client.from_torrent(torrent_file, client_id)
    await client.wait_peer()

    while True:
        await asyncio.sleep(0)
        if await client.download_piece(piece_index):
            break

    if piece_file:
        await asyncio.to_thread(stdlib_write, client._read_piece(piece_index), piece_file, "wb")


async def run_download(out_file: str, torrent_file: str, client_id: bytes) -> None:
    client = Client.from_torrent(torrent_file, client_id)
    await client.wait_peer()

    while True:
        await asyncio.sleep(0)
        if await client.download_all():
            break

    if out_file:
        for piece_index in range(client.torrent.num_pieces):
            await asyncio.to_thread(stdlib_write, client._read_piece(piece_index), out_file, "ab")


async def run_magnet_parse(magnet_link: str) -> None:
    _, tracker_urls, info_hash_str = TorrentInfo.parse_magnet(magnet_link)
    print("Tracker URL:", tracker_urls[0])
    print("Info Hash:", info_hash_str)


async def run_magnet_handshake(magnet_link: str, client_id: bytes) -> None:
    """
    Test links:
    - magnet1.gif.torrent: magnet:?xt=urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165&dn=magnet1.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    - magnet2.gif.torrent: magnet:?xt=urn:btih:3f994a835e090238873498636b98a3e78d1c34ca&dn=magnet2.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    - magnet3.gif.torrent: magnet:?xt=urn:btih:c5fb9894bdaba464811b088d806bdd611ba490af&dn=magnet3.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
    """
    client = Client.from_magnet(magnet_link, client_id)
    await client.wait_metadata()

    for peer in client.peers.values():
        await peer.event_extension.wait()

        assert peer.peer_id is not None
        assert peer.peer_ext_support is not None
        print("peer_ext_support", peer.peer_ext_support)

        print(f"Peer ID: {peer.peer_id.hex()}")
        print("Peer Metadata Extension ID:", peer.peer_ext_support["m"]["ut_metadata"])

        break


async def run_magnet_info(magnet_link: str, client_id: bytes) -> None:
    client = Client.from_magnet(magnet_link, client_id)
    await client.wait_metadata()

    for peer in client.peers.values():
        await peer.event_metadata.wait()

        assert peer.peer_id is not None
        assert peer.peer_ext_support is not None
        print("peer_ext_support", peer.peer_ext_support)

        print("Peer ID:", peer.peer_id.hex())
        print("Peer Metadata Extension ID:", peer.peer_ext_support["m"]["ut_metadata"])

        assert client.trackers is not None
        print("Tracker URL:", client.trackers[0].url)
        print("File name:", peer.torrent.name)
        print("Length:", peer.torrent.total_length)
        print("Info Hash:", client.torrent.info_hash.hex())
        print("Piece Length:", peer.torrent.piece_length)
        print("Piece Hashes:")
        for piece_index in range(peer.torrent.num_pieces):
            print(peer.torrent.pieces_hash[piece_index * 20 : piece_index * 20 + 20].hex())

        break


async def run_magnet_piece(piece_file: str, piece_index: int, magnet_link: str, client_id: bytes) -> None:
    client = Client.from_magnet(magnet_link, client_id)
    await client.wait_metadata()

    while True:
        await asyncio.sleep(0)
        if await client.download_piece(piece_index):
            break

    if piece_file:
        await asyncio.to_thread(stdlib_write, client._read_piece(piece_index), piece_file, "wb")


async def run_magnet_download(out_file: str, magnet_link: str, client_id: bytes) -> None:
    client = Client.from_magnet(magnet_link, client_id)
    await client.wait_metadata()

    while True:
        await asyncio.sleep(0)
        if await client.download_all():
            break

    if out_file:
        for piece_index in range(client.torrent.num_pieces):
            await asyncio.to_thread(stdlib_write, client._read_piece(piece_index), out_file, "ab")
