"""
UDP Tracker Protocol for BitTorrent
https://www.bittorrent.org/beps/bep_0015.html

Tracker Returns Compact Peer Lists
https://www.bittorrent.org/beps/bep_0023.html

Bittorrent UDP-tracker protocol extension (for types)
https://www.rasterbar.com/products/libtorrent/udp_tracker_protocol.html
"""

import random
import struct
from urllib.parse import urlparse

from app.protocol import address_from_str, address_list_from_bytes
from app.protocol.datagram import send_recv_udp_data

from .announce import UDP_ANNOUNCE_DICT, AnnounceEvent, UDPAction

UDP_TRACKER_PROTOCOL_ID = int("0x41727101980", 16)


async def connect_udp(address: tuple[str, int]) -> int:
    transaction_id = random.randrange(-(2**31), 2**31)
    send_data = struct.pack("!qii", UDP_TRACKER_PROTOCOL_ID, UDPAction.CONNECT.value, transaction_id)
    recv_data = await send_recv_udp_data(address, send_data)
    assert len(recv_data) >= 16
    recv_action, recv_transaction_id, connection_id = struct.unpack("!iiq", recv_data[:16])
    assert recv_transaction_id == transaction_id
    assert recv_action == UDPAction.CONNECT.value
    assert isinstance(connection_id, int)
    return connection_id


async def announce_udp(
    url: str,
    info_hash: bytes,
    client_id: bytes,
    client_port: int,
    downloaded: int,
    left: int,
    uploaded: int,
    event: AnnounceEvent = AnnounceEvent.NONE,
) -> tuple[float, int, int, list[tuple[str, int]]]:
    address = address_from_str(urlparse(url).netloc)
    connection_id = await connect_udp(address)

    client_key = hash(client_id)
    transaction_id = random.randrange(-(2**31), 2**31)
    send_data = struct.pack("!qii", connection_id, UDPAction.ANNOUNCE.value, transaction_id)
    send_data += info_hash
    send_data += client_id
    send_data += struct.pack(
        "!qqqiIIiH",
        downloaded,
        left,
        uploaded,
        UDP_ANNOUNCE_DICT[event].value,
        0,
        client_key,
        -1,
        client_port,
    )
    recv_data = await send_recv_udp_data(address, send_data)
    assert len(recv_data) >= 20

    recv_action, recv_transaction_id, interval, leechers, seeders = struct.unpack("!iiiii", recv_data[:20])
    assert recv_transaction_id == transaction_id
    assert recv_action == UDPAction.ANNOUNCE.value

    return float(interval), leechers, seeders, address_list_from_bytes(recv_data[20:])
