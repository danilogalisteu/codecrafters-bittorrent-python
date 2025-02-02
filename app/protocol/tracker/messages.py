"""
UDP Tracker Protocol for BitTorrent
https://www.bittorrent.org/beps/bep_0015.html

UDP Tracker Protocol Extensions
https://bittorrent.org/beps/bep_0041.html

Bittorrent UDP-tracker protocol extension (for types)
https://www.rasterbar.com/products/libtorrent/udp_tracker_protocol.html
"""
import enum
import random
import struct

from .udp import send_recv_udp_data


UDP_TRACKER_PROTOCOL_ID = int("0x41727101980", 16)


class UDPAction(enum.IntEnum):
    CONNECT = 0
    ANNOUNCE = 1
    SCRAPE = 2
    ERROR = 3


class UDPEvent(enum.IntEnum):
    NONE = 0
    COMPLETED = 1
    STARTED = 2
    STOPPED = 3


async def connect_udp(address: tuple[str, int]) -> int:
    transaction_id = random.randrange(-2**31, 2**31)
    send_data = struct.pack(
        "!qii",
        UDP_TRACKER_PROTOCOL_ID,
        UDPAction.CONNECT.value,
        transaction_id
    )
    recv_data = await send_recv_udp_data(
        (address[0], int(address[1])),
        send_data,
    )
    assert len(recv_data) >= 16
    recv_action, recv_transaction_id, connection_id = struct.unpack("!iiq", recv_data[:16])
    assert recv_transaction_id == transaction_id
    assert recv_action == UDPAction.CONNECT.value
    return connection_id


async def announce_udp(
        address: tuple[str, int],
        connection_id: int,
        info_hash: bytes,
        client_id: bytes,
        client_port: int,
        downloaded: int,
        left: int,
        uploaded: int,
        client_key: int=0,
    ) -> tuple[int, int, int, bytes]:
    transaction_id = random.randrange(-2**31, 2**31)
    send_data = struct.pack("!qii", connection_id, UDPAction.ANNOUNCE.value, transaction_id)
    send_data += info_hash
    send_data += client_id
    send_data += struct.pack("!qqqiIIiH", downloaded, left, uploaded, UDPEvent.NONE.value, 0, client_key, -1, client_port)
    recv_data = await send_recv_udp_data(
        (address[0], int(address[1])),
        send_data,
    )
    assert len(recv_data) >= 20
    recv_action, recv_transaction_id, interval, leechers, seeders = struct.unpack("!iiiii", recv_data[:20])
    assert recv_transaction_id == transaction_id
    assert recv_action == UDPAction.ANNOUNCE.value
    return interval, leechers, seeders, recv_data[20:]
