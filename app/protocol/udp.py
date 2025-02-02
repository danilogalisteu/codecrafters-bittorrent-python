import asyncio
import enum
import random
import struct


UDP_TRACKER_PROTOCOL_ID = int("0x41727101980", 16)


class UDPAction(enum.IntEnum):
    CONNECT = 0
    ANNOUNCE = 1


class UDPEvent(enum.IntEnum):
    NONE = 0
    COMPLETED = 1
    STARTED = 2
    STOPPED = 3


class UDPSender:
    def __init__(self, data: bytes, on_con_lost) -> None:
        self.send_data = data
        self.on_con_lost = on_con_lost
        self.recv_data = None
        self.transport = None

    def connection_made(self, transport) -> None:
        self.transport = transport
        self.transport.sendto(self.send_data)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.recv_data = data
        self.transport.close()

    def error_received(self, exc: OSError) -> None:
        print("Error received:", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self.on_con_lost.set_result(True)


async def send_recv_udp_data(address: tuple[str, int], send_data: bytes) -> bytes:
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()
    udp_sender = UDPSender(send_data, on_con_lost)
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: udp_sender,
        remote_addr=address,
    )
    try:
        await on_con_lost
    finally:
        transport.close()
    assert len(udp_sender.recv_data) >= 16
    return udp_sender.recv_data


async def connect_udp(address: tuple[str, int]) -> int:
    transaction_id = random.randrange(2**32)
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
    transaction_id = random.randrange(2**32)
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
