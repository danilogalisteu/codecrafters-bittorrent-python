import asyncio


class UDPSender:
    def __init__(self, data: bytes, on_con_lost: asyncio.Future[bool]) -> None:
        self.send_data = data
        self.on_con_lost = on_con_lost
        self.recv_data: bytes | None = None
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        self.transport.sendto(self.send_data)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.recv_data = data
        assert self.transport is not None
        self.transport.close()

    def error_received(self, exc: OSError) -> None:
        print("Error received:", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self.on_con_lost.set_result(True)


async def send_recv_udp_data(address: tuple[str, int], send_data: bytes) -> bytes:
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()
    transport, udp_sender = await loop.create_datagram_endpoint(
        lambda: UDPSender(send_data, on_con_lost),
        remote_addr=address,
    )
    try:
        await on_con_lost
    finally:
        transport.close()
    assert udp_sender.recv_data is not None
    assert len(udp_sender.recv_data) >= 16
    return udp_sender.recv_data
