import enum


class AnnounceEvent(enum.IntEnum):
    NONE = 0
    COMPLETED = 1
    STARTED = 2
    STOPPED = 3


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


UDP_ANNOUNCE_DICT = {
    AnnounceEvent.NONE: UDPEvent.NONE,
    AnnounceEvent.COMPLETED: UDPEvent.COMPLETED,
    AnnounceEvent.STARTED: UDPEvent.STARTED,
    AnnounceEvent.STOPPED: UDPEvent.STOPPED,
}


class TCPEvent(enum.StrEnum):
    EMPTY = "empty"
    COMPLETED = "completed"
    STARTED = "started"
    STOPPED = "stopped"


TCP_ANNOUNCE_DICT = {
    AnnounceEvent.NONE: TCPEvent.EMPTY,
    AnnounceEvent.COMPLETED: TCPEvent.COMPLETED,
    AnnounceEvent.STARTED: TCPEvent.STARTED,
    AnnounceEvent.STOPPED: TCPEvent.STOPPED,
}


def address_str_to_tuple(address: str) -> tuple[str, int]:
    assert ":" in address
    ip, port = address.split(":")
    return ip, int(port)


def peer_list_from_bytes(peers_bytes: bytes) -> list[tuple[str, int]]:
    pos = 0
    peers = []
    while pos < len(peers_bytes):
        peer_ip = ".".join(map(str, peers_bytes[pos : pos + 4]))
        peer_port = int.from_bytes(peers_bytes[pos + 4 : pos + 6], "big")
        peers.append((peer_ip, peer_port))
        pos += 6
    return peers
