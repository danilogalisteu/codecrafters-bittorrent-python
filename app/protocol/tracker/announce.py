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


class TCPEvent(enum.StrEnum):
    EMPTY = "empty"
    COMPLETED = "completed"
    STARTED = "started"
    STOPPED = "stopped"


UDP_ANNOUNCE_DICT = {
    AnnounceEvent.NONE: UDPEvent.NONE,
    AnnounceEvent.COMPLETED: UDPEvent.COMPLETED,
    AnnounceEvent.STARTED: UDPEvent.STARTED,
    AnnounceEvent.STOPPED: UDPEvent.STOPPED,
}


TCP_ANNOUNCE_DICT = {
    AnnounceEvent.NONE: TCPEvent.EMPTY,
    AnnounceEvent.COMPLETED: TCPEvent.COMPLETED,
    AnnounceEvent.STARTED: TCPEvent.STARTED,
    AnnounceEvent.STOPPED: TCPEvent.STOPPED,
}
