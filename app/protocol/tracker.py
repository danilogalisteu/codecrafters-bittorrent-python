import urllib.parse
import urllib.request

from .bencode import decode_bencode


class Tracker:
    def __init__(self, url: str, info_hash: bytes, file_length: int, client_id: bytes) -> None:
        self.url = url
        self.info_hash = info_hash
        self.file_length = file_length
        self.client_id = client_id
        self.port: int = 6881
        self.peers: list[tuple[str, int]] | None = None

    def print_peers(self) -> None:
        for peer in self.peers:
            print(f"{peer[0]}:{peer[1]}")

    async def _get_peers_tcp(self):
        query = {
            "info_hash": self.info_hash,
            "peer_id": self.client_id,
            "port": self.port,
            "uploaded": 0,
            "downloaded": 0,
            "left": self.file_length,
            "compact": 1,
        }
        url = self.url + "?" + urllib.parse.urlencode(query)
        res, _ = decode_bencode(urllib.request.urlopen(url).read())

        self.peers = []
        if isinstance(res, dict):
            if "peers" in res:
                pos = 0
                while pos < len(res["peers"]):
                    peer_ip = ".".join(map(str, res["peers"][pos:pos+4]))
                    peer_port = int.from_bytes(res["peers"][pos+4:pos+6], "big")
                    self.peers.append((peer_ip, peer_port))
                    pos += 6
            else:
                raise ValueError(f"invalid tracker response, missing 'peers':\n{res}")
        else:
            raise ValueError(f"unhandled tracker response:\n{res}")

    async def _get_peers_udp(self):
        url_info = urllib.parse.urlparse(self.url)
        print("url_info", url_info)
        print("UDP tracker", url_info.netloc)
        ...

    async def get_peers(self):
        if self.url.startswith("http"):
            await self._get_peers_tcp()
            return self.peers
        elif self.url.startswith("udp"):
            await self._get_peers_udp()
            return self.peers
        else:
            raise ValueError(f"unknown tracker protocol {self.url}")
