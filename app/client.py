import asyncio
import pathlib
import secrets
import sys
from typing import Any


async def bt_client(argument: str) -> None:
    from .protocol.client import Client

    client_id = secrets.token_bytes(20)

    torrent_file = pathlib.Path(argument)
    if torrent_file.is_file():
        client = Client.from_torrent(str(torrent_file), client_id).run_task()
    elif argument.startswith("magnet:"):
        extension_reserved = (1 << 20).to_bytes(8, byteorder="big", signed=False)
        extension_support: dict[str | bytes, Any] = {"m": {"ut_metadata": 1}}
        client = Client.from_magnet(argument, client_id, extension_reserved, extension_support).run_task()
    else:
        print(f"Invalid argument: '{argument}'.\nExpected a torrent file or magnet link.")
        return

    await asyncio.wait(
        [asyncio.create_task(evt.wait()) for evt in [client.event_complete, client.event_failed]],
        return_when=asyncio.FIRST_COMPLETED,
    )
    if client.event_failed.is_set():
        print(f"Download failed: '{argument}'")
    else:
        print(f"Download completed: '{argument}'")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.client <torrent_file | magnet_link>")
        sys.exit(1)
    asyncio.run(bt_client(sys.argv[1]))
