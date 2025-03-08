def address_from_str(address: str) -> tuple[str, int]:
    assert ":" in address
    ip, port = address.split(":")
    return ip, int(port)


def address_to_str(address: tuple[str, int]) -> str:
    return f"{address[0]}:{address[1]}"


def address_from_bytes(address: bytes) -> tuple[str, int]:
    assert len(address) == 6
    return ".".join(map(str, address[:4])), int.from_bytes(address[4:], "big")


def address_list_from_bytes(addresses: bytes) -> list[tuple[str, int]]:
    assert len(addresses) % 6 == 0
    return [address_from_bytes(addresses[i : i + 6]) for i in range(0, len(addresses), 6)]
