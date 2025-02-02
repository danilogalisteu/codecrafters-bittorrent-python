def address_str_to_tuple(address: str) -> tuple[str, int]:
    assert ":" in address
    ip, port = address.split(":")
    return ip, int(port)
