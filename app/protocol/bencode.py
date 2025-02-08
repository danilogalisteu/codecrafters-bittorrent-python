from typing import Any


def encode_bencode(value: str | bytes | int | list[Any] | dict[str | bytes, Any]) -> bytes:
    if isinstance(value, str):
        value_array = value.encode()
        return f"{len(value_array)}:".encode() + value_array
    if isinstance(value, bytes):
        return f"{len(value)}:".encode() + value
    if isinstance(value, int):
        return f"i{value}e".encode()
    if isinstance(value, list):
        value_array = b"l"
        for v in value:
            value_array += encode_bencode(v)
        return value_array + b"e"
    if isinstance(value, dict):
        value_array = b"d"
        for k in sorted(value):
            value_array += encode_bencode(k)
            value_array += encode_bencode(value[k])
        return value_array + b"e"
    raise NotImplementedError(f"encode_bencode: invalid value {value}")


def decode_str(value: bytes, pos: int) -> tuple[str, int] | tuple[bytes, int]:
    first_colon_index = value[pos:].find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    str_length = int(value[pos : pos + first_colon_index])
    str_pos = pos + first_colon_index + 1
    str_end = str_pos + str_length
    try:
        return value[str_pos:str_end].decode(), str_end
    except UnicodeDecodeError:
        return value[str_pos:str_end], str_end


def decode_int(value: bytes, pos: int) -> tuple[int, int]:
    end = pos + 1
    while chr(value[end]) != "e":
        end += 1
    return int(value[pos + 1 : end]), end + 1


def decode_bencode(
    value: bytes,
    pos: int = 0,
) -> tuple[str, int] | tuple[bytes, int] | tuple[int, int] | tuple[list[Any], int] | tuple[dict[str | bytes, Any], int]:
    if chr(value[pos]).isdigit():
        return decode_str(value, pos)
    if chr(value[pos]) == "i":
        return decode_int(value, pos)
    if chr(value[pos]) == "l":
        res_list = []
        pos += 1
        while chr(value[pos]) != "e":
            res, pos = decode_bencode(value, pos)
            res_list.append(res)
        return res_list, pos + 1
    if chr(value[pos]) == "d":
        res_dict = {}
        pos += 1
        while chr(value[pos]) != "e":
            res_key, pos = decode_str(value, pos)
            res_val, pos = decode_bencode(value, pos)
            res_dict[res_key] = res_val
        return res_dict, pos + 1
    raise NotImplementedError(f"decode_bencode: invalid value {value!r}")
