import json
import sys
import hashlib

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"


def encode_bencode(value):
    if isinstance(value, str):
        value_array = value.encode()
        return f"{len(value_array)}:".encode() + value_array
    if isinstance(value, bytes):
        return f"{len(value)}:".encode() + value
    elif isinstance(value, int):
        return f"i{value}e".encode()
    elif isinstance(value, list):
        value_array = b"l"
        for v in value:
            value_array += encode_bencode(v)
        return value_array + b"e"
    elif isinstance(value, dict):
        value_array = b"d"
        for k in sorted(value):
            value_array += encode_bencode(k)
            value_array += encode_bencode(value[k])
        return value_array + b"e"


def decode_str(bencoded_value, pos):
    first_colon_index = bencoded_value[pos:].find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    str_length = int(bencoded_value[pos:pos+first_colon_index])
    str_pos = pos+first_colon_index+1
    str_end = str_pos+str_length
    try:
        return bencoded_value[str_pos:str_end].decode(), str_end
    except UnicodeDecodeError:
        return bencoded_value[str_pos:str_end], str_end


def decode_int(bencoded_value, pos):
    end = pos + 1
    while chr(bencoded_value[end]) != "e":
        end += 1
    return int(bencoded_value[pos+1:end]), end + 1


def decode_bencode(bencoded_value, pos):
    if chr(bencoded_value[pos]).isdigit():
        return decode_str(bencoded_value, pos)
    elif chr(bencoded_value[pos]) == "i":
        return decode_int(bencoded_value, pos)
    elif chr(bencoded_value[pos]) == "l":
        res_list = []
        pos += 1
        while chr(bencoded_value[pos]) != "e":
            res, pos = decode_bencode(bencoded_value, pos)
            res_list.append(res)
        return res_list, pos + 1
    elif chr(bencoded_value[pos]) == "d":
        res_dict = {}
        pos += 1
        while chr(bencoded_value[pos]) != "e":
            res_key, pos = decode_str(bencoded_value, pos)
            res_val, pos = decode_bencode(bencoded_value, pos)
            res_dict[res_key] = res_val
        return res_dict, pos + 1
    else:
        raise NotImplementedError("Only strings are supported at the moment")


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value, 0)[0], default=bytes_to_str))
    
    elif command == "info":
        file_name = sys.argv[2]
        with open(file_name, "rb") as file:
            metainfo, _ = decode_bencode(file.read(), 0)
            info = encode_bencode(metainfo["info"])
            hash = hashlib.sha1(info).hexdigest()
            print(f"Tracker URL: {metainfo['announce']}")
            print(f"Length: {metainfo['info']['length']}")
            print(f"Info Hash: {hash}")

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
