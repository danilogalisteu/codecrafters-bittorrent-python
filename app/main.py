import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"

def decode_str(bencoded_value, pos):
    first_colon_index = bencoded_value[pos:].find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    str_length = int(bencoded_value[pos:pos+first_colon_index])
    return bencoded_value[pos+first_colon_index+1:pos+first_colon_index+1+str_length], pos+first_colon_index+1+str_length


def decode_int(bencoded_value, pos):
    end = pos
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
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
