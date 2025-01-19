import json
import sys
import hashlib
import secrets
import socket
import struct
import urllib.parse
import urllib.request
from enum import IntEnum


class MsgID(IntEnum):
    KEEPALIVE = -1
    UNCHOKE = 1
    INTERESTED = 2
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7


def encode_bencode(value: str | bytes | int | list | dict) -> bytes:
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


def decode_str(bencoded_value: bytes, pos: int) -> tuple[str, int] | tuple[bytes, int]:
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


def decode_int(bencoded_value: bytes, pos: int) -> tuple[int, int]:
    end = pos + 1
    while chr(bencoded_value[end]) != "e":
        end += 1
    return int(bencoded_value[pos+1:end]), end + 1


def decode_bencode(bencoded_value: bytes, pos: int=0) -> tuple[str, int] | tuple[bytes, int] | tuple[int, int] | tuple[list, int] | tuple[dict, int]:
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


def parse_metainfo_pieces(pieces: bytes) -> list[bytes]:
    pos = 0
    pieces_list = []
    while pos < len(pieces):
        pieces_list.append(pieces[pos:pos+20])
        pos += 20
    return pieces_list


def get_metainfo(file_name: str) -> dict:
    with open(file_name, "rb") as file:
        metainfo, _ = decode_bencode(file.read())
        return metainfo


def print_info(metainfo: dict):
    hash = hashlib.sha1(encode_bencode(metainfo["info"])).hexdigest()
    print(f"Tracker URL: {metainfo['announce']}")
    print(f"Length: {metainfo['info']['length']}")
    print(f"Info Hash: {hash}")
    print(f"Piece Length: {metainfo['info']['piece length']}")
    print("Piece Hashes:")
    for piece in parse_metainfo_pieces(metainfo["info"]["pieces"]):
        print(piece.hex())


def get_peers(metainfo: dict, peer_id: bytes, port: int=6881) -> list[tuple[str, int]]:
    query = {
        "info_hash": hashlib.sha1(encode_bencode(metainfo["info"])).digest(),
        "peer_id": peer_id,
        "port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": metainfo['info']['length'],
        "compact": 1,
    }
    url = metainfo['announce'] + "?" + urllib.parse.urlencode(query)
    res, _ = decode_bencode(urllib.request.urlopen(url).read())

    peers = []
    if "peers" in res:
        pos = 0
        while pos < len(res["peers"]):
            peer_ip = ".".join(map(str, res['peers'][pos:pos+4]))
            peer_port = int.from_bytes(res['peers'][pos+4:pos+6], 'big')
            peers.append((peer_ip, peer_port))
            pos += 6

    return peers


def encode_handshake(info_hash: bytes, peer_id: bytes) -> bytes:
    pstr = b"BitTorrent protocol"
    pstrlen = len(pstr)
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    
    message = bytearray(49 + pstrlen)
    message[0] = pstrlen
    message[1:1+pstrlen] = pstr
    message[1+pstrlen:1+pstrlen+8] = reserved
    message[1+pstrlen+8:1+pstrlen+8+20] = info_hash
    message[1+pstrlen+8+20:1+pstrlen+8+20+20] = peer_id
    return message


def decode_handshake(data: bytes) -> tuple[bytes, bytes]:
    pstr = b"BitTorrent protocol"
    r_pstrlen = data[0]
    r_pstr = data[1:1+r_pstrlen]
    assert pstr == r_pstr
    # r_reserved_ = data[1+r_pstrlen:1+r_pstrlen+8]
    r_info_hash = data[1+r_pstrlen+8:1+r_pstrlen+8+20]
    r_peer_id = data[1+r_pstrlen+8+20:1+r_pstrlen+8+20+20]
    return r_info_hash, r_peer_id


def send_handshake(sock: socket.SocketType, info_hash: bytes, peer_id: bytes) -> bytes:
    message = encode_handshake(info_hash, peer_id)
    sock.send(message)
    r_info_hash, r_peer_id = decode_handshake(sock.recv(1024))
    assert info_hash == r_info_hash
    return r_peer_id


def encode_message(id: int=None, payload: bytes=b"") -> bytes:
    payload_length = len(payload)
    message = bytearray(4 + (1 if id else 0) + payload_length)
    message[:4] = struct.pack("!I", (1 if id else 0) + payload_length)
    if id:
        message[4] = id
    if payload_length > 0:
        message[5:] = payload
    return message


def decode_message(message: bytes) -> tuple[int, bytes]:
    if len(message) < 4:
        # Signal incomplete message
        raise IndexError
    payload_length = struct.unpack("!I", message[:4])[0]
    if payload_length > 0:
        id = message[4] if payload_length > 1 else  -1
        payload = message[5:4+payload_length] if payload_length > 1 else b""
    return id, payload


def recv_bitfield(sock: socket.SocketType) -> bytes:
    id, bitfield = decode_message(sock.recv(1024))
    assert id == MsgID.BITFIELD
    return bitfield


def get_peers_info(peers: list[tuple[str, int]], info_hash: bytes, peer_id: bytes) -> dict[tuple[str, int], tuple[bytes, bytes]]:
    peers_info = {}
    for peer in peers:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(peer)
            r_peer_id = send_handshake(sock, info_hash, peer_id)
            r_bitfield = recv_bitfield(sock)
            sock.close()
            peers_info[peer] = (r_peer_id, r_bitfield)
    return peers_info


def has_bitfield_piece(bitfield: bytes, piece_index: int) -> bool:
    bitfield_index = piece_index // 8
    byte_mask = 1 << (7 - piece_index % 8)
    return (bitfield[bitfield_index] & byte_mask) != 0


def send_interested(sock: socket.SocketType) -> None:
    sock.send(encode_message(MsgID.INTERESTED, b""))


def recv_unchoke(sock: socket.SocketType) -> None:
    id, payload = decode_message(sock.recv(1024))
    assert id == MsgID.UNCHOKE
    assert len(payload) == 0


def send_request(sock: socket.SocketType, index: int, begin: int, length: int) -> None:
    msg_req = struct.pack("!IbIII", 13, MsgID.REQUEST, index, begin, length)
    sock.send(msg_req)


def recv_piece_chunk(sock: socket.SocketType, msg_length: int, chunk_length: int) -> tuple[int, int, bytes]:
    msg = b""
    msg_total = 0
    while msg_total < chunk_length:
        chunk = sock.recv(msg_length)
        msg += chunk
        msg_total += len(chunk)
        try:
            id, payload = decode_message(msg)
            assert id == MsgID.PIECE
        except AssertionError:
            # Unexpected message, discard data
            print("MsgID", id)
            msg_length = 5 + len(payload)
            msg = msg[msg_length:]
            msg_total -= msg_length
        except IndexError:
            # Incomplete message
            continue

    index = struct.unpack("!I", payload[0:4])[0]
    begin = struct.unpack("!I", payload[4:8])[0]
    block = payload[8:]
    return index, begin, block


def recv_piece(sock: socket.SocketType, metainfo: dict, piece_index: int) -> bytes:
    pieces = parse_metainfo_pieces(metainfo["info"]["pieces"])
    assert piece_index < len(pieces)
    piece_hash = pieces[piece_index]

    if piece_index < len(pieces) - 1:
        total_length = metainfo["info"]["piece length"]
    else:
        total_length = metainfo["info"]["length"] - metainfo["info"]["piece length"] * (len(pieces) - 1)

    piece = b""
    msg_length = 4*1024
    chunk_length = 16*1024
    current_begin = 0
    while current_begin < total_length:
        eff_chunk_length = min(chunk_length, total_length - current_begin)

        send_request(sock, piece_index, current_begin, eff_chunk_length)

        r_index, r_begin, r_block = recv_piece_chunk(sock, msg_length, eff_chunk_length)
        assert r_index == piece_index
        assert r_begin == current_begin

        piece += r_block
        current_begin += len(r_block)

    r_piece_hash = hashlib.sha1(piece).digest()
    assert r_piece_hash == piece_hash

    return piece


def main() -> None:
    peer_id = secrets.token_bytes(20)

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

        print(json.dumps(decode_bencode(bencoded_value)[0], default=bytes_to_str))
    
    elif command == "info":
        file_name = sys.argv[2]
        metainfo = get_metainfo(file_name)
        if metainfo:
            print_info(metainfo)
    
    elif command == "peers":
        file_name = sys.argv[2]
        metainfo = get_metainfo(file_name)
        if metainfo:
            for peer in get_peers(metainfo, peer_id, port=6881):
                print(f"{peer[0]}:{peer[1]}")

    elif command == "handshake":
        file_name = sys.argv[2]
        peer_host_port = sys.argv[3]
        peer_sep_index = peer_host_port.find(":")
        peer_host = peer_host_port[:peer_sep_index]
        peer_port = int(peer_host_port[peer_sep_index+1:])
        metainfo = get_metainfo(file_name)
        if metainfo:
            info_hash = hashlib.sha1(encode_bencode(metainfo["info"])).digest()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((peer_host, peer_port))
                r_peer_id = send_handshake(sock, info_hash, peer_id)
                sock.close()
                print(f"Peer ID: {r_peer_id.hex()}")

    elif command == "download_piece":
        piece_file_name = sys.argv[3]
        torrent_file_name = sys.argv[4]
        piece_index = int(sys.argv[5])
        metainfo = get_metainfo(torrent_file_name)
        if metainfo:
            info_hash = hashlib.sha1(encode_bencode(metainfo["info"])).digest()
            if piece_index >= len(metainfo["info"]["pieces"]):
                print(f"Piece {piece_index} not found in torrent")

            peers = get_peers(metainfo, peer_id)
            peers_info = get_peers_info(peers, info_hash, peer_id)
            peers_valid = [peer for peer in peers if has_bitfield_piece(peers_info[peer][1], piece_index)]
            if peers_valid:
                peer = peers_valid[0]
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect(peer)

                    _ = send_handshake(sock, info_hash, peer_id)

                    bitfield = recv_bitfield(sock)
                    assert has_bitfield_piece(bitfield, piece_index)

                    send_interested(sock)

                    recv_unchoke(sock)

                    piece = recv_piece(sock, metainfo, piece_index)

                    sock.close()

                    with open(piece_file_name, "wb") as file:
                        file.write(piece)

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
