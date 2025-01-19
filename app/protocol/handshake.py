import socket


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
    r_reserved_ = data[1+r_pstrlen:1+r_pstrlen+8]
    r_info_hash = data[1+r_pstrlen+8:1+r_pstrlen+8+20]
    r_peer_id = data[1+r_pstrlen+8+20:1+r_pstrlen+8+20+20]
    return r_reserved_, r_info_hash, r_peer_id


def do_handshake(sock: socket.SocketType, info_hash: bytes, peer_id: bytes) -> bytes:
    sock.send(encode_handshake(info_hash, peer_id))
    r_reserved, r_info_hash, r_peer_id = decode_handshake(sock.recv(1024))
    assert info_hash == r_info_hash
    return r_peer_id, r_reserved
