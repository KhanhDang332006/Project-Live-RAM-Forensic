#!/usr/bin/env python3
"""aes_schedule.py - sinh AES key schedule (Rijndael key expansion).

Dung chung cho keyscan.py: voi mot khoa ung vien, tinh ra toan bo key schedule
dung chuan roi doi chieu voi cac byte nam ngay sau trong dump. Trung -> la khoa that.
Nen tang giong cong cu findaes/aeskeyfind (cong trinh Trenholme / 'Lest We Remember').
"""

# AES S-box
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D]


def _sub_word(w):
    return bytes(SBOX[b] for b in w)


def _rot_word(w):
    return w[1:] + w[:1]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def expand_key(key: bytes) -> bytes:
    """Khoa 16/24/32 byte -> key schedule 176/208/240 byte (chuan Rijndael)."""
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise ValueError("khoa phai 16, 24 hoac 32 byte")
    nr = {4: 10, 6: 12, 8: 14}[nk]
    total = 4 * (nr + 1)              # so word tong cong
    w = [key[4 * i:4 * i + 4] for i in range(nk)]
    for i in range(nk, total):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _xor(_sub_word(_rot_word(temp)), bytes([RCON[i // nk - 1], 0, 0, 0]))
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp)
        w.append(_xor(w[i - nk], temp))
    return b"".join(w)


# so byte key schedule theo so bit khoa
SCHED_LEN = {128: 176, 192: 208, 256: 240}


if __name__ == "__main__":
    # NIST FIPS-197 test vector cho AES-128
    k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    sched = expand_key(k)
    assert sched[:16] == k
    # word W[43] cuoi cung theo FIPS-197 phai la b6630ca6
    assert sched[-4:].hex() == "b6630ca6", sched[-4:].hex()
    print("expand_key OK, AES-128 schedule =", len(sched), "byte")
    print("AES-256 schedule =", len(expand_key(b"\x00" * 32)), "byte")
