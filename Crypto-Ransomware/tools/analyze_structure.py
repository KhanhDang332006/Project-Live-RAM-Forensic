#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""So sanh cau truc file goc (plain) / da khoa (.locked) / da giai (decrypted).

In ra: kich thuoc, 16 byte dau (hex), magic/header co dung khong, entropy Shannon.
Dung de chung minh bang chung-cu the cho Buoc 3-4-5 bao cao: IV ghi de header,
entropy tang vot sau ma hoa, roi tro ve dung gia tri goc sau giai ma.

    python tools/analyze_structure.py --plain /c/evidence/plain \
        --locked /c/evidence/notpetya_locked --decrypted /c/evidence/notpetya_decrypted \
        --manifest /c/evidence/manifest_notpetya.csv
"""
import argparse
import csv
import hashlib
import math
import os
from collections import Counter

MAGIC = {"pdf": b"%PDF", "docx": b"PK\x03\x04", "xlsx": b"PK\x03\x04", "zip": b"PK\x03\x04",
         "doc": bytes.fromhex("d0cf11e0a1b11ae1"), "xls": bytes.fromhex("d0cf11e0a1b11ae1")}


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in Counter(b).values())


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def load_manifest(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return {r["filename"]: r for r in csv.DictReader(f)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plain", required=True)
    ap.add_argument("--locked", required=True)
    ap.add_argument("--decrypted", required=True)
    ap.add_argument("--manifest", required=True)
    a = ap.parse_args()

    man = load_manifest(a.manifest)
    for name, row in sorted(man.items()):
        ext = row["ext"]
        p_plain = os.path.join(a.plain, name)
        p_locked = os.path.join(a.locked, name + ".locked")
        p_dec = os.path.join(a.decrypted, name)
        if not os.path.exists(p_plain):
            continue
        plain = open(p_plain, "rb").read()
        locked = open(p_locked, "rb").read() if os.path.exists(p_locked) else b""
        dec = open(p_dec, "rb").read() if os.path.exists(p_dec) else b""

        print("=" * 78)
        print("FILE:", name, "(%s)" % ext)
        print("-" * 78)
        print("%-12s %8s  %-34s %-8s %6s" % ("trang_thai", "kich_thuoc", "16_byte_dau(hex)", "magic_ok", "entropy"))
        for label, data in (("goc(plain)", plain), (".locked", locked), ("decrypted", dec)):
            if not data:
                print("%-12s %8s" % (label, "-- (khong co) --"))
                continue
            head = data[:16].hex()
            magic_ok = "-" if label == ".locked" else str(data.startswith(MAGIC.get(ext, b"\0")))
            print("%-12s %8d  %-34s %-8s %6.2f" % (label, len(data), head, magic_ok, entropy(data[:4096])))
        if dec:
            match = "KHOP" if sha256(dec) == row["sha256"].lower() else "LECH"
            print("-> SHA-256 decrypted vs goc: %s" % match)
        print()


if __name__ == "__main__":
    main()
