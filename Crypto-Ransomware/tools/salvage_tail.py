# -*- coding: utf-8 -*-
"""Cuu file co KHOI CUOI bi hong (vd bi ghi/copy toan 0) nhung noi dung van nguyen.

decrypt.py loc khoa bang padding o khoi cuoi; neu khoi cuoi hong thi no bao NO_KEY du
khoa dung va noi dung con nguyen. Script nay bo dung khoi padding cuoi roi giai phan con lai
bang CBC (profile overwrite16: iv = 16 byte dau, ciphertext = tu byte 16), va va 16 byte dau
tu header16 trong manifest. Kiem SHA-256 voi ban goc.

    python tools/salvage_tail.py --in <file.locked> --key <hex> --manifest manifest.csv
                                 --out <file_cuu> [--name <ten_trong_manifest>]
"""
import argparse
import csv
import hashlib
import os
import sys

from Crypto.Cipher import AES


def load_manifest(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return {r["filename"]: r for r in csv.DictReader(f)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="file .locked bi hong khoi cuoi")
    ap.add_argument("--key", required=True, help="khoa AES thang cuoc (hex)")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", help="ten file trong manifest (mac dinh: suy tu file .locked)")
    a = ap.parse_args()

    name = a.name or os.path.basename(a.inp)
    if name.endswith(".locked"):
        name = name[:-len(".locked")]
    man = load_manifest(a.manifest)
    mrow = man.get(name)
    if not mrow:
        sys.exit("Khong thay '%s' trong manifest" % name)

    key = bytes.fromhex(a.key)
    head = bytes.fromhex(mrow["header16_hex"])[:16]   # 16 byte dau goc (bi IV ghi de)
    want = mrow["sha256"].lower()

    blob = open(a.inp, "rb").read()
    iv, ct = blob[:16], blob[16:]
    print("[=] File        :", name)
    print("[=] Khoa         :", a.key)
    print("[=] Kich thuoc   : ma hoa %d byte | 16 byte cuoi: %s" % (len(blob), ct[-16:].hex()))
    print("[=] Khoi cuoi bi hong -> bo 16 byte cuoi, giai phan noi dung con lai")

    content_ct = ct[:-16]                              # bo khoi padding cuoi bi hong
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(content_ct)
    out = head + data                                  # va lai 16 byte dau tu manifest

    got = hashlib.sha256(out).hexdigest().lower()
    print("[=] SHA-256 goc  :", want)
    print("[=] SHA-256 cuu  :", got)
    if got == want:
        open(a.out, "wb").write(out)
        print("[+] SHA-256 KHOP -> da ghi file cuu: %s (%d byte)" % (a.out, len(out)))
    else:
        sys.exit("[!] SHA-256 KHONG khop - noi dung cung bi hong, khong chi khoi cuoi.")


if __name__ == "__main__":
    main()
