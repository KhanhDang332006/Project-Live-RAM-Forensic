#!/usr/bin/env python3
"""keyholder.py - test-vector generator cho pipeline keyscan/decrypt.

KHONG phai ransomware: chi ma hoa BAN SAO cac file trong thu muc test sang
thu muc khac bang mot khoa AES BIET TRUOC, roi ghi khoa ra ground_truth.json.
Khong ghi de, khong xoa, khong dung file goc. Dung de test cong cu khi chua co
dump mau that, va de giu khoa trong RAM (--hold) phuc vu test dump.

Profile:
  prepend     : out = IV || CBC(key, IV, PKCS7(P))        # khong mat byte
  overwrite16 : out = IV || CBC(key, IV, PKCS7(P[16:]))   # mat 16 byte dau P (giong NotPetya)

Vi du:
  python keyholder.py --in samples/plain --out samples/enc_prepend_aes128 --bits 128 --profile prepend
  python keyholder.py --in samples/plain --out samples/enc_prepend_aes256 --bits 256 --profile prepend
  python keyholder.py --in samples/plain --out samples/enc_ow16_aes128 --profile overwrite16 --hold
"""
import argparse, hashlib, json, os, sys
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VN = timezone(timedelta(hours=7))
BLOCK = 16


def pkcs7(data: bytes) -> bytes:
    pad = BLOCK - (len(data) % BLOCK)
    return data + bytes([pad]) * pad


def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(pkcs7(data)) + enc.finalize()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="indir", required=True)
    ap.add_argument("--out", dest="outdir", required=True)
    ap.add_argument("--bits", type=int, choices=[128, 256], default=128)
    ap.add_argument("--profile", choices=["prepend", "overwrite16"], default="prepend")
    ap.add_argument("--key", help="khoa hex co san; khong co thi sinh ngau nhien")
    ap.add_argument("--hold", action="store_true", help="giu khoa trong RAM cho toi khi Enter (de dump)")
    a = ap.parse_args()

    indir = os.path.abspath(a.indir)
    outdir = os.path.abspath(a.outdir)
    # An toan: out khong duoc trung hay nam trong in
    if outdir == indir or outdir.startswith(indir + os.sep):
        sys.exit("[!] --out khong duoc trung hoac nam trong --in")
    os.makedirs(outdir, exist_ok=True)

    key = bytes.fromhex(a.key) if a.key else os.urandom(a.bits // 8)
    if len(key) != a.bits // 8:
        sys.exit(f"[!] khoa phai dai {a.bits // 8} byte")

    files, created = [], datetime.now(VN).isoformat(timespec="seconds")
    for name in sorted(os.listdir(indir)):
        src = os.path.join(indir, name)
        if not os.path.isfile(src):
            continue
        plain = open(src, "rb").read()
        iv = os.urandom(BLOCK)
        body = plain if a.profile == "prepend" else plain[BLOCK:]
        blob = iv + encrypt(key, iv, body)
        locked = name + ".locked"
        open(os.path.join(outdir, locked), "wb").write(blob)
        files.append({
            "locked": locked,
            "orig": name,
            "orig_sha256": hashlib.sha256(plain).hexdigest(),
            "iv_hex": iv.hex(),
            "plaintext_bytes": len(plain),
        })
        print(f"[+] {name} -> {locked} ({len(plain)} B)")

    gt = {
        "schema": 1,
        "batch": os.path.basename(outdir),
        "profile": a.profile,          # prepend | overwrite16
        "bits": a.bits,
        "mode": "AES-CBC-PKCS7",
        "iv_location": "prepend_16",   # 16 byte dau cua file .locked la IV
        "lost_head_bytes": 0 if a.profile == "prepend" else 16,
        "key_hex": key.hex(),
        "created": created,
        "files": files,
        "keys": [{
            "source": "ground_truth", "bits": a.bits, "key_hex": key.hex(),
            "tool": "ground_truth", "pid": None, "scope": None, "offset": None,
        }],
    }
    gt_path = os.path.join(outdir, "ground_truth.json")
    json.dump(gt, open(gt_path, "w"), indent=2)
    print(f"[=] {len(files)} file, profile={a.profile}, bits={a.bits}")
    print(f"[=] key = {key.hex()}")
    print(f"[=] ground truth -> {gt_path}")

    if a.hold:
        # Giu KEY SCHEDULE song trong RAM, khong chi 16 byte khoa tho.
        # findaes/aeskeyfind/keyscan tim key schedule (176/208/240 byte) chu
        # khong tim 16 byte khoa; schedule chi ton tai khi context ma hoa con
        # song. Tao mot encryptor va KHONG finalize de OpenSSL giu schedule
        # (mo phong ransomware that dang trong qua trinh ma hoa).
        held = Cipher(algorithms.AES(key), modes.CBC(os.urandom(BLOCK))).encryptor()
        held.update(b"\x00" * 64)        # ep OpenSSL nap key schedule vao RAM
        print(f"[*] PID {os.getpid()} - key schedule dang trong RAM. Dump xong roi Enter de thoat...")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass
        held.update(b"\x00" * 16)        # cham lai sau input de held khong bi giai phong som


if __name__ == "__main__":
    main()
