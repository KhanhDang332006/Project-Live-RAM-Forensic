#!/usr/bin/env python3
"""Mã hóa bộ file mồi đúng theo DATA_CONTRACT.md mục 5–6, để test decrypt.py khi chưa có keyholder.

KHÔNG phải keyholder: không giữ khóa trong RAM, chỉ tạo file .locked và ground_truth.json.
Hoàng có thể dùng để đối chiếu đầu ra của keyholder: cùng tham số thì cùng layout file.

    python tests/mock_encrypt.py --profile prepend
    python tests/mock_encrypt.py --profile overwrite16 --bits 256 --out samples/encrypted_256 \
        --gt samples/encrypted_256/ground_truth.json
"""
import argparse
import json
import os
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def encrypt_blob(data, key, profile, iv=None):
    iv = iv or os.urandom(16)
    body = data if profile == "prepend" else data[16:]  # overwrite16: bỏ 16 byte đầu bản gốc
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(body, 16))


def main():
    if hasattr(sys.stdout, "reconfigure"):  # console Windows mặc định cp1252, in tiếng Việt sẽ lỗi
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Mã hóa giả lập theo hợp đồng dữ liệu")
    ap.add_argument("--src", default="samples/plain")
    ap.add_argument("--out", default="samples/encrypted")
    ap.add_argument("--profile", choices=["prepend", "overwrite16"], required=True)
    ap.add_argument("--bits", type=int, choices=[128, 256], default=128)
    ap.add_argument("--key", help="khóa hex (mặc định: ngẫu nhiên)")
    ap.add_argument("--gt", default="ground_truth.json", help="nơi ghi ground_truth.json")
    args = ap.parse_args()

    key = bytes.fromhex(args.key) if args.key else os.urandom(args.bits // 8)
    if len(key) * 8 != args.bits:
        sys.exit("--key dài %d bit, khác --bits %d" % (len(key) * 8, args.bits))

    n = 0
    for dirpath, _, names in os.walk(args.src):
        for name in names:
            if name.startswith("."):  # bỏ .gitkeep, file ẩn
                continue
            src = os.path.join(dirpath, name)
            dst = os.path.join(args.out, os.path.relpath(src, args.src)) + ".locked"
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(src, "rb") as f:
                blob = encrypt_blob(f.read(), key, args.profile)
            with open(dst, "wb") as f:
                f.write(blob)
            n += 1

    gt = {"schema": 1, "profile": args.profile, "keys": [{
        "source": "mock_encrypt", "dump_time": None, "scope": None, "pid": None, "offset": None,
        "bits": args.bits, "key_hex": key.hex(), "tool": "ground_truth"}]}
    os.makedirs(os.path.dirname(os.path.abspath(args.gt)), exist_ok=True)
    with open(args.gt, "w", encoding="utf-8") as f:
        json.dump(gt, f, indent=2)
    print("Đã mã hóa %d file (%s, AES-%d) vào %s; khóa ghi ở %s" % (n, args.profile, args.bits, args.out, args.gt))


if __name__ == "__main__":
    main()
