#!/usr/bin/env python3
"""Tạo manifest.csv cho bộ file mồi (xem DATA_CONTRACT.md, mục 7).

Chạy TRƯỚC khi mã hóa:
    python tools/make_manifest.py                       # samples/plain -> manifest.csv
    python tools/make_manifest.py --src D:/mồi --out manifest.csv
"""
import argparse
import csv
import hashlib
import os
import sys
from collections import Counter

FIELDS = ["filename", "ext", "size", "sha256", "magic_hex", "header16_hex"]
EXPECTED_EXT = ["pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg"]
CHUNK = 1024 * 1024


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def describe(root, path):
    with open(path, "rb") as f:
        head = f.read(16)
    name = os.path.relpath(path, root).replace(os.sep, "/")
    ext = os.path.splitext(name)[1].lstrip(".").lower()
    return {
        "filename": name,
        "ext": ext,
        "size": os.path.getsize(path),
        "sha256": sha256_file(path),
        "magic_hex": head[:8].hex(),
        "header16_hex": head.hex(),
    }


def main():
    if hasattr(sys.stdout, "reconfigure"):  # console Windows mặc định cp1252, in tiếng Việt sẽ lỗi
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Tạo manifest.csv cho bộ file mồi")
    ap.add_argument("--src", default="samples/plain", help="thư mục file mồi (mặc định: samples/plain)")
    ap.add_argument("--out", default="manifest.csv", help="file đầu ra (mặc định: manifest.csv)")
    args = ap.parse_args()

    if not os.path.isdir(args.src):
        sys.exit("Không thấy thư mục: %s" % args.src)

    paths = []
    for dirpath, _, files in os.walk(args.src):
        paths += [os.path.join(dirpath, n) for n in files if not n.startswith(".")]  # bỏ .gitkeep, file ẩn
    if not paths:
        sys.exit("Thư mục rỗng: %s" % args.src)

    rows = sorted((describe(args.src, p) for p in paths), key=lambda r: r["filename"])
    locked = [r["filename"] for r in rows if r["ext"] == "locked"]
    if locked:
        sys.exit("Có file .locked trong thư mục gốc, có vẻ chạy nhầm sau khi mã hóa: %s" % locked[0])

    # utf-8-sig để Excel hiển thị đúng tiếng Việt
    with open(args.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    count = Counter(r["ext"] for r in rows)
    print("Đã ghi %d file vào %s" % (len(rows), args.out))
    for ext in sorted(count):
        print("  %-5s %d" % (ext, count[ext]))
    missing = [e for e in EXPECTED_EXT if e not in count]
    if missing:
        print("Cảnh báo: thiếu loại %s" % ", ".join(missing))
    short = [r["filename"] for r in rows if r["size"] < 16]
    if short:
        print("Lưu ý: %d file ngắn hơn 16 byte (overwrite16 sẽ mất toàn bộ nội dung): %s"
              % (len(short), ", ".join(short)))


if __name__ == "__main__":
    main()
