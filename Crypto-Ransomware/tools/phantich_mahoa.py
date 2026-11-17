#!/usr/bin/env python3
"""Phân tích hành vi mã hóa của NotPetya trên toàn bộ corpus, chỉ dùng: manifest + thư mục file đã mã hóa + khóa.

Với từng file trong manifest:
  - untouched : SHA-256 trùng manifest -> mẫu không đụng tới.
  - full      : kích thước = gốc + đệm PKCS7 (1..16 byte) -> mã hóa toàn bộ.
  - partial   : kích thước không đổi nhưng nội dung khác -> chỉ mã hóa một phần.
Rồi kiểm chứng bằng khóa:
  - IV thực của mỗi file = AES_K^-1(C1) XOR P1 (P1 = header16 trong manifest).
  - file partial: giải mã 1 MiB đầu bằng IV đó, phần sau giữ nguyên -> so SHA-256 với manifest.
  - IV khác 0 có trùng khối cuối vùng 1 MiB của một file partial khác không (rò trạng thái CBC).

    python3 tools/phantich_mahoa.py --enc /mnt/hgfs/evidence/plain \
        --manifest /mnt/hgfs/evidence/manifest_bigrun.csv --key a4e7d6834a63030ac6000f2d8a63a14b
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    sys.exit("Thiếu pycryptodome: python -m pip install -r requirements.txt")

MIB = 1 << 20
ZERO = b"\0" * 16


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Phân tích hành vi mã hóa trên corpus (NotPetya)")
    ap.add_argument("--enc", required=True, help="thư mục file đã mã hóa (giữ nguyên tên)")
    ap.add_argument("--manifest", required=True, help="manifest ground-truth trước khi mã hóa")
    ap.add_argument("--key", required=True, help="khóa AES-128 (hex) tìm được bằng keyscan")
    ap.add_argument("--json", help="ghi kết quả từng file ra JSON")
    a = ap.parse_args()

    key = bytes.fromhex(a.key)
    ecb = AES.new(key, AES.MODE_ECB)
    with open(a.manifest, newline="", encoding="utf-8-sig") as f:
        mani = list(csv.DictReader(f))

    rows = []
    for m in mani:
        path = os.path.join(a.enc, m["filename"])
        if not os.path.exists(path):
            rows.append(dict(file=m["filename"], ext=m["ext"], cls="missing"))
            continue
        with open(path, "rb") as f:
            data = f.read()
        size = int(m["size"])
        if hashlib.sha256(data).hexdigest() == m["sha256"]:
            cls = "untouched"
        elif len(data) == size + 16 - size % 16:
            cls = "full"
        elif len(data) == size:
            cls = "partial"
        else:
            cls = "other"
        r = dict(file=m["filename"], ext=m["ext"], size=size, cls=cls, iv="", recovered=None)
        if cls in ("full", "partial"):
            p1 = bytes.fromhex(m["header16_hex"])
            iv = bytes(x ^ y for x, y in zip(ecb.decrypt(data[:16]), p1))
            r["iv"] = iv.hex()
            if cls == "full":
                try:
                    out = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), 16)
                except ValueError:
                    out = b""
            else:
                out = AES.new(key, AES.MODE_CBC, iv).decrypt(data[:MIB]) + data[MIB:]
            r["recovered"] = hashlib.sha256(out).hexdigest() == m["sha256"]
            r["tail"] = data[MIB - 16:MIB].hex() if cls == "partial" else ""
        rows.append(r)

    # ---- bảng theo phần mở rộng
    per = collections.defaultdict(collections.Counter)
    for r in rows:
        per[r["ext"]][r["cls"]] += 1
    print("%-6s %7s %7s %8s %9s" % ("đuôi", "tổng", "toàn bộ", "1 MiB đầu", "giữ nguyên"))
    for ext in sorted(per, key=lambda e: (-(per[e]["full"] + per[e]["partial"]), e)):
        c = per[ext]
        print("%-6s %7d %7d %8d %9d" % (ext, sum(c.values()), c["full"], c["partial"], c["untouched"]))
    tot = collections.Counter(r["cls"] for r in rows)
    print("TỔNG   %7d %7d %8d %9d   (khác: %d)" % (len(rows), tot["full"], tot["partial"], tot["untouched"],
                                                  tot["missing"] + tot["other"]))

    # ---- ngưỡng kích thước
    full = [r for r in rows if r["cls"] == "full"]
    part = [r for r in rows if r["cls"] == "partial"]
    if full and part:
        print("Ngưỡng: file mã hóa toàn bộ lớn nhất %d byte; file chỉ mã hóa một phần nhỏ nhất %d byte (1 MiB = %d)"
              % (max(r["size"] for r in full), min(r["size"] for r in part), MIB))

    # ---- IV
    enc = full + part
    tails = {r["tail"] for r in part}
    iv0 = sum(r["iv"] == ZERO.hex() for r in enc)
    chained = sum(r["iv"] != ZERO.hex() and r["iv"] in tails for r in enc)
    print("IV = 0: %d/%d file | IV = khối cuối vùng 1 MiB của file khác: %d | không giải thích được: %d"
          % (iv0, len(enc), chained, len(enc) - iv0 - chained))

    # ---- khôi phục
    print("Khôi phục khớp SHA-256: toàn bộ %d/%d, 1 MiB đầu %d/%d -> tổng %d/%d file bị mã hóa"
          % (sum(bool(r["recovered"]) for r in full), len(full), sum(bool(r["recovered"]) for r in part), len(part),
             sum(bool(r["recovered"]) for r in enc), len(enc)))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=1)
        print("Ghi chi tiết -> %s" % a.json)


if __name__ == "__main__":
    main()
