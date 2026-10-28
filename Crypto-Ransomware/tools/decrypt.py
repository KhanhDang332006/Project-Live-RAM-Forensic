#!/usr/bin/env python3
"""Giải mã file bị ransomware mã hóa bằng khóa AES dò được trong RAM.

Tương ứng Experiment part 3 của bài báo (mục 3.2.3, 4.3.3, 5.x.3).
Định dạng đầu vào/đầu ra: DATA_CONTRACT.md mục 4–8.

    python tools/decrypt.py --keys ground_truth.json          # profile lấy từ ground_truth
    python tools/decrypt.py --keys keys.json --profile overwrite16
    python tools/decrypt.py --keys keys.json --profile overwrite16 --manifest= --patch template
                                                               # giống điều tra thật: không có bản gốc

Cách chọn khóa đúng trong hàng trăm khóa ứng viên:
  1. Lọc nhanh: chỉ giải mã khối cuối, kiểm tra padding PKCS7 (khóa sai lọt qua ~1/256).
  2. Xác nhận: có manifest thì so SHA-256; không có thì kiểm tra cấu trúc theo loại file.
     (Không dùng entropy cho docx/xlsx/jpg: bản thân các file này đã nén, entropy vốn cao.)
  3. Khóa đã giải mã đúng file khác được thử trước (cả lô dùng chung một khóa).

Dùng như module (tool của nhóm):
    sys.path.insert(0, "tools"); import decrypt
    keys, profile = decrypt.load_keys(["keys.json"])
    rows = decrypt.run("samples/encrypted", keys, "overwrite16", decrypt.load_manifest("manifest.csv"))
"""
import argparse
import csv
import hashlib
import json
import math
import os
import sys
from collections import Counter

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    sys.exit("Thiếu pycryptodome: python -m pip install -r requirements.txt")

SUFFIX = ".locked"
REPORT_FIELDS = ["file", "profile", "key_tool", "key_source", "key_hex",
                 "header_patch", "magic_ok", "sha256_ok", "status", "note"]

# DATA_CONTRACT.md mục 6. iv_offset âm = tính từ cuối file; ct_end None = tới hết file.
PROFILES = {
    "prepend":     {"iv_offset": 0, "ct_start": 16, "ct_end": None, "lost_head": 0},
    "overwrite16": {"iv_offset": 0, "ct_start": 16, "ct_end": None, "lost_head": 16},
}

OLE = bytes.fromhex("d0cf11e0a1b11ae1")
MAGIC = {"pdf": b"%PDF", "docx": b"PK\x03\x04", "xlsx": b"PK\x03\x04", "zip": b"PK\x03\x04",
         "doc": OLE, "xls": OLE, "jpg": b"\xff\xd8\xff"}
ZIP_EXT = ("docx", "xlsx", "zip")
OLE_EXT = ("doc", "xls")
TEXT_EXT = ("txt", "csv")
# Header đoán cho loại không dựng lại chính xác được: file vẫn mở được nhưng hash có thể lệch.
# Phải dài đúng 16 byte = số byte mất, để offset phía sau giữ nguyên (bảng xref của PDF dựa vào offset).
GUESS_HEAD = {
    "pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\r\n",
    "jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01",
}


# ---------------------------------------------------------------- đọc đầu vào

def load_keys(paths):
    """Đọc keys.json / ground_truth.json. Trả về (danh sách khóa không trùng, profile hoặc None)."""
    keys, seen, profile = [], set(), None
    for path in paths:
        with open(path, encoding="utf-8-sig") as f:
            doc = json.load(f)
        if doc.get("schema") != 1:
            print("Cảnh báo: %s có schema=%r, hợp đồng hiện tại là 1" % (path, doc.get("schema")))
        p = doc.get("profile")
        if p:
            if profile and p != profile:
                raise ValueError("Các file khóa khai báo profile khác nhau: %s / %s" % (profile, p))
            profile = p
        for i, k in enumerate(doc.get("keys", [])):
            hx = str(k.get("key_hex", "")).lower()
            try:
                raw = bytes.fromhex(hx)
            except ValueError:
                print("Bỏ qua %s#%d: key_hex không phải hex" % (path, i))
                continue
            if k.get("bits") not in (128, 256) or len(raw) * 8 != k.get("bits"):
                print("Bỏ qua %s#%d: bits=%r không khớp độ dài key_hex (%d bit)"
                      % (path, i, k.get("bits"), len(raw) * 8))
                continue
            if hx in seen:  # cùng khóa xuất hiện ở nhiều dump: giữ dòng đầu tiên
                continue
            seen.add(hx)
            keys.append(dict(k, key_hex=hx, raw=raw))
    return keys, profile


def load_manifest(path):
    if not path:
        return {}
    if not os.path.exists(path):
        print("Cảnh báo: không thấy %s, sẽ không so được SHA-256" % path)
        return {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        return {r["filename"]: r for r in csv.DictReader(f)}


# ---------------------------------------------------------------- AES

def split(blob, prof):
    off = prof["iv_offset"] + (len(blob) if prof["iv_offset"] < 0 else 0)
    return blob[off:off + 16], blob[prof["ct_start"]:prof["ct_end"]]


def padding_ok(key, iv, ct):
    """Chỉ giải mã khối cuối: P_n = D(C_n) XOR C_(n-1). Rẻ, loại ~255/256 khóa sai."""
    prev = ct[-32:-16] if len(ct) >= 32 else iv
    last = bytes(a ^ b for a, b in zip(AES.new(key, AES.MODE_ECB).decrypt(ct[-16:]), prev))
    n = last[-1]
    return 1 <= n <= 16 and last[-n:] == bytes([n]) * n


# ---------------------------------------------------------------- vá header

def zip_head(data, lost):
    """docx/xlsx là file ZIP. 16 byte đầu (local header của entry đầu tiên) chứa lại đúng các
    trường đã có trong central directory nằm ở cuối file, nên dựng lại được chính xác."""
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        return None
    count = int.from_bytes(data[eocd + 10:eocd + 12], "little")
    pos = int.from_bytes(data[eocd + 16:eocd + 20], "little") - lost  # offset tính trên file gốc
    for _ in range(count):
        if pos < 0 or data[pos:pos + 4] != b"PK\x01\x02":
            return None
        if int.from_bytes(data[pos + 42:pos + 46], "little") == 0:  # entry có local header ở offset 0
            flags = int.from_bytes(data[pos + 8:pos + 10], "little")
            crc = b"\0" * 4 if flags & 0x08 else data[pos + 16:pos + 20]  # bit 3: CRC nằm ở data descriptor
            head = b"PK\x03\x04" + data[pos + 6:pos + 16] + crc  # version, flags, method, time, date, crc
            return head[:lost] if lost <= len(head) else None
        n, m, c = (int.from_bytes(data[pos + o:pos + o + 2], "little") for o in (28, 30, 32))
        pos += 46 + n + m + c
    return None


def patch_head(ext, data, lost, patch, mrow):
    """Trả về (header, header_patch, ghi chú)."""
    if lost == 0:
        return b"", "none", ""
    if patch in ("auto", "manifest") and mrow and mrow.get("header16_hex"):
        return bytes.fromhex(mrow["header16_hex"])[:lost], "manifest", ""
    if patch in ("auto", "template"):
        if ext in ZIP_EXT:
            head = zip_head(data, lost)
            if head is not None:
                return head, "template", "header dựng lại chính xác từ central directory"
        elif ext in OLE_EXT and lost <= 24:  # MS-CFB: magic 8 byte + CLSID 16 byte luôn bằng 0
            return (OLE + b"\0" * 16)[:lost], "template", "header OLE dựng lại chính xác"
        elif ext in GUESS_HEAD and lost <= len(GUESS_HEAD[ext]):
            return GUESS_HEAD[ext][:lost], "template", "header đoán theo loại file"
    return b"", "none", "mất %d byte đầu, chưa vá header" % lost


# ---------------------------------------------------------------- kiểm tra kết quả

def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in Counter(b).values())


def plausible(ext, data, lost):
    """Khi không có manifest: phần giải mã được có đúng cấu trúc của loại file không.

    Trả về True / False, hoặc None khi quá ít dữ liệu để kết luận: vài byte rác do khóa sai
    sinh ra vẫn có entropy thấp và dễ là UTF-8 hợp lệ, nên không được coi là "đúng".
    """
    if not data:
        return None  # file gốc ≤ 16 byte ở overwrite16: không còn gì để kiểm tra
    if lost == 0 and ext in MAGIC:
        return data.startswith(MAGIC[ext])
    if ext in ZIP_EXT:
        return b"PK\x05\x06" in data[-65557:]  # end of central directory
    if ext == "pdf":
        return b"%%EOF" in data[-2048:]
    if ext == "jpg":
        return b"\xff\xd9" in data[-32:]
    if ext in TEXT_EXT:
        if len(data) < 16:
            return None
        for cut in range(4):  # mất 16 byte đầu có thể cắt ngang một ký tự UTF-8
            try:
                data[cut:].decode("utf-8")
                return True
            except UnicodeDecodeError:
                pass
        return False
    if len(data) < 256:  # entropy của vài chục byte luôn thấp, không phân biệt được với rác
        return None
    return entropy(data[:1 << 16]) < 7.5


def tf(b):
    return "true" if b else "false"


# ---------------------------------------------------------------- giải mã

def decrypt_file(path, keys, profile, mrow=None, patch="auto", name=None, verified=()):
    """Thử lần lượt các khóa trên một file. Trả về (dòng report, dữ liệu đã giải mã hoặc None).

    verified: các khóa đã giải mã đúng file khác. File quá nhỏ để tự kiểm chứng (khóa rác lọt
    padding cũng cho ra kết quả "hợp lệ") chỉ nhận khóa trong tập này.
    """
    prof = PROFILES[profile] if isinstance(profile, str) else profile
    name = name or os.path.basename(path)
    orig = name[:-len(SUFFIX)] if name.endswith(SUFFIX) else name
    ext = os.path.splitext(orig)[1].lstrip(".").lower()
    lost = prof["lost_head"]
    row = dict.fromkeys(REPORT_FIELDS, "")
    row.update(file=name, profile=profile if isinstance(profile, str) else "custom",
               header_patch="none", status="no_key")

    with open(path, "rb") as f:
        blob = f.read()
    iv, ct = split(blob, prof)
    if len(iv) != 16 or not ct or len(ct) % 16:
        row.update(status="error", note="ciphertext %d byte không chia hết cho 16, sai profile?" % len(ct))
        return row, None

    fallback, weak_skipped = None, False
    for k in keys:
        if not padding_ok(k["raw"], iv, ct):
            continue
        try:
            data = unpad(AES.new(k["raw"], AES.MODE_CBC, iv).decrypt(ct), 16)
        except ValueError:
            continue
        head, how, note = patch_head(ext, data, lost, patch, mrow)
        out = head + data
        sha_ok = bool(mrow) and hashlib.sha256(out).hexdigest() == mrow["sha256"]
        # Khớp hash trên dữ liệu giải mã thật -> chắc chắn đúng khóa.
        # (data rỗng thì out chỉ là header lấy từ manifest: khớp hash không chứng minh gì.)
        if data and sha_ok:
            return _finish(row, k, out, how, note, mrow, ext, sha=True, strong=True), out
        # Có manifest và kết quả lẽ ra phải khớp tuyệt đối (không mất byte, hoặc vá từ manifest)
        # mà hash lệch -> khóa sai.
        if data and mrow and (lost == 0 or how == "manifest"):
            continue
        verdict = plausible(ext, data, lost)
        if verdict is False:
            continue
        if verdict is None:  # file quá nhỏ để tự kiểm chứng
            if k["key_hex"] not in verified:
                weak_skipped = True
                continue
            note = "; ".join(x for x in (note, "file quá nhỏ để tự kiểm chứng: khóa được xác nhận"
                                               " qua các file khác") if x)
            return _finish(row, k, out, how, note, mrow, ext,
                           sha=sha_ok if mrow else None, strong=False), out
        if fallback is None:
            fallback = (k, out, how, note)
    if fallback:
        k, out, how, note = fallback
        sha = None if not mrow else False
        if sha is False:
            note = "; ".join(x for x in (note, "hash không khớp manifest") if x)
        return _finish(row, k, out, how, note, mrow, ext, sha=sha, strong=True), out
    row["note"] = "không khóa nào giải mã được (đã thử %d khóa)" % len(keys)
    if weak_skipped:
        row["note"] = ("file quá nhỏ để tự kiểm chứng: chỉ nhận khóa đã giải mã đúng file khác,"
                       " chưa có khóa nào như vậy")
    return row, None


def _finish(row, k, out, how, note, mrow, ext, sha, strong):
    want = bytes.fromhex(mrow["magic_hex"]) if mrow and mrow.get("magic_hex") else MAGIC.get(ext)
    row.update(key_tool=k.get("tool") or "", key_source=k.get("source") or "", key_hex=k["key_hex"],
               header_patch=how, magic_ok=tf(out.startswith(want)) if want else "",
               sha256_ok="" if sha is None else tf(sha), status="ok", note=note)
    row["_strong"] = strong  # khóa được kiểm chứng bằng dữ liệu thật của file này; run() bỏ trường này
    return row


def run(src, keys, profile, manifest, patch="auto", out_dir=None):
    """Giải mã mọi file .locked trong src. Ghi file ra out_dir (nếu có). Trả về các dòng report."""
    files = []
    for dirpath, _, names in os.walk(src):
        for n in names:
            if n.endswith(SUFFIX):
                p = os.path.join(dirpath, n)
                files.append((os.path.relpath(p, src).replace(os.sep, "/"), p))
    files.sort(key=lambda f: -os.path.getsize(f[1]))  # file lớn kiểm chứng khóa chắc chắn hơn: làm trước

    hits = Counter()
    rows = []
    for rel, path in files:
        ordered = sorted(keys, key=lambda k: -hits[k["key_hex"]])  # khóa đã đúng ở file khác thử trước
        row, data = decrypt_file(path, ordered, profile, manifest.get(rel[:-len(SUFFIX)]), patch, rel,
                                 verified=set(hits))
        if row.pop("_strong", False):
            hits[row["key_hex"]] += 1
        if data is not None:
            if out_dir:
                dst = os.path.join(out_dir, rel[:-len(SUFFIX)])
                os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
                with open(dst, "wb") as f:
                    f.write(data)
        rows.append(row)
    rows.sort(key=lambda r: r["file"])
    return rows


def write_report(rows, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------- CLI

def main():
    if hasattr(sys.stdout, "reconfigure"):  # console Windows mặc định cp1252, in tiếng Việt sẽ lỗi
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Giải mã file .locked bằng khóa AES ứng viên (Part 3)")
    ap.add_argument("--keys", nargs="+", required=True, help="keys.json và/hoặc ground_truth.json")
    ap.add_argument("--in", dest="src", default="samples/encrypted", help="thư mục file .locked")
    ap.add_argument("--profile", choices=sorted(PROFILES) + ["custom"],
                    help="mặc định: lấy từ trường profile của ground_truth.json")
    ap.add_argument("--manifest", default="manifest.csv", help='viết --manifest= (bỏ trống) để không dùng, giống điều tra thật')
    ap.add_argument("--patch", choices=["auto", "manifest", "template", "none"], default="auto",
                    help="cách vá header khi mất byte đầu (auto: manifest nếu có, không thì template)")
    ap.add_argument("--out", default="decrypted", help="thư mục ghi file đã giải mã")
    ap.add_argument("--report", default="report.csv")
    g = ap.add_argument_group("profile custom")
    g.add_argument("--iv-offset", type=int, default=0, help="vị trí IV, âm = tính từ cuối file")
    g.add_argument("--ct-start", type=int, default=16, help="ciphertext bắt đầu từ byte này")
    g.add_argument("--ct-end", type=int, default=None, help="ciphertext kết thúc trước byte này (âm = từ cuối)")
    g.add_argument("--lost-head", type=int, default=0, help="số byte đầu file gốc bị mất")
    args = ap.parse_args()

    try:
        keys, file_profile = load_keys(args.keys)
    except (OSError, ValueError) as e:
        sys.exit("Lỗi đọc khóa: %s" % e)
    if not keys:
        sys.exit("Không có khóa hợp lệ nào trong %s" % ", ".join(args.keys))

    profile = args.profile or file_profile
    if not profile:
        sys.exit("Chưa biết profile: thêm --profile (keys.json không có trường profile)")
    if args.profile and file_profile and args.profile != file_profile:
        print("Cảnh báo: --profile %s khác profile trong file khóa (%s), dùng %s"
              % (args.profile, file_profile, args.profile))
    if profile == "custom":
        profile = {"iv_offset": args.iv_offset, "ct_start": args.ct_start,
                   "ct_end": args.ct_end, "lost_head": args.lost_head}
    elif profile not in PROFILES:
        sys.exit("Profile %r chưa được hỗ trợ (xem DATA_CONTRACT.md mục 6)" % profile)

    if not os.path.isdir(args.src):
        sys.exit("Không thấy thư mục: %s" % args.src)
    manifest = load_manifest(args.manifest)
    rows = run(args.src, keys, profile, manifest, args.patch, args.out)
    if not rows:
        sys.exit("Không có file %s nào trong %s" % (SUFFIX, args.src))
    write_report(rows, args.report)

    print("Profile: %s | %d khóa ứng viên | %d file"
          % (profile if isinstance(profile, str) else "custom", len(keys), len(rows)))
    for r in rows:
        if r["status"] == "ok":
            sha = {"true": "sha256 KHỚP", "false": "sha256 LỆCH", "": "chưa so hash"}[r["sha256_ok"]]
            print("  OK     %-32s %s | khóa %s@%s | vá: %s"
                  % (r["file"], sha, r["key_tool"], r["key_source"] or "-", r["header_patch"]))
        else:
            print("  %-6s %-32s %s" % (r["status"].upper(), r["file"], r["note"]))
        if r["status"] == "ok" and r["note"]:
            print("         %s" % r["note"])
    ok = sum(r["status"] == "ok" for r in rows)
    sha_ok = sum(r["sha256_ok"] == "true" for r in rows)
    print("Giải mã %d/%d file, %d file khớp SHA-256. Report: %s, file: %s/"
          % (ok, len(rows), sha_ok, args.report, args.out))
    if ok < len(rows):
        sys.exit(1)


if __name__ == "__main__":
    main()
