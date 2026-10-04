#!/usr/bin/env python3
"""Ghi chain of custody cho bằng chứng (xem DATA_CONTRACT.md, mục 9).

custody_log.csv chỉ được ghi thêm dòng, không sửa dòng cũ.

Thu một bằng chứng (một dump VMware gồm .vmem + .vmsn -> chung một evidence_id):
    python tools/hash_evidence.py acquire mem_0030s.vmem mem_0030s.vmsn \
        --collector "Khánh Đăng" --desc "Dump RAM giây 30, lần chạy prepend #1"

Kiểm tra lại trước khi phân tích / khi chuyển giao (exit code 1 nếu hash lệch):
    python tools/hash_evidence.py verify --id E001 --collector "Minh Hoàng"
    python tools/hash_evidence.py verify --id E001 --collector "Khánh Đăng" \
        --action transferred --desc "Giao cho Minh Hoàng qua ổ chung"

Kiểm tra trên máy khác (bằng chứng nằm ở thư mục khác lúc thu):
    python tools/hash_evidence.py verify --id E001 --collector "Minh Hoàng" --base Z:/evidence

Xem tóm tắt:
    python tools/hash_evidence.py list
"""
import argparse
import csv
import hashlib
import os
import sys
import time
from datetime import datetime

FIELDS = ["evidence_id", "timestamp", "action", "collector", "path", "size", "sha256", "description"]
CHUNK = 1024 * 1024


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path):
    h = hashlib.sha256()
    size = os.path.getsize(path)
    done, t0, next_report = 0, time.time(), 1 << 30
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
            done += len(block)
            if done >= next_report:  # dump RAM vài GB: báo tiến độ mỗi 1 GB
                print("    ... %.1f/%.1f GB" % (done / 2**30, size / 2**30), flush=True)
                next_report += 1 << 30
    print("    %s  (%.1f MB, %.1fs)" % (os.path.basename(path), size / 2**20, time.time() - t0))
    return h.hexdigest()


def read_log(log):
    if not os.path.exists(log):
        return []
    with open(log, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def append_rows(log, rows):
    new = not os.path.exists(log)
    with open(log, "a", newline="", encoding="utf-8-sig" if new else "utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerows(rows)


def next_id(rows):
    nums = [int(r["evidence_id"][1:]) for r in rows
            if r["evidence_id"][:1] == "E" and r["evidence_id"][1:].isdigit()]
    return "E%03d" % (max(nums, default=0) + 1)


def expand(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for dirpath, _, names in os.walk(p):
                files += [os.path.join(dirpath, n) for n in sorted(names)]
        elif os.path.isfile(p):
            files.append(p)
        else:
            sys.exit("Không thấy file: %s" % p)
    return [os.path.abspath(f) for f in files]


def cmd_acquire(args):
    rows = read_log(args.log)
    eid = args.id or next_id(rows)
    if any(r["evidence_id"] == eid and r["action"] == "acquired" for r in rows):
        sys.exit("%s đã được thu trước đó. Dùng verify, hoặc bỏ --id để lấy mã mới." % eid)

    files = expand(args.paths)
    print("Thu bằng chứng %s (%d file):" % (eid, len(files)))
    new = [{
        "evidence_id": eid, "timestamp": now(), "action": "acquired",
        "collector": args.collector, "path": p, "size": os.path.getsize(p),
        "sha256": sha256_file(p), "description": args.desc,
    } for p in files]
    append_rows(args.log, new)
    print("Đã ghi %d dòng vào %s" % (len(new), args.log))


def cmd_verify(args):
    rows = read_log(args.log)
    baseline = {}
    for r in rows:  # hash lúc thu là chuẩn để so
        if r["evidence_id"] == args.id and r["action"] == "acquired":
            baseline.setdefault(r["path"], r)
    if not baseline:
        sys.exit("Không có bằng chứng %s trong %s" % (args.id, args.log))

    print("Kiểm tra %s (%d file):" % (args.id, len(baseline)))
    new, bad = [], 0
    for path, base in baseline.items():
        if not os.path.isfile(path) and args.base:  # máy khác: tìm theo tên trong --base
            path = os.path.abspath(os.path.join(args.base, os.path.basename(path)))
        if not os.path.isfile(path):
            digest, size, result = "", "", "MISSING"
        else:
            digest, size = sha256_file(path), os.path.getsize(path)
            result = "match" if digest == base["sha256"] else "MISMATCH (lúc thu: %s)" % base["sha256"]
        bad += result != "match"
        desc = "%s; %s" % (result, args.desc) if args.desc else result
        new.append({
            "evidence_id": args.id, "timestamp": now(), "action": args.action,
            "collector": args.collector, "path": path, "size": size,
            "sha256": digest, "description": desc,
        })
        print("    -> %s" % result)
    append_rows(args.log, new)
    if bad:
        sys.exit("CẢNH BÁO: %d file không khớp hash lúc thu" % bad)
    print("Toàn vẹn: mọi file khớp hash lúc thu.")


def cmd_list(args):
    rows = read_log(args.log)
    if not rows:
        print("Log trống.")
        return
    for eid in sorted({r["evidence_id"] for r in rows}):
        rs = [r for r in rows if r["evidence_id"] == eid]
        acq = [r for r in rs if r["action"] == "acquired"]
        last = rs[-1]
        print("%s  %d file  thu bởi %s lúc %s  | gần nhất: %s (%s) %s"
              % (eid, len(acq), acq[0]["collector"] if acq else "?",
                 acq[0]["timestamp"] if acq else "?",
                 last["action"], last["collector"], last["timestamp"]))
        if acq and acq[0]["description"]:
            print("      %s" % acq[0]["description"])


def main():
    if hasattr(sys.stdout, "reconfigure"):  # console Windows mặc định cp1252, in tiếng Việt sẽ lỗi
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Chain of custody: hash và ghi log bằng chứng")
    ap.add_argument("--log", default="custody_log.csv", help="file log (mặc định: custody_log.csv)")
    sub = ap.add_subparsers(dest="cmd")
    sub.required = True

    a = sub.add_parser("acquire", help="thu bằng chứng mới")
    a.add_argument("paths", nargs="+", help="file hoặc thư mục; nhiều file = một bằng chứng")
    a.add_argument("--collector", required=True, help="người thu")
    a.add_argument("--desc", default="", help="mô tả")
    a.add_argument("--id", help="mã bằng chứng (mặc định: tự tăng E001, E002…)")
    a.set_defaults(func=cmd_acquire)

    v = sub.add_parser("verify", help="tính lại hash và so với lúc thu")
    v.add_argument("--id", required=True)
    v.add_argument("--collector", required=True, help="người kiểm tra / người giao")
    v.add_argument("--action", choices=["verified", "transferred"], default="verified")
    v.add_argument("--desc", default="")
    v.add_argument("--base", help="thư mục chứa bằng chứng nếu đường dẫn lúc thu không còn đúng (máy khác)")
    v.set_defaults(func=cmd_verify)

    l = sub.add_parser("list", help="tóm tắt các bằng chứng trong log")
    l.set_defaults(func=cmd_list)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
