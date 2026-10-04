#!/usr/bin/env python3
"""keyscan.py - do khoa AES trong anh bo nho (memory dump).

Cong cu PHAP CHUNG / PHONG THU: muc dich la LAY LAI khoa AES ma ransomware giu
trong RAM, de giai ma lai file cho nan nhan (Part 1 cua bai bao Davies 2020).
Nguyen ly giong findaes/aeskeyfind:

  1. Loc tho theo so byte phan biet: khoa la du lieu ngau nhien -> ~15-16
     byte phan biet trong 16 byte; vung zero/lap bi bo qua.
  2. Xac nhan bang key schedule: voi moi ung vien 16/24/32 byte, tinh key
     schedule dung chuan Rijndael roi so voi cac byte NGAY SAU trong dump.
     Khop 176/208/240 byte -> gan nhu chac chan la khoa AES that
     (ngau nhien trung la cuc ky kho).

Cach dung:
  python keyscan.py dump.vmem
  python keyscan.py dump.vmem --bits 128 256 --out keys.json
  python keyscan.py dump.vmem --baseline clean.vmem --source dump.vmem --pid 4321
  python keyscan.py dump.vmem --no-entropy        # tat loc tho (cham hon, de do thoi gian)
"""
import argparse, json, time

from aes_schedule import expand_key, SCHED_LEN


def byteswap_words(buf: bytes) -> bytes:
    """Dao thu tu byte trong tung word 4 byte (mot so thu vien luu khoa kieu nay)."""
    out = bytearray(len(buf))
    for i in range(0, len(buf) - 3, 4):
        out[i:i + 4] = buf[i:i + 4][::-1]
    return bytes(out)


def scan(data: bytes, bits_list, use_entropy=True, min_unique=11,
         swap=False, step=1):
    """Tra ve list khoa tim duoc: (offset, bits, key_hex).

    Loc tho = so byte phan biet trong 16 byte ung vien. Khoa ngau nhien gan
    nhu luon co ~15-16 byte phan biet, nen nguong 11 KHONG BAO GIO sot khoa
    that, trong khi vung zero (1 byte phan biet) va du lieu lap bi bo qua.
    An toan hon do entropy theo block (block co the loang neu khoa nam giua
    vung zero)."""
    found = []
    seen = set()
    n = len(data)
    for bits in sorted(bits_list):
        klen = bits // 8
        slen = SCHED_LEN[bits]
        off = 0
        while off + slen <= n:
            # loc tho: bo qua vung it byte phan biet (zero/lap). byteswap trong
            # tung word khong doi tap byte nen check tren du lieu goc van dung.
            if use_entropy and len(set(data[off:off + klen])) < min_unique:
                off += step
                continue
            region = data[off:off + slen]
            if swap:
                region = byteswap_words(region)
            cand = region[:klen]
            try:
                if expand_key(cand) == region:
                    kh = cand.hex()
                    if kh not in seen:
                        seen.add(kh)
                        found.append((off, bits, kh))
            except ValueError:
                pass
            off += step
    return found


def load_baseline_keys(path, bits_list, **kw):
    data = open(path, "rb").read()
    return {kh for _, _, kh in scan(data, bits_list, **kw)}


def main():
    ap = argparse.ArgumentParser(description="Do khoa AES trong memory dump (phap chung).")
    ap.add_argument("dump")
    ap.add_argument("--bits", type=int, nargs="+", choices=[128, 192, 256],
                    default=[128, 192, 256])
    ap.add_argument("--out", help="ghi ket qua ra keys.json")
    ap.add_argument("--baseline", help="dump sach -> loai khoa da co san")
    ap.add_argument("--source", help="ten nguon ghi vao keys.json (mac dinh = ten file dump)")
    ap.add_argument("--dump-time", help="thoi diem chup RAM, ISO +07:00 (tu log script Hai)")
    ap.add_argument("--pid", type=int, help="PID neu dang quet vung nho 1 tien trinh")
    ap.add_argument("--scope", choices=["file", "process"], help="pham vi quet")
    ap.add_argument("--no-entropy", action="store_true", help="tat loc tho (quet moi offset, cham)")
    ap.add_argument("--min-unique", type=int, default=11,
                    help="so byte phan biet toi thieu de xet mot offset (mac dinh 11)")
    ap.add_argument("--byteswap", action="store_true", help="che do dao byte trong word")
    a = ap.parse_args()

    kw = dict(use_entropy=not a.no_entropy, min_unique=a.min_unique, swap=a.byteswap)

    data = open(a.dump, "rb").read()
    t0 = time.time()
    found = scan(data, a.bits, **kw)
    dt = time.time() - t0

    baseline = set()
    if a.baseline:
        baseline = load_baseline_keys(a.baseline, a.bits, **kw)
        found = [f for f in found if f[2] not in baseline]

    scope = a.scope or ("process" if a.pid is not None else "file")
    source = a.source or a.dump.replace("\\", "/").split("/")[-1]

    keys = [{
        "source": source,
        "dump_time": a.dump_time,
        "offset": hex(off),
        "bits": bits,
        "key_hex": kh,
        "tool": "keyscan",
        "pid": a.pid,
        "scope": scope,
    } for off, bits, kh in found]

    print(f"[=] quet {len(data):,} byte trong {dt:.2f}s "
          f"(entropy={'off' if a.no_entropy else a.entropy}, "
          f"byteswap={'on' if a.byteswap else 'off'})")
    if a.baseline:
        print(f"[=] loai {len(baseline)} khoa co trong baseline")
    for k in keys:
        print(f"    + {k['bits']:3}-bit @ {k['offset']:>10}  {k['key_hex']}")
    print(f"[=] tong: {len(keys)} khoa moi")

    if a.out:
        json.dump({"schema": 1, "keys": keys}, open(a.out, "w"), indent=2)
        print(f"[=] ghi -> {a.out}")


if __name__ == "__main__":
    main()
