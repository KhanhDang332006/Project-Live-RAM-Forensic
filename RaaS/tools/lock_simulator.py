#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

# Chỉ thao tác trong thư mục lab
BASE_DIR = Path.home() / "lab"
DATA_DIR = BASE_DIR / "data"
LOCKED_DIR = BASE_DIR / "locked-demo"
EVIDENCE_DIR = BASE_DIR / "evidence"

LOG_FILE = EVIDENCE_DIR / "encryption_simulation.log"

# Chỉ xử lý các định dạng dữ liệu giả lập
ALLOWED_EXTENSIONS = {".csv", ".txt"}

# Giới hạn kích thước mỗi file
MAX_FILE_SIZE = 5 * 1024 * 1024


def calculate_sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():

    if not DATA_DIR.is_dir():
        print(f"[ERROR] Data directory not found: {DATA_DIR}")
        return

    LOCKED_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    files = sorted(
        path for path in DATA_DIR.rglob("*")
        if path.is_file()
        and path.suffix.lower() in ALLOWED_EXTENSIONS
    )

    if not files:
        print("[ERROR] No eligible files found.")
        return

    print("DOUBLE EXTORTION LAB")
    print("Encryption Simulation - Non-destructive mode")
    print("-" * 55)

    successful = 0

    for source in files:

        relative_path = source.relative_to(DATA_DIR)

        # Tạo đường dẫn tương ứng trong locked-demo
        destination = (
            LOCKED_DIR /
            relative_path.parent /
            (relative_path.name + ".locked-demo")
        )

        if destination.exists():
            print(f"[SKIPPED] Already exists: {relative_path}")
            continue

        data = source.read_bytes()

        if len(data) > MAX_FILE_SIZE:
            print(f"[SKIPPED] File too large: {relative_path}")
            continue

        original_hash = calculate_sha256(data)

        # Chỉ tạo nội dung mô phỏng, không mã hóa file gốc
        marker = (
            "DOUBLE EXTORTION LAB - SIMULATION ONLY\n"
            "--------------------------------------\n"
            "Thi file represents a simulated ransomware impact.\n"
            "No real encryption was performed.\n"
            "The original file has not been modified.\n\n"
            f"Original file: {relative_path}\n"
            f"Original SHA256: {original_hash}\n"
        )

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(marker, encoding="utf-8")

        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "original_file": str(relative_path),
            "simulated_locked_file": str(
                destination.relative_to(LOCKED_DIR)
            ),
            "original_size_bytes": len(data),
            "original_sha256": original_hash,
            "simulation": True
        }

        with LOG_FILE.open("a", encoding="utf-8") as log:
            log.write(json.dumps(record, ensure_ascii=False) + "\n")

        print(f"[LOCKED - SIMULATED] {relative_path}")
        print(f"                     -> {destination.name}")

        successful += 1

    print("-" * 55)
    print(f"Simulation completed: {successful}/{len(files)} files")
    print(f"Output directory: {LOCKED_DIR}")
    print(f"Evidence log: {LOG_FILE}")
    print("Original files and backups were not modified.")


if __name__ == "__main__":
    main()
