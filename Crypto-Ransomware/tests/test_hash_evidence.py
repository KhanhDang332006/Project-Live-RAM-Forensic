"""Test hash_evidence.py, gồm trường hợp log ghi trên hệ điều hành này rồi verify trên hệ khác.

    python -m unittest discover -s tests -v
"""
import csv
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "tools", "hash_evidence.py")
FIELDS = ["evidence_id", "timestamp", "action", "collector", "path", "size", "sha256", "description"]


def run(cwd, *args):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, SCRIPT] + list(args), cwd=cwd, env=env,
                          capture_output=True, text=True, encoding="utf-8")


class HashEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nt334_he_")
        for name, data in (("mem.vmem", b"\x00" * 50000), ("mem.vmsn", b"snapshot")):
            with open(os.path.join(self.tmp, name), "wb") as f:
                f.write(data)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def last_rows(self, n):
        with open(os.path.join(self.tmp, "custody_log.csv"), newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))[-n:]

    def test_acquire_verify_roi_phat_hien_sua_file(self):
        r = run(self.tmp, "acquire", "mem.vmem", "mem.vmsn", "--collector", "Khánh Đăng")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(run(self.tmp, "verify", "--id", "E001", "--collector", "X").returncode, 0)
        with open(os.path.join(self.tmp, "mem.vmsn"), "ab") as f:
            f.write(b"x")
        r = run(self.tmp, "verify", "--id", "E001", "--collector", "X")
        self.assertEqual(r.returncode, 1)
        self.assertEqual([row["description"][:8] for row in self.last_rows(2)], ["match", "MISMATCH"])

    def test_khong_cho_thu_trung_ma(self):
        run(self.tmp, "acquire", "mem.vmem", "--collector", "A")
        self.assertEqual(run(self.tmp, "acquire", "mem.vmem", "--id", "E001", "--collector", "A").returncode, 1)

    def test_verify_log_ghi_tren_he_dieu_hanh_khac(self):
        """Đường dẫn trong log là của máy khác (Windows hoặc Linux): --base phải tìm ra file theo tên."""
        rows = []
        for name, foreign in (("mem.vmem", r"C:\Users\dang\evidence\mem.vmem"),
                              ("mem.vmsn", "/mnt/evidence/run1/mem.vmsn")):
            with open(os.path.join(self.tmp, name), "rb") as f:
                data = f.read()
            rows.append({"evidence_id": "E001", "timestamp": "2026-10-04T15:30:00+07:00",
                         "action": "acquired", "collector": "Khánh Đăng", "path": foreign,
                         "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "description": ""})
        with open(os.path.join(self.tmp, "custody_log.csv"), "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(rows)

        self.assertEqual(run(self.tmp, "verify", "--id", "E001", "--collector", "X").returncode, 1)  # chưa có --base
        r = run(self.tmp, "verify", "--id", "E001", "--collector", "X", "--base", ".")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([row["description"] for row in self.last_rows(2)], ["match", "match"])


if __name__ == "__main__":
    unittest.main()
