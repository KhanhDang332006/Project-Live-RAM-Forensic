"""Test cả chuỗi: make_manifest -> mock_encrypt -> decrypt, chạy đúng như dòng lệnh thật.

    python -m unittest discover -s tests -v
"""
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OLE = bytes.fromhex("d0cf11e0a1b11ae1")


def make_fixtures(d):
    """File mồi giả nhưng đúng cấu trúc: docx/xlsx là ZIP thật, doc/xls có header OLE chuẩn."""
    os.makedirs(d)

    def put(name, data):
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)

    for name, body in [("bao_cao.docx", "<w:p>Xin chào, đây là báo cáo.</w:p>"),
                       ("bang_tinh.xlsx", "<row><c>12345</c></row>")]:
        with zipfile.ZipFile(os.path.join(d, name), "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", "<Types>" + "<Default/>" * 40 + "</Types>")
            z.writestr("word/document.xml", body * 300)
    put("cu.doc", OLE + b"\0" * 16 + b"Microsoft Word 97 body\0\0\0\0" * 400)
    put("so_lieu.xls", OLE + b"\0" * 16 + b"Workbook BIFF8 rows\0\0\0\0\0" * 400)
    # pdf 1.4 và jpg JFIF 1.02: khác header đoán của decrypt.py, để test trường hợp "mở được nhưng hash lệch"
    put("hop_dong.pdf", b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        + b"1 0 obj\n<< /Type /Catalog >>\nendobj\n" * 50 + b"%%EOF\n")
    put("anh.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x02\x00\x00\x48"
        + os.urandom(4000) + b"\xff\xd9")
    put("ghi_chu.txt", "Tài liệu nội bộ, không phát tán.\n".encode("utf-8") * 60)
    put("ngan.txt", b"hello")


def run(cwd, script, *args):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, os.path.join(REPO, script)] + list(args),
                          cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8")


def read_report(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return {r["file"]: r for r in csv.DictReader(f)}


class DecryptPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="nt334_")
        cls.plain = os.path.join(cls.tmp, "samples", "plain")
        make_fixtures(cls.plain)
        r = run(cls.tmp, "tools/make_manifest.py")
        assert r.returncode == 0, r.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def original(self, name):
        with open(os.path.join(self.plain, name), "rb") as f:
            return f.read()

    def output(self, out_dir, name):
        with open(os.path.join(self.tmp, out_dir, name), "rb") as f:
            return f.read()

    def encrypt(self, tag, profile, bits=128):
        r = run(self.tmp, "tests/mock_encrypt.py", "--profile", profile, "--bits", str(bits),
                "--out", "samples/enc_" + tag, "--gt", "gt_%s.json" % tag)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.tmp, "gt_%s.json" % tag), encoding="utf-8") as f:
            return json.load(f)["keys"][0]["key_hex"]

    def decrypt(self, tag, keys, *extra):
        return run(self.tmp, "tools/decrypt.py", "--in", "samples/enc_" + tag, "--keys", keys,
                   "--out", "dec_" + tag, "--report", "rep_%s.csv" % tag, *extra)

    def write_keys(self, name, true_key=None, decoys=300):
        """keys.json giống đầu ra keyscan: nhiều khóa rác (128 và 256 bit), khóa thật nằm gần cuối."""
        keys = [{"source": "mem_%04ds.vmem" % (i * 30), "dump_time": None, "scope": "file", "pid": None,
                 "offset": hex(i * 4096), "bits": b, "key_hex": os.urandom(b // 8).hex(), "tool": "aeskeyfind"}
                for i, b in enumerate([128, 256] * (decoys // 2))]
        if true_key:
            keys.insert(len(keys) - 3, dict(keys[0], source="mem_0060s.vmem", bits=len(true_key) * 4,
                                            key_hex=true_key, scope="process", pid=4321))
        with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as f:
            json.dump({"schema": 1, "keys": keys}, f)

    # ------------------------------------------------------------------ tests

    def test_prepend_ground_truth_hash_khop_100(self):
        self.encrypt("p", "prepend")
        r = self.decrypt("p", "gt_p.json")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for name, row in read_report(os.path.join(self.tmp, "rep_p.csv")).items():
            self.assertEqual((row["status"], row["sha256_ok"], row["magic_ok"]), ("ok", "true", "true"), name)
            self.assertEqual(self.output("dec_p", name[:-7]), self.original(name[:-7]))

    def test_overwrite16_va_header_tu_manifest_hash_khop_100(self):
        self.encrypt("o", "overwrite16")
        r = self.decrypt("o", "gt_o.json")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for name, row in read_report(os.path.join(self.tmp, "rep_o.csv")).items():
            self.assertEqual((row["status"], row["sha256_ok"], row["header_patch"]),
                             ("ok", "true", "manifest"), name)

    def test_overwrite16_khong_manifest_300_khoa_rac(self):
        """Giống điều tra thật: không có bản gốc, khóa thật lẫn trong 300 khóa rác của keyscan."""
        key = self.encrypt("t", "overwrite16")
        self.write_keys("keys_t.json", true_key=key)
        r = self.decrypt("t", "keys_t.json", "--profile", "overwrite16", "--manifest", "", "--patch", "template")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        rep = read_report(os.path.join(self.tmp, "rep_t.csv"))
        for name, row in rep.items():
            self.assertEqual((row["status"], row["key_hex"]), ("ok", key), name)
            self.assertEqual(row["key_source"], "mem_0060s.vmem")
        # ZIP và OLE: 16 byte đầu dựng lại chính xác -> trùng bản gốc dù không có manifest
        for name in ("bao_cao.docx", "bang_tinh.xlsx", "cu.doc", "so_lieu.xls"):
            self.assertEqual(self.output("dec_t", name), self.original(name), name)
        # pdf/jpg: header đoán -> đúng magic, mở được, nhưng không trùng byte với bản gốc
        for name, magic in (("hop_dong.pdf", b"%PDF"), ("anh.jpg", b"\xff\xd8\xff")):
            out = self.output("dec_t", name)
            self.assertTrue(out.startswith(magic), name)
            self.assertEqual(out[16:], self.original(name)[16:], name)
        # txt: không có header mẫu -> chỉ mất 16 byte đầu
        self.assertEqual(self.output("dec_t", "ghi_chu.txt"), self.original("ghi_chu.txt")[16:])

    def test_chi_co_khoa_rac_thi_khong_nhan_bua(self):
        self.encrypt("d", "overwrite16")
        self.write_keys("keys_d.json")
        r = self.decrypt("d", "keys_d.json", "--profile", "overwrite16")
        self.assertEqual(r.returncode, 1)
        for name, row in read_report(os.path.join(self.tmp, "rep_d.csv")).items():
            self.assertEqual(row["status"], "no_key", name)

    def test_aes256(self):
        self.encrypt("k", "prepend", bits=256)
        r = self.decrypt("k", "gt_k.json")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for name, row in read_report(os.path.join(self.tmp, "rep_k.csv")).items():
            self.assertEqual(row["sha256_ok"], "true", name)

    def test_header_doan_dai_dung_16_byte(self):
        sys.path.insert(0, os.path.join(REPO, "tools"))
        import decrypt
        for ext, head in decrypt.GUESS_HEAD.items():
            self.assertEqual(len(head), 16, ext)  # lệch độ dài thì offset (xref của PDF) sai hết

    def test_sai_profile_bao_loi_ro_rang(self):
        self.encrypt("e", "prepend")
        r = self.decrypt("e", "gt_e.json", "--profile", "custom", "--ct-start", "20")
        self.assertEqual(r.returncode, 1)
        for row in read_report(os.path.join(self.tmp, "rep_e.csv")).values():
            self.assertEqual(row["status"], "error")
            self.assertIn("sai profile", row["note"])


if __name__ == "__main__":
    unittest.main()
