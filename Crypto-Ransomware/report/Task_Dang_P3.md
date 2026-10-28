# Code mảng Đĩa & giải mã file – giải thích từng file

Thư mục `tools/` và `tests/` chứa phần công cụ của **Mảng 2 (Đĩa & giải mã file)** trong đồ án:
dùng khóa AES dò được trong RAM để giải mã lại file bị ransomware mã hóa (Part 3 của bài báo
Davies 2020), và giữ chain of custody cho mọi bằng chứng (việc PHỤ của mảng 1).

## Ý tưởng chung (đọc cái này trước)

Khi `keyscan` dò ra khóa AES trong RAM, việc còn lại là **chứng minh khóa đó mở được file**.
Có ba vấn đề phải giải quyết:

1. **IV nằm ở đâu?** Mã hóa CBC cần thêm IV 16 byte. Ransomware không giấu IV mà ghi luôn vào file
   bị mã hóa (đầu file với NotPetya/Bad Rabbit, cuối file với Phobos). IV công khai vẫn an toàn,
   vì không có khóa thì IV vô dụng. Vị trí IV được quy định trong **profile** (DATA_CONTRACT.md mục 6).
2. **Khóa nào là khóa đúng?** `keyscan` có thể trả về nhiều khóa ứng viên. Phải có cách loại khóa
   sai nhanh và chắc chắn.
3. **Làm sao chứng minh file giải mã ra là đúng?** Bài báo kiểm tra bằng tay (mở file xem có đọc
   được không). Nhóm làm tự động: lưu SHA-256 của file mồi **trước khi** mã hóa, giải mã xong so lại.
   Khớp SHA-256 = trùng từng byte với bản gốc.

Luồng chạy của cả pipeline:

```
samples/plain ─► make_manifest.py ─► manifest.csv (SHA-256 gốc) ──────────┐
      │                                                                   ▼
      └─► keyholder.py ─► *.locked ─────────────────────────────────► decrypt.py ─► file gốc + report.csv
                                                                          ▲
(dump RAM) ─► keyscan.py ─► keys.json ────────────────────────────────────┘

mọi bằng chứng (dump, ảnh đĩa, pcap) ─► hash_evidence.py ─► custody_log.csv
```

---

## `tools/make_manifest.py` – chụp lại "đáp án" của file mồi

**Làm gì:** quét `samples/plain/`, với mỗi file ghi tên, kích thước, **SHA-256**, 8 byte đầu (magic
bytes) và 16 byte đầu (`header16`) vào `manifest.csv`. Chạy **trước** khi mã hóa.

**Vì sao cần:** đây là "control files with known content" của bài báo (mục 3.2.4). Có manifest thì
`decrypt.py` chứng minh được kết quả bằng hash thay vì nhìn bằng mắt. Cột `header16` dùng để vá lại
16 byte đầu bị mất ở profile `overwrite16`.

**Chạy:**
```bash
python tools/make_manifest.py                          # samples/plain -> manifest.csv
python tools/make_manifest.py --src <thư mục> --out manifest.csv
```

**Kiểm tra tự động:** cảnh báo nếu thiếu loại file nào trong 7 loại (pdf, doc, docx, xls, xlsx, txt,
jpg); báo file ngắn hơn 16 byte (ở `overwrite16` sẽ mất toàn bộ nội dung); từ chối chạy nếu trong
thư mục lẫn file `.locked` (tức là đang chạy nhầm sau khi mã hóa); bỏ qua file ẩn như `.gitkeep`.

---

## `tools/decrypt.py` – giải mã file bị mã hóa (TOOL CHÍNH)

**Làm gì:** đọc các file `.locked`, thử lần lượt các khóa trong `keys.json` / `ground_truth.json`,
ghi file gốc ra `decrypted/` và kết quả từng file ra `report.csv`.

**Profile hỗ trợ** (DATA_CONTRACT.md mục 6):
- `prepend` – file = `IV + CBC(P)`. Không mất byte nào.
- `overwrite16` – file = `IV + CBC(P[16:])`. Mất 16 byte đầu, giống NotPetya, phải vá header.
- `custom` – tự nhập vị trí IV, đoạn ciphertext và số byte mất, dùng khi gặp layout lạ.

**Cách chọn khóa đúng** trong hàng trăm khóa ứng viên:
1. **Lọc nhanh bằng padding PKCS7:** chỉ giải mã khối cuối của file. Khóa sai cho ra padding hợp lệ
   với xác suất khoảng 1/256, nên phần lớn khóa rác bị loại ngay mà không phải giải mã cả file.
2. **Xác nhận:** có manifest thì so SHA-256. Không có manifest thì kiểm tra cấu trúc theo loại file:
   ZIP/docx/xlsx có *end of central directory*, PDF có `%%EOF`, JPG kết thúc bằng `FFD9`, TXT/CSV là
   UTF-8 hợp lệ. *(Không dùng entropy cho docx/xlsx/jpg: các định dạng này vốn đã nén, entropy cao
   ngay cả khi giải mã đúng.)*
3. **Ưu tiên khóa đã đúng ở file khác:** cả lô dùng chung một khóa, nên khóa đã mở được một file thì
   được thử trước cho các file sau. File lớn được xử lý trước vì kiểm chứng chắc chắn hơn.

**File quá nhỏ** (ciphertext chỉ 1 khối, hoặc file gốc ≤ 16 byte ở `overwrite16`) không tự kiểm
chứng được: khóa rác lọt padding cũng cho ra vài byte "hợp lệ". Những file này **chỉ nhận khóa đã
giải mã đúng file khác** trong lô. Không có quy tắc này thì khóa rác bị nhận nhầm.

**Vá 16 byte đầu bị mất** (`overwrite16`, `--patch template`, không cần bản gốc):

| Loại file | Cách vá | Kết quả |
|---|---|---|
| docx, xlsx, zip | Chép lại các trường của *local header* từ *central directory* ở cuối file | Trùng bản gốc từng byte |
| doc, xls | Magic OLE + CLSID (theo đặc tả MS-CFB, CLSID luôn bằng 0) | Trùng bản gốc từng byte |
| pdf, jpg | Header mẫu dài đúng 16 byte (giữ nguyên offset, bảng xref của PDF không bị lệch) | Mở được, hash có thể lệch |
| txt, csv | Không vá được | Mất 16 byte đầu |

Đây là điểm vượt hơn bài báo: tác giả phải chèn header bằng tay cho từng loại file (mục 4.3.3, 5.1.3).
Đã thử trên một file docx thật do Word tạo: khôi phục trùng từng byte mà không cần bản gốc.

**Chạy:**
```bash
# có ground truth (profile tự lấy từ file): phải khớp SHA-256 100%
python tools/decrypt.py --keys ground_truth.json

# khóa dò được từ RAM
python tools/decrypt.py --keys keys.json --profile overwrite16

# giống điều tra thật: không có bản gốc, vá header theo cấu trúc file
python tools/decrypt.py --keys keys.json --profile overwrite16 --manifest= --patch template

# lô của keyholder nằm ở thư mục riêng
python tools/decrypt.py --in samples/enc_prepend_aes128 --keys samples/enc_prepend_aes128/ground_truth.json
```

**Các tùy chọn quan trọng:**
- `--manifest=` (bỏ trống) – không dùng manifest. Viết có dấu `=` để chạy được trên cả bash lẫn
  PowerShell 5.1 (PowerShell tự bỏ tham số chuỗi rỗng `""`).
- `--patch auto|manifest|template|none` – cách vá header. `auto`: dùng manifest nếu có, không thì template.
- `--in`, `--out`, `--report` – thư mục file `.locked`, thư mục ghi kết quả, file report.

**Output `report.csv`** (DATA_CONTRACT.md mục 8), mỗi file một dòng:

| Cột | Ý nghĩa |
|---|---|
| `key_tool`, `key_source`, `key_hex` | Khóa đã mở được file và nó lấy từ dump nào |
| `header_patch` | `none` / `manifest` / `template` |
| `magic_ok`, `sha256_ok` | Kết quả kiểm tra; `sha256_ok` để trống nếu chạy không có manifest |
| `status` | `ok` / `no_key` / `error` (`error` thường do chọn sai profile) |

Lệnh trả exit code 1 nếu còn file chưa giải mã được, để tool tự động của Hải biết bước này thất bại.

**Dùng như module** (cho tool của Hải gọi):
```python
sys.path.insert(0, "tools"); import decrypt
keys, profile = decrypt.load_keys(["keys.json"])
rows = decrypt.run("samples/encrypted", keys, "overwrite16", decrypt.load_manifest("manifest.csv"))
```

---

## `tools/hash_evidence.py` – chain of custody

**Làm gì:** mỗi khi thu một bằng chứng (dump RAM, ảnh đĩa, pcap) thì tính SHA-256 và ghi một dòng vào
`custody_log.csv`: ai thu, lúc nào, file nào, hash bao nhiêu. Về sau, mỗi lần phân tích hoặc chuyển
giao thì kiểm tra lại để chứng minh bằng chứng **chưa bị thay đổi** kể từ lúc thu.

**Vì sao cần:** đề cương môn yêu cầu mọi bằng chứng phải có SHA-256 và thời điểm thu. Bài báo không có
quy trình này; gần nhất là việc định danh mẫu ransomware bằng SHA-256 ở Bảng 1.

**Chạy:**
```bash
# thu một bằng chứng; một dump VMware gồm .vmem + .vmsn -> chung một mã E001
python tools/hash_evidence.py acquire mem_0030s.vmem mem_0030s.vmsn --collector "Khánh Đăng" --desc "Dump giây 30"

# kiểm tra lại trước khi phân tích / khi giao cho người khác (exit code 1 nếu hash lệch)
python tools/hash_evidence.py verify --id E001 --collector "Minh Hoàng"
python tools/hash_evidence.py verify --id E001 --collector "Khánh Đăng" --action transferred --desc "Giao cho Hoàng"

# trên máy khác, bằng chứng nằm ở thư mục khác lúc thu
python tools/hash_evidence.py verify --id E001 --collector "Trung Hải" --base /mnt/evidence

python tools/hash_evidence.py list
```

**Thiết kế đáng chú ý:**
- Log **chỉ ghi thêm dòng**, không sửa hay xóa dòng cũ, để giữ đúng lịch sử chuyển giao.
- Hash bằng cách đọc từng khối 1 MB, nên dump RAM vài GB vẫn chạy được mà không tràn bộ nhớ.
- `--base` tìm file theo tên khi đường dẫn lúc thu không còn đúng. Log ghi trên Windows
  (`C:\...\mem.vmem`) vẫn verify được trên Linux và ngược lại.

---

## `tests/` – kiểm thử tự động

- `mock_encrypt.py` – mã hóa giả lập đúng hợp đồng dữ liệu, dùng thay `keyholder.py` khi test
  (không cần thư viện `cryptography`). Cùng tham số thì cho ra layout file giống keyholder.
- `test_decrypt.py` – dựng bộ file mồi giả nhưng đúng cấu trúc (docx/xlsx là ZIP thật, doc/xls có
  header OLE chuẩn), mã hóa rồi giải mã lại bằng đúng dòng lệnh như khi chạy tay.
- `test_hash_evidence.py` – thu, verify, phát hiện file bị sửa, verify log của hệ điều hành khác.

```bash
python -m unittest discover -s tests -v
```

---

## Cách tự kiểm tra lại (known-answer test)

Khóa và file gốc biết trước nên kiểm chứng được mọi thứ:
- Hai profile, AES-128 và AES-256: mọi file khớp SHA-256 100%.
- Khóa thật lẫn trong 300 khóa rác, không có manifest: mọi file chọn đúng khóa; docx/xlsx/doc/xls
  trùng bản gốc từng byte.
- Chỉ có khóa rác (kể cả 2000 khóa rác trên file nhỏ): không file nào bị nhận nhầm, exit code 1.
- Chọn sai profile: báo `error` kèm gợi ý thay vì giải mã ra rác.
- Sửa 1 byte trong bằng chứng: `verify` báo `MISMATCH`, exit code 1.

Trong lần test đã chạy: **12/12 test qua trên Windows (Python 3.8) và Ubuntu 26.04 (Python 3.14)**.
Giải mã đúng **8/8 file** trong hai lô `enc_prepend_aes128` / `enc_prepend_aes256` của Hoàng, SHA-256
khớp `orig_sha256` trong ground truth, kể cả khi khóa thật lẫn trong 1000 khóa rác và không có manifest.

---

## Ghi chú: `.gitattributes`

Git trên Windows mặc định đổi ký tự xuống dòng LF thành CRLF khi checkout. Với file mồi, việc này làm
SHA-256 lệch ngay khi pull; với file `.locked` bị git nhận nhầm là văn bản, nó chèn thêm byte `0x0D`
và làm hỏng ciphertext. `.gitattributes` tắt chuyển đổi này cho `samples/` và các file bằng chứng.

---

## Quan hệ với bài báo và rubric

| Phần | Khớp với |
|---|---|
| `decrypt.py` (đọc IV trong file + khóa → giải mã) | Experiment part 3, mục 3.2.3, 4.3.3; kết quả 5.1.3, 5.2.3, 5.3.3 |
| Vá header tự động | Bài báo chèn header bằng tay (4.3.3, 5.1.3); nhóm tự động hóa và khôi phục trùng byte |
| `make_manifest.py` + so SHA-256 | Control files (3.2.4); thay bước kiểm tra thủ công mà bài báo nêu là hạn chế (4.3.3) |
| `hash_evidence.py` | Chain of custody – tiêu chí trong đề cương; Bảng 1 của bài báo (hash mẫu) |
| `report.csv` | "Bảng file giải mã thành công/thất bại kèm hash" phải nộp (bảng phân công v2, mục 5.2) |
| Module gọi được từ tool | Phần tool tự động (G4.2 – công cụ nguyên mẫu) |

**Hạn chế:**
- Profile `phobos` (IV ở cuối file, khối 128 byte, chuỗi `LOCK96`) chưa làm; chờ đặc tả từ file thật.
- PDF/JPG ở `overwrite16` chỉ vá được header đoán; TXT/CSV mất 16 byte đầu.
- Mới test trên dữ liệu của keyholder và `mock_encrypt`, chưa test trên file do ransomware thật mã hóa.
