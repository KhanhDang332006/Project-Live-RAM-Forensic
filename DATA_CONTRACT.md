# Hợp đồng dữ liệu – Nhóm 4

Đề tài 4: Điều tra lây nhiễm ransomware trên máy tính (NT334)

| | |
|---|---|
| Phiên bản | 1 (`schema: 1`) |
| Ngày chốt | 04/10/2026 |
| Người chốt | Khánh Đăng, Minh Hoàng |
| Người dùng làm định dạng chung của tool | Trung Hải |

Tài liệu này quy định định dạng mọi file mà các script của nhóm truyền cho nhau. Ai muốn đổi một trường hay một cột thì phải báo cả 3 người trước khi sửa code. Thay đổi làm script cũ đọc sai thì phải tăng `schema`.

---

## 1. Luồng dữ liệu

```
samples/plain/ ──make_manifest.py──► manifest.csv ─────────────────────┐
      │                                                                │
      └──keyholder (mô phỏng)──► samples/encrypted/*.locked ──┐        │
                     │                                        ▼        ▼
                     └──► ground_truth.json ─────────────► decrypt.py ──► decrypted/ + report.csv
                                                              ▲
VM (VMware) ──chụp RAM──► *.vmem + *.vmsn ──keyscan.py──► keys.json
      │                         │
      │                         └──hash_evidence.py──► custody_log.csv
      └──script chụp RAM──► capture_log.csv (dump_time) ──► keyscan.py
```

| Script | Người viết | Đọc vào | Xuất ra |
|---|---|---|---|
| keyholder | Minh Hoàng | `samples/plain/` | `samples/encrypted/`, `ground_truth.json` |
| script chụp RAM | Trung Hải | VM | `*.vmem`, `*.vmsn`, `capture_log.csv` |
| keyscan.py | Minh Hoàng | dump, `capture_log.csv` | `keys.json` |
| make_manifest.py | Khánh Đăng | `samples/plain/` | `manifest.csv` |
| decrypt.py | Khánh Đăng | `*.locked`, `keys.json` hoặc `ground_truth.json`, `manifest.csv` | `decrypted/`, `report.csv` |
| hash_evidence.py | Khánh Đăng | mọi bằng chứng | `custody_log.csv` |

## 2. Thư mục trong repo

```
repo/
├── DATA_CONTRACT.md
├── ground_truth.json          # lô chính (AES-128)
├── manifest.csv
├── custody_log.csv
├── samples/
│   ├── plain/                 # file mồi gốc
│   ├── encrypted/             # file đã mã hóa, đuôi .locked
│   └── encrypted_256/         # lô AES-256, có ground_truth.json riêng
└── decrypted/                 # đầu ra của decrypt.py
```

Dump RAM và ảnh đĩa **không** đưa vào git vì quá nặng. Chúng nằm ở nơi lưu chung của nhóm; `custody_log.csv` ghi lại đường dẫn và hash của từng file.

## 3. Quy ước chung

- Mã hóa ký tự: UTF-8. JSON không có BOM. CSV phân cách bằng dấu phẩy, có dòng tiêu đề.
- CSV do script của nhóm tạo **có BOM** ở đầu file để Excel hiển thị đúng tiếng Việt. Script nào đọc CSV phải mở bằng `encoding="utf-8-sig"` (đọc được cả file có lẫn không có BOM).
- Hex: chữ thường, không dấu cách. Offset ghi dạng chuỗi có tiền tố `0x` (ví dụ `"0x1a2b"`).
- Thời gian: ISO 8601 có múi giờ, ví dụ `2026-10-04T15:30:00+07:00`.
- Trường không có giá trị thì ghi `null` (JSON) hoặc để trống (CSV), không bỏ hẳn trường đó.

---

## 4. `keys.json`

Do `keyscan.py` xuất ra.

```json
{
  "schema": 1,
  "keys": [
    {
      "source": "mem_0030s.vmem",
      "dump_time": "2026-10-04T15:30:00+07:00",
      "scope": "process",
      "pid": 1234,
      "offset": "0x1a2b",
      "bits": 128,
      "key_hex": "00112233445566778899aabbccddeeff",
      "tool": "aeskeyfind"
    }
  ]
}
```

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `source` | string | Tên file dump chứa khóa |
| `dump_time` | string | Thời điểm chụp dump, lấy từ `capture_log.csv` |
| `scope` | string | `"file"`: quét cả file dump. `"process"`: chỉ quét vùng nhớ của một tiến trình |
| `pid` | int / null | PID của tiến trình được quét; `null` khi `scope = "file"` |
| `offset` | string | Offset của khóa **trong file dump đang quét** |
| `bits` | int | `128` hoặc `256` |
| `key_hex` | string | Khóa AES: 32 ký tự hex (128 bit) hoặc 64 ký tự (256 bit) |
| `tool` | string | `"findaes"`, `"aeskeyfind"`, … |

Quy tắc:

- **Mỗi cặp dump–khóa là một dòng, không gộp.** Một khóa có mặt trong 10 bản dump thì ghi 10 dòng. Part 2 (timeline khóa) cần biết khóa xuất hiện ở những dump nào.
- `keyscan.py` mặc định **bỏ các khóa đã có trong bản dump sạch**. Cờ `--no-baseline` tắt bộ lọc này, chỉ dùng khi debug.
- Độ dài `key_hex` phải khớp với `bits`. decrypt.py coi dòng không khớp là lỗi và bỏ qua.

## 5. `ground_truth.json`

Do keyholder ghi ra. Dùng **cùng schema với `keys.json`** nên decrypt.py chỉ cần một bộ đọc. Có hai điểm khác:

- `"tool": "ground_truth"`
- Có thêm trường `"profile"` ở cấp ngoài cùng, áp dụng cho cả lô

```json
{
  "schema": 1,
  "profile": "prepend",
  "keys": [
    {
      "source": "keyholder",
      "dump_time": null,
      "scope": null,
      "pid": null,
      "offset": null,
      "bits": 128,
      "key_hex": "00112233445566778899aabbccddeeff",
      "tool": "ground_truth"
    }
  ]
}
```

Mỗi lô mã hóa có một `ground_truth.json` riêng. Lô AES-256 (dùng để kiểm tra keyscan bắt được khóa 256 bit như của Phobos) nằm ở `samples/encrypted_256/` kèm file ground truth của nó.

---

## 6. Định dạng file mã hóa (profile)

### Thông số chung cho mọi profile

| Thông số | Giá trị |
|---|---|
| Thuật toán | AES-CBC |
| Độ dài khóa | 128 bit (lô chính), 256 bit (lô phụ) |
| Khóa | Một khóa cho mọi file trong lô |
| IV | 16 byte ngẫu nhiên, mỗi file một IV khác |
| Padding | PKCS7 |
| Tên file | Giữ tên gốc, thêm đuôi `.locked` (ví dụ `bao_cao.docx.locked`) |
| Header / trailer thêm vào | Không có |
| Loại file bị mã hóa | Cả 7 loại: pdf, doc, docx, xls, xlsx, txt, jpg |

### 6.1. `prepend`: không mất byte nào

```
File mã hóa:  [ IV (16) ][ AES-CBC(key, IV, PKCS7(P)) ]
```

Giải mã:

```
iv   = f[0:16]
P    = unpad(AES-CBC-decrypt(key, iv, f[16:]))
```

`SHA-256(P)` phải khớp 100% với `manifest.csv`. Profile này dùng để thông cả chuỗi công cụ trước.

### 6.2. `overwrite16`: mất 16 byte đầu, mô phỏng NotPetya / Bad Rabbit

```
File mã hóa:  [ IV (16) ][ AES-CBC(key, IV, PKCS7(P[16:])) ]
              16 byte đầu của bản gốc P[0:16] bị bỏ đi, không được mã hóa
```

Giải mã:

```
iv    = f[0:16]
body  = unpad(AES-CBC-decrypt(key, iv, f[16:]))      # = P[16:]
P     = header16 + body                               # vá header
```

`header16` lấy từ một trong hai nguồn:

| Nguồn | Khi nào dùng | Hash có khớp không |
|---|---|---|
| Cột `header16_hex` trong `manifest.csv` | Trong lab, khi có bản gốc | Khớp 100% |
| Header mẫu theo từng loại file (`%PDF-1.x`, `PK\x03\x04…`, `D0CF11E0…`) | Giống điều tra thật, không có bản gốc | File mở được, hash có thể lệch |

**Vì sao chọn kiểu này mà không ghi IV đè lên khối ciphertext đầu tiên C0:**
Trong CBC, `P_i = D(C_i) XOR C_(i-1)`. Nếu IV ghi đè lên C0 thì P0 hỏng (cần C0) và P1 cũng hỏng (`P1 = D(C1) XOR C0`), tức là mất 32 byte. Tệ hơn, IV khi đó trở nên vô dụng: hai khối cần đến IV đều đã mất, và từ P2 trở đi chỉ cần khóa là giải mã được. Như vậy trái với mục 5.1.3 của bài báo, nơi tác giả đọc IV từ file rồi dùng nó cùng khóa để giải mã. Kiểu `overwrite16` ở trên khớp với mô tả của bài báo: IV có tác dụng, mất đúng 16 byte, phải chèn lại header. Chi tiết "phải bỏ vài byte ở cuối file" trong bài báo tương ứng với phần padding.

File gốc ngắn hơn 16 byte: `P[16:]` rỗng, phần ciphertext chỉ là một khối padding, toàn bộ nội dung nằm trong `header16`.

### 6.3. `phobos`: để sau

Theo mục 5.3.3 của bài báo: IV nằm ở cuối file, kèm khối 128 byte và chuỗi đánh dấu (`LOCK96`). Sẽ đặc tả khi có file thật hoặc khi viết profile mô phỏng.

---

## 7. `manifest.csv`

Do `make_manifest.py` tạo ra từ `samples/plain/` **trước khi mã hóa**.

```csv
filename,ext,size,sha256,magic_hex,header16_hex
bao_cao.docx,docx,48213,9f2c…,504b030414000600,504b0304140006000800000021007a1e
```

| Cột | Ý nghĩa |
|---|---|
| `filename` | Tên file gốc. File mã hóa tương ứng là `filename + ".locked"` |
| `ext` | Đuôi file, chữ thường |
| `size` | Kích thước (byte) |
| `sha256` | Hash của file gốc |
| `magic_hex` | 8 byte đầu, dùng để kiểm tra magic bytes |
| `header16_hex` | 16 byte đầu (ít hơn nếu file ngắn hơn 16 byte), dùng để vá header ở profile `overwrite16` |

## 8. `report.csv`

Do `decrypt.py` xuất ra; đây là bảng "file giải mã thành công/thất bại" phải nộp. Được phép thêm cột mới, không được đổi tên cột đã có.

| Cột | Ý nghĩa |
|---|---|
| `file` | Tên file `.locked` |
| `profile` | Profile đã dùng |
| `key_tool` | `tool` của khóa giải mã được (`ground_truth`, `aeskeyfind`, …) |
| `key_source` | `source` của khóa đó (tên dump) |
| `key_hex` | Khóa đã dùng |
| `header_patch` | `none` / `manifest` / `template` |
| `magic_ok` | `true` / `false`. Có manifest thì so với `magic_hex`; không có thì so với magic chuẩn của loại file, để trống nếu loại đó không có magic (txt) |
| `sha256_ok` | `true` / `false`; để trống nếu chạy không có manifest |
| `status` | `ok` / `no_key` / `error` |
| `note` | Ghi chú lỗi, nếu có |

## 9. `custody_log.csv`

Do `hash_evidence.py` ghi. **Chỉ được ghi thêm dòng, không sửa hay xóa dòng cũ.**

| Cột | Ý nghĩa |
|---|---|
| `evidence_id` | Mã bằng chứng, ví dụ `E001` |
| `timestamp` | Thời điểm thực hiện hành động |
| `action` | `acquired` / `transferred` / `verified` |
| `collector` | Người thực hiện |
| `path` | Đường dẫn file |
| `size` | Kích thước (byte) |
| `sha256` | Hash tại thời điểm đó |
| `description` | Mô tả |

Một bằng chứng gồm nhiều file thì **dùng chung `evidence_id`, mỗi file một dòng**. Ví dụ một lần chụp RAM bằng VMware tạo ra `.vmem` (RAM thô) và `.vmsn`: ghi hai dòng cùng mã `E001`.

## 10. `capture_log.csv` (chờ Hải xác nhận)

Script chụp RAM của Hải ghi ra; `keyscan.py` đọc để điền `dump_time`. Định dạng đề xuất:

```csv
file,dump_time,elapsed_s
mem_0030s.vmem,2026-10-04T15:30:00+07:00,30
```

`elapsed_s` là số giây tính từ lúc chạy mẫu. Không bắt buộc, nhưng giúp vẽ biểu đồ timeline khóa Part 2 dễ hơn.

---

## 11. Việc còn mở

- [ ] Hải xác nhận định dạng `capture_log.csv` (mục 10).
- [ ] Hải sửa mục 5.3 của bảng phân công v2: đổi VirtualBox / `dumpvmcore` thành VMware (`.vmem` + `.vmsn`).
- [ ] Hoàng xác nhận cài `overwrite16` theo kiểu ở mục 6.2 (bỏ 16 byte đầu, không ghi đè C0).
- [ ] Đăng so hex file gốc và file mã hóa đầu tiên Hoàng gửi, kiểm tra đúng layout ở mục 6.
- [ ] Đặc tả profile `phobos` (mục 6.3).
