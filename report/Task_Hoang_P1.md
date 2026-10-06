# Code mảng RAM & khóa AES – giải thích từng file

Thư mục này là phần công cụ của **Mảng 1 (RAM & khóa AES)** trong đồ án: dò khóa AES
mà ransomware giữ trong RAM để giải mã lại file cho nạn nhân (Part 1 của bài báo Davies 2020).

## Ý tưởng chung (đọc cái này trước)

Ransomware lai (HCR) mã hóa file bằng **khóa AES**. Để mã hóa được thì khóa đó **bắt buộc
phải nằm trong RAM** lúc đang chạy. Nếu chụp RAM đúng lúc rồi dò ra khóa, ta giải mã lại
được file mà không cần trả tiền chuộc.

Vấn đề: khóa chỉ dài 16–32 byte, lọt giữa hàng GB dữ liệu. Làm sao tìm? Hai bước:

1. **Lọc thô** – khóa là dữ liệu ngẫu nhiên, khác với code/text/zero ở xung quanh.
   Bỏ nhanh các vùng "chết" (toàn 0, dữ liệu lặp).
2. **Xác nhận chắc chắn** – AES không chỉ giữ 16 byte khóa gốc, mà tính sẵn cả một
   **key schedule** (mảng khóa con) dài 176/208/240 byte rồi để nguyên trong RAM cho chạy nhanh.
   Mảng này có ràng buộc toán học biết trước. Với mỗi đoạn 16 byte nghi ngờ, ta tự tính
   key schedule đúng-ra-phải-có rồi so với các byte nằm ngay sau trong dump. **Khớp → chắc
   chắn là khóa AES thật** (ngẫu nhiên mà trùng cả 176 byte là gần như không thể).

Luồng chạy của cả pipeline:

```
keyholder.py  ->  (dump RAM)  ->  keyscan.py  ->  keys.json  ->  decrypt.py  ->  file gốc
(tạo dữ liệu test)              (dò khóa)       (khóa tìm được)  (của Đăng)
```

---

## `aes_schedule.py` – sinh AES key schedule

**Làm gì:** từ một khóa 16/24/32 byte, tính ra toàn bộ key schedule chuẩn Rijndael
(176/208/240 byte). Đây là "công thức" để `keyscan` kiểm tra một đoạn byte có phải khóa thật không.

**Vì sao tin được:** có hàm kiểm thử bằng **test vector FIPS-197** (chuẩn chính thức của AES).
Chạy `python tools/aes_schedule.py` sẽ tự so với đáp án trong chuẩn → đúng mới chạy tiếp.

**Dùng riêng:** không, đây là thư viện cho `keyscan.py` gọi.

```bash
python tools/aes_schedule.py      # in ra: expand_key OK, AES-128 schedule = 176 byte...
```

---

## `keyscan.py` – dò khóa AES trong dump (TOOL CHÍNH)

**Làm gì:** đọc một file dump RAM, quét qua tìm các khóa AES, in ra và ghi `keys.json`.

**Cách hoạt động:** trượt cửa sổ qua dump. Tại mỗi vị trí:
- Lọc thô: đếm số byte phân biệt trong 16 byte ứng viên. Khóa ngẫu nhiên gần như luôn có
  ~15–16 byte phân biệt, nên ngưỡng 11 **không bao giờ bỏ sót khóa thật**, mà vẫn bỏ được
  vùng toàn 0 (1 byte phân biệt). *(Đây là lý do không dùng entropy theo block: block có thể
  bị loãng nếu khóa nằm giữa vùng zero → sót khóa, rất nguy hiểm cho pháp chứng.)*
- Xác nhận: tính key schedule của ứng viên, so với các byte ngay sau. Khớp → là khóa.

**Chạy:**
```bash
python tools/keyscan.py dump.vmem                          # dò cả 128/192/256
python tools/keyscan.py dump.vmem --bits 128 --out keys.json
python tools/keyscan.py dump.vmem --baseline clean.vmem    # loại khóa đã có trong dump sạch
python tools/keyscan.py dump.vmem --no-entropy             # tắt lọc thô (chậm, để đo thời gian)
python tools/keyscan.py dump.vmem --byteswap               # chế độ khóa bị đảo byte trong word
python tools/keyscan.py proc.dmp --pid 4321 --scope process   # khi quét riêng 1 tiến trình
```

**Các tùy chọn quan trọng:**
- `--baseline clean.vmem` – chụp RAM *trước* khi nhiễm, dò khóa, rồi loại các khóa đó đi.
  `keys.json` chỉ còn khóa mới do ransomware sinh ra.
- `--byteswap` – một số thư viện lưu khóa với thứ tự byte đảo trong từng word 4 byte.
  Bật cờ này để bắt trường hợp đó (findaes không bắt được).
- `--no-entropy` – quét mọi vị trí, không lọc. Chậm hơn nhiều, dùng để **đo** chênh lệch
  tốc độ cho báo cáo (xem phần so sánh bên dưới).

**Output `keys.json`:**
```json
{"schema": 1, "keys": [
  {"source": "dump.vmem", "dump_time": "2026-10-04T16:00:08+07:00",
   "offset": "0x1a2b3c", "bits": 128, "key_hex": "…",
   "tool": "keyscan", "pid": 4321, "scope": "process"}
]}
```
Mỗi cặp dump–khóa một dòng (Part 2 cần biết khóa xuất hiện ở dump nào). `decrypt.py` của Đăng
đọc file này để lấy khóa.

**Hạn chế:** viết bằng Python thuần nên chậm hơn findaes (viết bằng C). Đúng thế là bình thường —
chính là điểm để **so sánh công cụ** trong báo cáo. Quét cả dump GB thì nên dùng Volatility
tách riêng vùng nhớ một tiến trình rồi mới quét:
```bash
vol -f dump.vmem windows.memmap --pid <PID> --dump
python tools/keyscan.py <file_vol_xuat_ra> --pid <PID>
```

---

## `keyholder.py` – tạo dữ liệu test (KHÔNG phải ransomware)

**Làm gì:** mã hóa **bản sao** các file trong thư mục test bằng một khóa AES **biết trước**,
ghi khóa thật ra `ground_truth.json`. Dùng để test `keyscan`/`decrypt` khi chưa có mẫu thật.

**An toàn:** chỉ đọc file gốc, ghi sang thư mục khác; không ghi đè, không xóa, không lây lan.
Khóa để công khai trong JSON. Đây là test vector, không phải mã độc.

**Hai profile mô phỏng cách ghi IV của ransomware thật:**
- `prepend` – file = `IV + ciphertext`. Không mất byte nào. Dùng để test pipeline cho nhanh.
- `overwrite16` – file = `IV + CBC(key, IV, PKCS7(P[16:]))`. Mất đúng 16 byte đầu plaintext,
  giống NotPetya (nên phải vá lại header khi giải mã).

**Chạy:**
```bash
# tạo lô mã hóa cho Đăng test
python tests/keyholder.py --in samples/plain --out samples/enc_prepend_aes128 --bits 128 --profile prepend

# giữ khóa trong RAM để test dump (in ra PID rồi treo chờ Enter)
python tests/keyholder.py --in samples/plain --out /tmp/enc --profile overwrite16 --hold
```

---

## `samples/` – dữ liệu test sẵn cho Đăng

- `samples/plain/` – 4 file mồi biết trước nội dung: `note.txt`, `report.pdf`, `data.csv`, `book.zip`
  (4 loại magic bytes khác nhau để test nhận dạng).
- `samples/enc_prepend_aes128/` – lô mã hóa AES-128 + `ground_truth.json`.
- `samples/enc_prepend_aes256/` – lô mã hóa AES-256 + `ground_truth.json`.

Mỗi lô có `ground_truth.json` riêng, khai `profile` + `bits` + `key_hex` một lần cho cả lô,
kèm `orig_sha256` của từng file để `decrypt.py` đối chiếu sau khi giải mã.

**Đăng test `decrypt.py`:** đọc `ground_truth.json` lấy `key_hex`, giải mã các file `.locked`,
so SHA-256 kết quả với `orig_sha256`. Khớp = giải mã đúng.

---

## Cách tự kiểm tra lại (known-answer test)

Vì khóa biết trước nên kiểm chứng được mọi thứ:
- `keyscan` tìm đúng khóa đã nhúng trong dump giả → thuật toán dò đúng.
- `decrypt` ra file có SHA-256 khớp file gốc → giải mã đúng.
- Lọc thô bật/tắt cho cùng kết quả, chỉ khác tốc độ → lọc không làm sót khóa.

Trong lần test đã chạy: dò đúng cả khóa 128 và 256; lọc thô nhanh **~14 lần** so với không lọc
(đối chiếu với nhận xét "interrogate chậm ~100 lần" trong bài báo); `--baseline` loại đúng
khóa cũ.

---

## Quan hệ với bài báo và rubric

| Phần | Khớp với |
|---|---|
| `keyscan` (entropy + key schedule) | Mục 2.2.1–2.2.3 của bài báo; kiến thức nền 30% |
| So sánh có/không lọc thô | Nhận xét về tốc độ findaes vs interrogate; demo nâng cao |
| `keyholder` + `samples` | Dữ liệu test để chạy pipeline trước khi có mẫu thật |
| `keys.json` chung với `decrypt` | Phần tool tự động (G4.2 – công cụ nguyên mẫu) |

**Lưu ý:** mẫu ransomware thật (Phobos trước) chạy ở buổi lab trong môi trường cô lập. Phần code
ở đây là chuỗi công cụ + dữ liệu test, đã chạy xong để không phải chờ lab.
