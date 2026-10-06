# NT334 – Nhóm 4: Điều tra lây nhiễm ransomware trên máy tính

Đồ án môn **NT334 – Pháp chứng kỹ thuật số**, Trường Đại học Công nghệ Thông tin – ĐHQG TP.HCM.

Nhóm đóng vai điều tra viên trước một máy Windows (máy ảo) vừa bị ransomware mã hóa file, và phải trả lời hai câu hỏi:

1. **Có lấy lại được file mà không trả tiền chuộc không?** Khi ransomware đang mã hóa, khóa AES bắt buộc phải nằm trong RAM. Chụp RAM đúng lúc, dò ra khóa, rồi dùng khóa đó giải mã file.
2. **Chuyện gì đã xảy ra, lúc nào, bằng cách nào?** Gom dấu vết từ RAM, ổ đĩa và mạng thành một timeline sự cố.

Phương pháp tái hiện theo bài báo:

> S. R. Davies, R. Macfarlane, W. J. Buchanan (2020). *Evaluation of live forensic techniques in ransomware attack mitigation.* Forensic Science International: Digital Investigation.

## Thành viên

| Thành viên | Mảng chính |
|---|---|
| Ngô Xuân Minh Hoàng (nhóm trưởng) | RAM & khóa AES – Part 1, Part 2 của bài báo |
| Nguyễn Hoàng Khánh Đăng | Đĩa & giải mã file – Part 3, chain of custody, timeline sự cố |
| Nguyễn Hoàng Trung Hải | Lab, mạng & tool tự động |

## Luồng xử lý

```
chạy mẫu trong VM ──► chụp RAM (.vmem) ──► tools/keyscan.py ──► keys.json ──┐
        │                                                             ▼
        └──► file bị mã hóa (*.locked) ──────────────────────► decrypt.py ──► file gốc + report.csv
                                                                      ▲
samples/plain/ ──► make_manifest.py ──► manifest.csv (SHA-256 gốc) ───┘

mọi bằng chứng (dump, ảnh đĩa, pcap) ──► hash_evidence.py ──► custody_log.csv
```

Định dạng mọi file truyền giữa các script được quy định trong **[DATA_CONTRACT.md](DATA_CONTRACT.md)**. Muốn đổi định dạng nào thì báo cả nhóm trước khi sửa code.

## Cấu trúc repo

```
.
├── README.md
├── DATA_CONTRACT.md        # hợp đồng dữ liệu giữa các script
├── requirements.txt
├── tools/
│   ├── make_manifest.py    # tạo manifest.csv cho bộ file mồi
│   ├── decrypt.py          # Part 3: giải mã file .locked bằng khóa ứng viên
│   └── hash_evidence.py    # chain of custody: hash + ghi log bằng chứng
├── tests/
│   ├── mock_encrypt.py     # mã hóa giả lập đúng hợp đồng dữ liệu (thay keyholder khi test)
│   └── test_decrypt.py     # test cả chuỗi manifest -> mã hóa -> giải mã
└── samples/
    ├── plain/              # file mồi gốc (pdf, doc, docx, xls, xlsx, txt, jpg)
    └── encrypted/          # file đã bị mã hóa (*.locked)
```

## Cài đặt

Cần Python 3.8 trở lên.

```bash
pip install -r requirements.txt
```

`make_manifest.py` và `hash_evidence.py` chỉ dùng thư viện chuẩn. `pycryptodome` dành cho `decrypt.py` và `tests/`. Nếu lệnh `pip` báo "Permission denied" thì dùng `python -m pip install -r requirements.txt`.

Mọi lệnh bên dưới chạy từ thư mục gốc của repo.

**Trên Linux** (đã test trên Ubuntu 26.04, Python 3.14; Windows test trên Python 3.8):

- Gõ `python3` thay cho `python`.
- Ubuntu/Debian bản mới chặn `pip install` vào Python hệ thống, nên cài trong môi trường ảo (thư mục `.venv/` đã có trong `.gitignore`):
  ```bash
  sudo apt install python3-venv
  python3 -m venv .venv && source .venv/bin/activate
  pip install -r requirements.txt
  ```
- Đặt múi giờ `Asia/Ho_Chi_Minh` để log ghi `+07:00` (DATA_CONTRACT.md mục 3).
- Muốn chạy kiểu `./tools/decrypt.py` thì phải `chmod +x`, và file phải lấy qua `git clone` trên Linux. File chép thẳng từ máy Windows còn ký tự xuống dòng CRLF nên dòng shebang sẽ lỗi. Gọi bằng `python3 tools/...` thì không bị ảnh hưởng.
- Tham số `--manifest=` (bỏ trống) viết giống nhau trên cả bash và PowerShell.

## Sử dụng

### Tạo manifest cho bộ file mồi

Chạy **trước khi** mã hóa, để có SHA-256 gốc làm chuẩn so sánh sau khi giải mã.

```bash
python tools/make_manifest.py                              # samples/plain -> manifest.csv
python tools/make_manifest.py --src <thư mục> --out manifest.csv
```

Script cảnh báo khi thiếu một trong 7 loại file, khi có file ngắn hơn 16 byte, và từ chối chạy nếu thư mục gốc lẫn file `.locked`.

### Giải mã file (Part 3)

```bash
# Có ground truth (profile tự lấy từ file): kiểm tra cả chuỗi, phải khớp SHA-256 100%
python tools/decrypt.py --keys ground_truth.json

# Khóa dò được từ RAM
python tools/decrypt.py --keys keys.json --profile overwrite16

# Giống điều tra thật: không có bản gốc, vá header theo cấu trúc file
python tools/decrypt.py --keys keys.json --profile overwrite16 --manifest= --patch template
```

Kết quả: file gốc trong `decrypted/` và `report.csv` (DATA_CONTRACT.md mục 8). Lệnh trả exit code 1 nếu còn file chưa giải mã được.

Cách chọn khóa đúng trong hàng trăm khóa ứng viên của keyscan:

1. **Lọc bằng padding PKCS7:** chỉ giải mã khối cuối; khóa sai lọt qua khoảng 1/256.
2. **Xác nhận:** có manifest thì so SHA-256. Không có thì kiểm tra cấu trúc: ZIP có end of central directory, PDF có `%%EOF`, JPG kết thúc bằng `FFD9`, TXT là UTF-8 hợp lệ. Không dùng entropy cho docx/xlsx/jpg, vì các định dạng này vốn đã nén nên entropy cao ngay cả khi giải mã đúng.
3. **Ưu tiên khóa đã đúng ở file khác** (cả lô dùng chung một khóa). File lớn xử lý trước. File gốc ≤ 16 byte ở `overwrite16` không còn dữ liệu để kiểm chứng, nên chỉ nhận khóa đã đúng ở file khác.

Vá 16 byte đầu bị mất ở profile `overwrite16` (`--patch template`, không cần bản gốc):

| Loại file | Cách vá | Kết quả |
|---|---|---|
| docx, xlsx | Chép lại các trường của local header từ central directory ở cuối file | Trùng bản gốc từng byte |
| doc, xls | Magic OLE + CLSID (luôn bằng 0 theo đặc tả MS-CFB) | Trùng bản gốc từng byte |
| pdf, jpg | Header mẫu 16 byte | Mở được, hash có thể lệch |
| txt | Không vá được | Mất 16 byte đầu |

### Chạy test

```bash
python -m unittest discover -s tests -v
```

Test dựng bộ file mồi giả (docx/xlsx là ZIP thật, doc/xls có header OLE chuẩn), mã hóa bằng `tests/mock_encrypt.py` rồi giải mã lại. Các trường hợp được test: hai profile, AES-256, khóa thật lẫn trong 300 khóa rác, chỉ có khóa rác, chọn sai profile.

### Chain of custody

Mỗi lần thu một bằng chứng thì ghi lại hash. Một bằng chứng có thể gồm nhiều file, ví dụ một lần chụp RAM bằng VMware tạo ra cả `.vmem` và `.vmsn`:

```bash
python tools/hash_evidence.py acquire mem_0030s.vmem mem_0030s.vmsn \
    --collector "Khánh Đăng" --desc "Dump RAM giây 30, lần chạy prepend #1"
```

Trước khi phân tích, hoặc khi giao bằng chứng cho người khác, kiểm tra lại hash. Lệnh trả exit code 1 nếu file đã bị thay đổi:

```bash
python tools/hash_evidence.py verify --id E001 --collector "Minh Hoàng"
python tools/hash_evidence.py verify --id E001 --collector "Khánh Đăng" \
    --action transferred --desc "Giao cho Minh Hoàng qua ổ chung"

# trên máy khác, bằng chứng nằm ở thư mục khác lúc thu:
python tools/hash_evidence.py verify --id E001 --collector "Minh Hoàng" --base Z:/evidence

python tools/hash_evidence.py list     # tóm tắt các bằng chứng
```

`custody_log.csv` chỉ được ghi thêm dòng, không sửa hay xóa dòng cũ.

## Tiến độ

| Thành phần | Người phụ trách | Trạng thái |
|---|---|---|
| `DATA_CONTRACT.md` | Khánh Đăng, Minh Hoàng | Xong (v1) |
| `tools/make_manifest.py` | Khánh Đăng | Xong |
| `tools/hash_evidence.py` | Khánh Đăng | Xong |
| `tools/decrypt.py` – profile `prepend`, `overwrite16`, `custom` | Khánh Đăng | Xong, chờ test trên file thật của keyholder |
| `decrypt.py` – profile `phobos` | Khánh Đăng | Chưa làm (chờ đặc tả, DATA_CONTRACT.md mục 6.3) |
| `tools/aes_schedule.py` – sinh AES key schedule (verify FIPS-197) | Minh Hoàng | Xong |
| `tools/keyscan.py` – dò khóa AES trong dump | Minh Hoàng | Xong (known-answer test PASS) |
| `tests/keyholder.py` – sinh test-vector, `--hold` giữ khóa trong RAM | Minh Hoàng | Xong |
| Script chạy thí nghiệm + chụp RAM | Trung Hải | Chưa làm |
| Tool tự động chạy cả chuỗi | Trung Hải | Chưa làm |

## Quy tắc an toàn

- Mẫu ransomware chỉ chạy trong máy ảo cô lập. Tắt mạng máy host trong lúc chạy mẫu. Không mở mẫu trên máy cá nhân.
- **Mẫu ransomware thật không bao giờ đưa lên repo** (kể cả nhánh riêng). Chỉ lưu dạng nén có mật khẩu ở nơi lưu riêng của nhóm.
- Dump RAM, ảnh đĩa và pcap không đưa lên git vì quá nặng. Chúng nằm ở nơi lưu chung; `custody_log.csv` ghi đường dẫn và hash của từng file. `.gitignore` đã chặn sẵn các đuôi file này.
- Chỉ đưa vào `samples/plain/` những file mồi không chứa dữ liệu cá nhân.
