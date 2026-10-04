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
chạy mẫu trong VM ──► chụp RAM (.vmem) ──► keyscan.py ──► keys.json ──┐
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
│   └── hash_evidence.py    # chain of custody: hash + ghi log bằng chứng
└── samples/
    ├── plain/              # file mồi gốc (pdf, doc, docx, xls, xlsx, txt, jpg)
    └── encrypted/          # file đã bị mã hóa (*.locked)
```

## Cài đặt

Cần Python 3.8 trở lên.

```bash
pip install -r requirements.txt
```

`make_manifest.py` và `hash_evidence.py` chỉ dùng thư viện chuẩn. `pycryptodome` dành cho `decrypt.py`.

Mọi lệnh bên dưới chạy từ thư mục gốc của repo.

## Sử dụng

### Tạo manifest cho bộ file mồi

Chạy **trước khi** mã hóa, để có SHA-256 gốc làm chuẩn so sánh sau khi giải mã.

```bash
python tools/make_manifest.py                              # samples/plain -> manifest.csv
python tools/make_manifest.py --src <thư mục> --out manifest.csv
```

Script cảnh báo khi thiếu một trong 7 loại file, khi có file ngắn hơn 16 byte, và từ chối chạy nếu thư mục gốc lẫn file `.locked`.

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
| `decrypt.py` – profile `prepend`, `overwrite16` | Khánh Đăng | Đang làm |
| keyholder (chương trình mô phỏng mã hóa) | Minh Hoàng | Đang làm |
| `keyscan.py` | Minh Hoàng | Đang làm |
| Script chạy thí nghiệm + chụp RAM | Trung Hải | Chưa làm |
| Tool tự động chạy cả chuỗi | Trung Hải | Chưa làm |

## Quy tắc an toàn

- Mẫu ransomware chỉ chạy trong máy ảo cô lập. Tắt mạng máy host trong lúc chạy mẫu. Không mở mẫu trên máy cá nhân.
- **Mẫu ransomware thật không bao giờ đưa lên repo** (kể cả nhánh riêng). Chỉ lưu dạng nén có mật khẩu ở nơi lưu riêng của nhóm.
- Dump RAM, ảnh đĩa và pcap không đưa lên git vì quá nặng. Chúng nằm ở nơi lưu chung; `custody_log.csv` ghi đường dẫn và hash của từng file. `.gitignore` đã chặn sẵn các đuôi file này.
- Chỉ đưa vào `samples/plain/` những file mồi không chứa dữ liệu cá nhân.
