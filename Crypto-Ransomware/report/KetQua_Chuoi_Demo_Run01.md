# Kết quả – Chuỗi demo đầu tiên: chụp RAM → dò khóa → giải mã (run01)

**Người làm:** Minh Hoàng. **Ngày:** 17/10/2026.
Đây là lần chạy trọn Part 1 và Part 3 của bài báo Davies 2020 bằng công cụ của nhóm, trên máy ảo thật.
Dùng `tests/keyholder.py` làm chương trình mã hóa giả lập (**không phải ransomware thật**) để kiểm tra chuỗi trước khi có mẫu thật.
Liên quan: [KetQua_Lab_Baseline.md](KetQua_Lab_Baseline.md) (lab và baseline), [KetQua_Part1.md](KetQua_Part1.md) (so sánh công cụ).

## 1. Tóm tắt

| Bước | Công cụ | Kết quả |
|---|---|---|
| Mã hóa giả lập, giữ khóa trong RAM | `keyholder.py --hold` (AES-128, profile `prepend`) | Khóa `77eb5f011fbf6700287890581eb4ebe3` |
| Chụp RAM VM đang chạy | `tools/capture.ps1` (VMware snapshot) | 1 dump 4 GB (`mem_0000s.vmem` + `.vmsn`) |
| Dò khóa trên cả RAM | `keyscan` (C++), `--bits 128` | 11 khóa ứng viên, có khóa đúng ở offset `0x66825070` |
| Loại khóa nền | `keyscan --baseline` (dump Windows sạch) | Còn 8 ứng viên, vẫn có khóa đúng |
| Chọn khóa và giải mã | `decrypt.py` (profile `prepend`) | Chọn đúng khóa trong 8 ứng viên, **10/10 file** khớp bản gốc |

## 2. Thiết lập

| Mục | Giá trị |
|---|---|
| Victim | Windows 10, RAM 4 GB, VMware, đã bật audit tạo tiến trình, đã có snapshot sạch `clean-baseline` |
| Chương trình mã hóa | `tests/keyholder.py --in samples/plain --out samples/run01 --bits 128 --profile prepend --hold` |
| Khóa đúng (ground truth) | `77eb5f011fbf6700287890581eb4ebe3` (do keyholder in ra lúc chạy) |
| Chụp RAM | `capture.ps1 -Count 1`, bắt đầu lúc 2026-10-17T15:32:22+07:00, mất **211,1 s** |
| Phân tích | VM Kali: `keyscan` bản C++, `decrypt.py`, repo `Project-Live-RAM-Forensic` |
| Baseline | `Win10-VICTIM-Snapshot1.vmem` (4 GiB, 9 khóa 128-bit, xem `KetQua_Lab_Baseline.md`) |

Keyholder được chạy với `--hold`: nó giữ một đối tượng mã hóa còn sống để key schedule AES còn nằm trong RAM lúc chụp. Đây mô phỏng ransomware đang trong quá trình mã hóa (xem mục 4 của `KetQua_Part1.md`: key schedule chỉ tồn tại khi context mã hóa còn sống).

## 3. Dò khóa trên dump nguyên cả máy (Part 1)

Dump `mem_0000s.vmem` đưa sang Kali qua shared folder (chỉ bật cho Kali).

### 3.1. Không baseline

```
./keyscan mem_0000s.vmem --bits 128 --out keys_all.json
```

| Mục | Giá trị |
|---|---|
| Dung lượng quét | 4 294 967 296 byte |
| Thời gian | **18,80 s** |
| Số khóa 128-bit | **11** |

Khóa đúng `77eb5f011fbf6700287890581eb4ebe3` nằm ở offset `0x66825070`.

### 3.2. Có baseline

```
./keyscan mem_0000s.vmem --bits 128 --baseline ../baseline/Win10-VICTIM-Snapshot1.vmem --out keys.json
```

| Mục | Giá trị |
|---|---|
| Thời gian | **38,61 s** (gồm quét lại 4 GB của baseline) |
| Khóa baseline có 128-bit | 9 |
| Khóa bị loại (xuất hiện ở cả baseline và dump) | **3**: `a19e907f…`, `8b4b6f05…`, `7c3877dc…` |
| Khóa ứng viên còn lại | **8** |

Khóa keyholder **không có trong baseline** (đúng kỳ vọng: nó được sinh ra sau khi chụp baseline) nên còn nguyên trong 8 ứng viên.

### 3.3. Nhận xét

- Baseline loại được khóa nền của Windows nhưng **không loại hết**: 7 khóa lạ còn lại là khóa mới của Windows sinh ra từ lúc chụp baseline tới lúc chụp dump (khóa phiên của hệ thống). Có ví dụ cùng một offset `0x2e35aa0` nhưng khóa khác nhau giữa baseline (`27a23d37…`) và dump (`c7ce594a…`), tức khóa đổi theo thời gian.
- Vì vậy **baseline chỉ thu hẹp danh sách**, không chọn được khóa đúng. Việc chọn khóa đúng phải dựa vào thử giải mã (mục 4).
- Quét 4 GB RAM chỉ khoảng 19 giây cho một độ dài khóa. Con số quét có/không baseline là một lần đo, chưa lặp lại.

## 4. Chọn khóa và giải mã (Part 3)

File `.locked` do keyholder tạo trong victim (`samples/run01`) được chép ra qua thư mục chung (chỉ file `.locked`, **không** chép `ground_truth.json` để giống điều tra thật). Chạy trên Kali:

```
python tools/decrypt.py --keys keys.json --in ~/Downloads/run01/locked --profile prepend \
       --out ~/Downloads/run01/decrypted --report ~/Downloads/run01/report.csv
```

`decrypt.py` thử lần lượt 8 khóa ứng viên: lọc nhanh bằng padding PKCS7, rồi xác nhận bằng SHA-256 với `manifest.csv` hoặc kiểm tra cấu trúc file.

### 4.1. Kết quả

| File | Kết quả |
|---|---|
| baocao_tongket_q3.pdf, report.pdf | SHA-256 khớp |
| bienban_hop_thang9.doc, tonkho_cuoiky.xls | SHA-256 khớp |
| hopdong_muaban.docx, doanhthu_q3.xlsx | SHA-256 khớp |
| data.csv, note.txt | SHA-256 khớp |
| sodo_phongban.jpg | SHA-256 khớp |
| book.zip | Giải mã hợp lệ (`magic_ok`), `manifest.csv` **thiếu dòng** cho file này nên báo trống; hash thủ công `0df2151d…97804` **trùng bản gốc** `samples/plain/book.zip` |
| `.gitkeep.locked` | File ẩn bị keyholder mã hóa theo; quá nhỏ để tự xác nhận, `decrypt.py` chỉ nhận vì khóa đã đúng ở file khác |

**Kết quả: 10/10 file mồi giải mã trùng từng byte với bản gốc.** Khóa được chọn trong báo cáo (`key_hex`) là `77eb5f011fbf6700287890581eb4ebe3`, đúng khóa keyholder, `key_tool = keyscan`, `key_source = mem_0000s.vmem`.

### 4.2. Hai điểm cần sửa cho lần chạy mẫu thật

1. **`manifest.csv` thiếu `book.zip`**: được tạo trước khi file này thêm vào `samples/plain`. Cần chạy lại `make_manifest.py` (việc của Đăng) **trước khi** chạy mẫu thật; manifest phải ghi hash của file mồi lúc chưa bị mã hóa.
2. **`.gitkeep` bị mã hóa theo**: không chép file ẩn vào bộ file mồi đặt trong victim.

## 5. Điều kiện của kết quả này

- Đây là **keyholder** (chương trình thử nghiệm, AES-128, một khóa chung cho mọi file), không phải ransomware thật. Kết quả chứng minh công cụ và quy trình hoạt động, **chưa chứng minh** với mẫu thật như Phobos.
- Mới thử **AES-128**. AES-256 chưa chạy trên dump thật của quy trình này (đã thử ở lần thí nghiệm trước trên dump riêng của tiến trình, xem `KetQua_Part1.md`).
- Mới **một lần chạy, một dump**. Chưa lặp lại, chưa có timeline (Part 2).
- **Thời gian chụp RAM lâu** (211 s cho một snapshot VMware), tạm bỏ qua, sẽ xử lý khi làm Part 2. Dump là trạng thái RAM tại lúc bắt đầu chụp (theo log của VMware, snapshot kiểu "lazy": VM chỉ khựng khoảng 0,2 giây lúc bắt đầu).
- Cột `sha256_ok` có 1 dòng trống do manifest thiếu, đã xác minh thủ công; kết quả 10/10 dựa trên cả hai cách.

## 6. Bước tiếp theo

- Làm lại một lượt với **AES-256** (đổi `--bits 256` ở keyholder và keyscan).
- Đăng chạy lại `make_manifest.py`, đẩy `manifest.csv` mới.
- Chốt mẫu thật (Phobos) với cả nhóm và báo thầy, rồi chạy lại cả chuỗi này với mẫu thật (H4, D3).
- Part 2: chụp nhiều dump và vẽ timeline khóa.
- Ghi hash dump, file `.locked`, `keys.json` vào `custody_log.csv` (`hash_evidence.py acquire`).
