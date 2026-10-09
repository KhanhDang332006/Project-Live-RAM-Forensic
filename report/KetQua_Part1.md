# Kết quả thí nghiệm – Part 1: dò khóa AES trong RAM

**Mảng 1 (RAM & khóa AES).** Mục tiêu: chứng minh có thể lấy lại khóa AES từ ảnh bộ nhớ
để giải mã file (tái lập Part 1 của bài báo Davies 2020), bằng chuỗi công cụ của nhóm.

## 1. Chuỗi chạy thật (end-to-end) trên VM Windows

| Bước | Làm gì | Kết quả |
|---|---|---|
| Nhiễm giả lập | Chạy `keyholder.py --hold` trong VM Windows 10 (VMware) | PID 6372, khóa AES-128 = `51430ec3035fe71ebfd963cfadd206d3` |
| Chụp RAM | Suspend VM → lấy `.vmem` + `.vmss` | Dump VMware đọc được |
| Volatility | `vol -f ...vmem windows.info / pstree / cmdline` | Đọc được VMware `.vmem`, thấy `python.exe` chạy keyholder (PID 6372) |
| Cắt tiến trình | `windows.memmap --pid 6372 --dump` | `pid.6372.dmp` ≈ 765 MB |
| Dò khóa | `keyscan` + `aeskeyfind` trên `pid.6372.dmp` | Cả hai ra đúng `51430ec3...` ✔ |

→ **Chứng minh được giả thuyết của bài báo trên máy Windows thật: khóa AES moi lại được từ RAM.**
Volatility đọc tốt định dạng `.vmem` của VMware → nhóm chốt dùng **VMware**.

**Lần chạy thứ hai (bản C++ `keyscan.cpp`):** chạy lại trên Kali với hai dump mới, mỗi lần một keyholder:

| Lần | Khóa keyholder | Kết quả bản C++ |
|---|---|---|
| AES-128 (dump `pid.512.dmp`) | `e71dcd19cd2515aed5a930f0c0985513` | Tìm đúng, offset `0x8c8f0`; trùng `aeskeyfind` (cùng 5 khóa) ✔ |
| AES-256 (dump `pid.10032.dmp`) | `5477e85837b372b8ce0680638801fd9e35930577846591251f74179165ae7ed6` | Tìm đúng, offset `0x3c25d0` ✔ |

Ngoài khóa keyholder, mỗi dump còn vài khóa AES khác của thư viện trong tiến trình python.exe (ví dụ `738f1529…`
xuất hiện ở cả hai lần). Đây là khóa nền, không phải khóa cần tìm.

## 2. Bảng so sánh công cụ (số đo thật)

**Bảng A – dump `pid.6372.dmp` ≈ 765 MB, chỉ quét khóa 128 bit (lần đo đầu):**

| Công cụ | Ngôn ngữ | Thời gian (real) | Số khóa | Có khóa đúng? |
|---|---|---|---|---|
| `keyscan.py` (lọc thô, `--bits 128`) | Python | **3 239 s** (~54 phút) | 4 | ✔ `51430ec3…` |
| `keyscan.py --no-entropy` (không lọc) | Python | **18 675 s** (~5 giờ 11 phút) | 4 | ✔ |
| `aeskeyfind` | C | **5,98 s** | 10 ứng viên | ✔ |

**Bảng B – dump `pid.512.dmp` ≈ 731 MB, quét cả 3 độ dài khóa 128/192/256 (lần đo C++):**

| Công cụ | Ngôn ngữ | Thời gian (real) | Số khóa | Có khóa đúng? |
|---|---|---|---|---|
| `keyscan` (lọc Shannon) | C++ | **16,75 s** | 5 | ✔ `e71dcd19…` |
| `keyscan --no-entropy` (không lọc) | C++ | **12,10 s** | 5 | ✔ |
| `aeskeyfind` | C | **13,87 s** | 5 khóa khác nhau (6 dòng, 1 dòng lặp) | ✔ |

Dump `pid.10032.dmp` (≈ 709 MB, AES-256, chỉ `--bits 256`): `keyscan` C++ mất **6,05 s**, ra khóa `5477e858…` ✔.

Hai bảng dùng hai dump khác nhau (kích thước, độ dài khóa quét khác nhau) nên **chỉ so sánh được trong cùng một bảng**.
`findaes` chưa đo (đo sau trên máy ANALYSIS).

Khóa tìm ra ở **mode normal**, không cần `--byteswap` — trên Windows/AES-NI key schedule nằm
đúng layout chuẩn (khác với trường hợp OpenSSL trên Linux có thể đảo byte).

## 3. Nhận xét (cho báo cáo – demo nâng cao)

**Đọc bảng cho đúng:**
- Bản **Python** (`keyscan.py`) là nguyên mẫu ban đầu: đúng phương pháp (lọc thô + xác nhận
  bằng key schedule) nhưng quá chậm để dùng thực tế (54 phút cho một dump, chưa tính 192/256).
- Bản **C++** (`keyscan.cpp`) cùng giao diện và định dạng `keys.json`, ra cùng kết quả, nhưng
  chạy **cỡ chục giây cho cả 3 độ dài khóa**, ngang `aeskeyfind` (C). Đây là bản nhóm dùng
  trong pipeline (Part 2 chụp nhiều dump lớn nên bắt buộc phải nhanh).
- Dòng Python **không lọc 18 675 s (~5 giờ) chỉ để so sánh**, không phải cách dùng thật.

Từ đó:
- **Trong Python, lọc có tác dụng rõ:** 18 675 s → 3 239 s, nhanh hơn **~5,8×**, mỗi phép kiểm tra
  key schedule rất đắt nên bỏ bớt ứng viên là có lời. Cùng lý do bài báo nêu: interrogate chậm ~100×
  vì tính key schedule cho **mọi** ứng viên bất kể entropy.
- **Trong C++, lọc Shannon không giúp gì**: có lọc 16,75 s, không lọc 12,10 s (lọc còn chậm
  hơn ~1,4×). Lý do: phép kiểm tra key schedule trong C++ thoát ngay ở từ đầu tiên không khớp
  nên đã rất rẻ, còn việc cập nhật entropy ở mỗi offset là chi phí thêm. Nghĩa là nhận xét "bỏ
  lọc entropy thì chậm cả trăm lần" của bài báo đúng với implement chậm, còn implement tối ưu
  thì lợi ích của lọc nhỏ hoặc không có. Số đo này chỉ trên 1 dump, 1 lần chạy.
- **Python → C++ cùng thuật toán và cùng bộ lọc:** 3 239 s (chỉ 128-bit) → 16,75 s (cả 3 loại),
  nhanh hơn **~190×**, dù bản C++ còn quét thêm 192 và 256.
- Cả hai bản và `aeskeyfind` ra **cùng tập khóa**; trong mỗi dump chỉ một khóa khớp với keyholder,
  các khóa còn lại là khóa AES khác của thư viện trong RAM tiến trình — đúng kỳ vọng.

**So với công cụ của bài báo:** tác giả cũng tự viết công cụ — **RansomAES** (kết hợp Volatility +
findaes) để dò khóa và **decrypt.py** để giải mã. `keyscan` + `decrypt.py` của nhóm là bản tương
ứng. Khác biệt cần nêu thẳng: RansomAES của bài báo **tái dùng lõi C của findaes** nên nhanh ngang
findaes; bản Python đầu của nhóm viết lại từ đầu nên chậm hơn rất nhiều, vì vậy nhóm viết lại lõi
bằng C++ (`keyscan.cpp`). Bài báo **không công bố số giây cụ thể**, chỉ nói findaes và RansomAES
"thời gian tương đương", interrogate "chậm gần 100 lần".

**Phân vai công cụ:** `keyscan.cpp` là công cụ dò khóa chính của nhóm (lọc Shannon theo mô tả
bài báo, hỗ trợ baseline, byteswap, quét theo PID, xuất JSON theo DATA_CONTRACT); `keyscan.py`
giữ lại để so sánh trong báo cáo; `aeskeyfind`/`findaes` dùng đối chiếu kết quả.

## 4. Phát hiện phụ: "cửa sổ thời gian" của key schedule

Lần test đầu (trên Kali), `keyholder` mã hóa xong **rồi mới** hold → khóa thô còn trong RAM
nhưng **mọi scanner ra 0 khóa**, vì findaes/aeskeyfind/keyscan tìm **key schedule** (176 byte),
mà schedule bị thư viện giải phóng ngay sau khi mã hóa xong. Sau khi sửa `keyholder` giữ một
encryptor còn sống (schedule còn trong RAM) thì dò ra bình thường.

→ Khớp đúng cảnh báo cốt lõi của bài báo: **key schedule chỉ tồn tại khi đang mã hóa**; chụp RAM
trễ là mất khóa. Đây là lý do **Part 2 (timeline khóa)** quan trọng — phải canh đúng cửa sổ.

## 5. Hạn chế & bước tiếp

- Mới chạy trên `keyholder` (chương trình test lành), **chưa phải ransomware thật**. Cần chạy lại
  với **Phobos** trong lab cô lập (chờ lab của Hải).
- Làm **Part 2 – timeline khóa:** chụp RAM định kỳ trong lúc mã hóa để vẽ khóa xuất hiện/mất
  lúc nào (như Fig. 6/8/10 của bài báo).
- Nối **Part 3:** dùng khóa moi từ dump để `decrypt.py` giải mã file ransomware thật → so hash.
- `findaes` đo trên máy Windows ANALYSIS để hoàn chỉnh bảng mục 2.
- Chạy `aeskeyfind` trên dump AES-256 (`pid.10032.dmp`) để có số đối chiếu cho lần 256-bit.
- Đo lại có lọc / không lọc trên nhiều dump (số hiện tại chỉ 1 lần chạy mỗi cấu hình).
