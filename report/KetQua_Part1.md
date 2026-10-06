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

## 2. Bảng so sánh công cụ (số đo thật, cùng dump `pid.6372.dmp` ≈ 765 MB)

| Công cụ | Ngôn ngữ | Thời gian (real) | Số khóa | Có khóa đúng? |
|---|---|---|---|---|
| `keyscan` (lọc thô, `--bits 128`) | Python | **3 239 s** (~54 phút) | 4 | ✔ `51430ec3…` |
| `keyscan --no-entropy` (không lọc) | Python | **18 675 s** (~5 giờ 11 phút) | 4 | ✔ |
| `aeskeyfind` | C | **5,98 s** | 10 ứng viên | ✔ |
| `findaes` | C (Windows) | *(đo sau trên máy ANALYSIS)* | — | — |

Khóa tìm ra ở **mode normal**, không cần `--byteswap` — trên Windows/AES-NI key schedule nằm
đúng layout chuẩn (khác với trường hợp OpenSSL trên Linux có thể đảo byte).

## 3. Nhận xét (cho báo cáo – demo nâng cao)

**Đọc bảng cho đúng — con số nào là "thực chiến":**
- Thực chiến (điều tra viên thật) dùng **`aeskeyfind`/`findaes` viết bằng C → ~6 giây**. Đây là
  con số đáng nói.
- `keyscan` (nhóm tự viết, thuần Python) là **công cụ nguyên mẫu** (mục tiêu G4.2) để minh họa
  đúng phương pháp (lọc thô + xác nhận bằng key schedule), **không** nhằm đua tốc độ với tool C.
- Dòng **không lọc 18 675 s (~5 giờ) chỉ để so sánh**, cho thấy tác dụng của bước lọc thô —
  **không phải cách dùng thật**. Không ai chạy quét không lọc cả dump trong thực tế.

Từ đó:
- **Lọc thô có tác dụng rõ:** 18 675 s → 3 239 s, nhanh hơn **~5,8×**. Cùng lý do bài báo nêu:
  interrogate chậm ~100× vì tính key schedule cho **mọi** ứng viên bất kể entropy.
- **`aeskeyfind` (C) nhanh hơn `keyscan` (Python) ~540×** (5,98 s vs 3 239 s) — chênh lệch ngôn ngữ
  biên dịch (C) với thông dịch (Python), đã lường trước.
- Cả hai cùng ra 4 khóa 128-bit; khóa đầu `51430ec3…` khớp keyholder, 3 khóa còn lại là khóa AES
  khác đang nằm trong RAM tiến trình (thư viện/hệ thống dùng) — đúng kỳ vọng.

**So với công cụ của bài báo:** tác giả cũng tự viết công cụ — **RansomAES** (kết hợp Volatility +
findaes) để dò khóa và **decrypt.py** để giải mã. `keyscan` + `decrypt.py` của nhóm là bản tương
ứng. Khác biệt cần nêu thẳng: RansomAES của bài báo **tái dùng lõi C của findaes** nên nhanh ngang
findaes; `keyscan` của nhóm viết lại thuần Python từ đầu nên chậm hơn. Bài báo **không công bố số
giây cụ thể**, chỉ nói findaes và RansomAES "thời gian tương đương", interrogate "chậm gần 100 lần".

**Hướng tối ưu nếu cần nhanh:** quét riêng vùng heap của tiến trình nghi ngờ (vài MB thay vì cả
memmap 765 MB), hoặc đơn giản dùng aeskeyfind/findaes cho phần dò, giữ keyscan cho phần tùy biến
(lọc baseline, byteswap, quét theo PID).

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
- (Tùy chọn) tối ưu `keyscan`: 765 MB mất 54 phút là chậm — có thể chỉ quét vùng heap thay vì
  cả memmap, hoặc tăng `step`/`--bits` để giảm phạm vi.
