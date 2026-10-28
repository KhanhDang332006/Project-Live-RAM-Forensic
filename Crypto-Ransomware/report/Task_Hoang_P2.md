# Part 2 – Timeline khóa trong RAM (kế hoạch + phương pháp)

**Mảng 1 (RAM & khóa AES) – Minh Hoàng.** Đây là phần Part 2 của bài báo Davies 2020:
không chỉ *moi được khóa* (Part 1) mà còn trả lời **khóa xuất hiện trong RAM lúc nào và ở lại
bao lâu** — vẽ thành timeline (tương tự Fig. 6/8/10 của bài báo).

> **Trạng thái: chưa chạy.** Cần chụp RAM **nhiều lần trong lúc ransomware đang mã hóa**, nên
> phải có lab cô lập + mẫu thật (Phobos) của Hải. Part 1 đã xong (xem [KetQua_Part1.md](KetQua_Part1.md)).

## 1. Vì sao cần Part 2

Part 1 đã chứng minh một điểm quan trọng: **key schedule chỉ tồn tại trong RAM khi đang mã hóa**,
giải phóng ngay sau đó (xem mục 4 của KetQua_Part1.md). Vậy chụp RAM **đúng lúc** là yếu tố sống còn:
- Chụp quá sớm: khóa chưa nạp.
- Chụp quá muộn: khóa đã bị xóa / máy đã reboot.

Part 2 tạo ra timeline để biết "cửa sổ vàng" đó rộng bao nhiêu, canh cho Part 1.

## 2. Phương pháp

1. **Chụp RAM định kỳ** suốt vòng đời ransomware (ví dụ 30 giây/lần). Dùng VMware snapshot/suspend.
   Mỗi lần ra một `.vmem` + `.vmss`, đặt tên theo mốc thời gian: `mem_0030s.vmem`, `mem_0060s.vmem`…
2. **Hải ghi `capture_log.csv`** (DATA_CONTRACT mục 10): mỗi dump kèm `dump_time` và `elapsed_s`
   (số giây từ lúc chạy mẫu).
3. **Chạy `keyscan` trên từng dump**, ghi `keys.json`. Vì DATA_CONTRACT quy định *mỗi cặp dump–khóa
   một dòng*, một khóa có mặt ở nhiều dump sẽ thành nhiều dòng — đủ dữ liệu dựng timeline.
4. **Dựng biểu đồ**: trục X = thời gian (`elapsed_s`), đánh dấu các mốc dump có khóa → thấy khóa
   xuất hiện giây thứ mấy, biến mất giây thứ mấy.

## 3. Cần làm

- [ ] Thống nhất với Hải chu kỳ chụp (gợi ý 30 s; Bad Rabbit trong bài báo khóa chỉ sống ~30 s nên
      chu kỳ thưa dễ trượt — có thể phải 10–15 s).
- [ ] Script gom: đọc tất cả `keys.json` của các dump + `capture_log.csv` → bảng (elapsed_s, có_khóa).
- [ ] Vẽ biểu đồ timeline (matplotlib) kèng chú thích các pha: chạy, mã hóa, hiện ransom note, reboot.
- [ ] So với timeline trong bài báo (Fig. 6/8/10) cho mẫu tương ứng.

## 4. Lưu ý từ bài báo (mục 5) để đối chiếu

| Mẫu | Khóa xuất hiện | Tồn tại | Ghi chú |
|---|---|---|---|
| NotPetya | trong ~2 phút đầu | ~59 phút (đến khi tự reboot sau 60 phút) | khóa không sống sót qua reboot |
| Bad Rabbit | trong ~1 phút đầu | **chỉ ~30 giây** | chu kỳ chụp thưa dễ trượt |
| Phobos | trong ~1 phút đầu | nạp/xóa vài lần, xóa khi hiện ransom note | file mới tạo sau đó dùng khóa AES thứ 2 (chưa trích được) |

Nhóm chọn **Phobos** làm mẫu chính (an toàn nhất, xem bảng phân công v2), nên timeline Part 2 dựng
cho Phobos trước.
