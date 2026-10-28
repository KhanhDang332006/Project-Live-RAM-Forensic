# Kiến thức nền – Mảng 1: Điều tra bộ nhớ RAM và khóa AES
## 1. Live forensics và dead-box forensics

Pháp chứng máy tính truyền thống (dead-box) phân tích một máy đã tắt, chủ yếu làm việc trên ảnh
ổ đĩa. Cách này bỏ sót toàn bộ dữ liệu bay hơi: khi tắt máy, mọi thứ nằm trong RAM đều mất. Mà
nhiều dấu vết quan trọng chỉ tồn tại trong RAM: khóa mã hóa, kết nối mạng đang mở, tiến trình đang
chạy, người dùng đang đăng nhập, mã độc đang thực thi.

Live forensics bù vào khoảng trống đó: thu thập và phân tích dữ liệu bay hơi từ một máy **đang chạy**.
Với ransomware, điều này đặc biệt có ý nghĩa, vì khóa AES dùng để mã hóa file bắt buộc phải nằm
trong RAM lúc mã hóa (xem mục 4). Nếu phân tích RAM đúng thời điểm thì có thể lấy lại khóa và giải
mã ngược file, tức vô hiệu hóa đòn tống tiền mà không cần trả tiền chuộc.

## 2. Order of volatility

Dữ liệu càng dễ mất thì càng phải thu trước. Thứ tự ưu tiên thường là: thanh ghi và cache CPU →
nội dung RAM → trạng thái mạng và các kết nối → tiến trình đang chạy → dữ liệu trên đĩa → bản sao
lưu, log lưu trữ. Với đề tài này, RAM là nguồn bằng chứng dễ mất nhất và cũng quan trọng nhất,
nên nó được thu đầu tiên; ảnh đĩa thu sau vì dữ liệu trên đĩa ổn định hơn.

## 3. Memory acquisition

Theo Ruff, có ba nhóm kỹ thuật chụp RAM:

1. **Phần mềm:** chạy một chương trình chụp RAM ngay trên máy cần điều tra. Nhược điểm: chính việc
   chạy chương trình đã làm thay đổi nội dung RAM đang chụp, và nếu máy đã nhiễm mã độc thì kết quả
   có thể không tin cậy.
2. **Phần cứng:** dùng thiết bị cắm vào (thẻ PCMCIA, USB chuyên dụng). Cần truy cập vật lý vào máy,
   không phải lúc nào cũng khả thi.
3. **Qua ảo hóa (hypervisor):** chụp snapshot bộ nhớ của máy ảo bằng công cụ của phần mềm ảo hóa.
   Đây là cách nhóm dùng. Ưu điểm lớn: mã độc chạy trong máy ảo **không biết** mình đang bị chụp,
   và bản dump không chứa dấu vết của công cụ chụp. Trong thực nghiệm của nhóm, một máy Windows 10
   chạy trong VMware được suspend để tạo file `.vmem` (RAM thô) kèm `.vmss`; Volatility 3 đọc được
   file này và liệt kê đầy đủ tiến trình.

## 4. Vì sao khóa AES bắt buộc nằm trong RAM

Ransomware hiện đại phần lớn là loại lai (Hybrid Crypto-Ransomware, HCR). Nó mã hóa file của nạn
nhân bằng khóa đối xứng AES cho nhanh, sau đó mã hóa lại chính khóa AES đó bằng khóa công khai RSA.
Khóa riêng RSA — thứ dùng để giải mã khóa AES — luôn nằm ở máy kẻ tấn công, không bao giờ xuất hiện
trên máy nạn nhân. Vì vậy truy tìm khóa RSA là không thể.

Điểm khai thác nằm ở khóa AES. Để mã hóa (và để tự giải mã khi cần), thuật toán bắt buộc phải nạp
khóa AES vào RAM trong lúc đang chạy. Đây là mắt xích yếu duy nhất có thể khai thác được bằng
live forensics: khóa đối xứng chắc chắn hiện diện trong bộ nhớ nạn nhân tại thời điểm mã hóa.

## 5. Nhận diện khóa AES trong bộ nhớ

Khóa AES chỉ dài 16–32 byte, lọt giữa hàng trăm MB tới vài GB dữ liệu. Cách định vị dựa trên hai
đặc điểm:

**a) Entropy.** Khóa được sinh ngẫu nhiên nên có entropy cao, trong khi code, text và cấu trúc dữ
liệu thường có entropy thấp hơn. Chia bộ nhớ thành các đoạn nhỏ, đo entropy, chỗ nào cao bất thường
là ứng viên khóa. (Lưu ý: khóa có entropy cao vì bản thân nó ngẫu nhiên, không phải vì bị mã hóa.)

**b) Key schedule của AES.** AES không dùng thẳng khóa gốc mà chạy nhiều vòng, mỗi vòng cần một
khóa con sinh từ khóa gốc qua thuật toán key schedule. Để chạy nhanh, phần mềm thường tính sẵn toàn
bộ khóa con một lần rồi giữ nguyên trong RAM (đánh đổi bảo mật lấy tốc độ). Với AES-128, trong bộ
nhớ có cả một mảng 176 byte: 16 byte đầu là khóa gốc, 160 byte sau là các khóa con; AES-256 thì mảng
dài 240 byte. Giữa khóa gốc và khóa con có quan hệ toán học ràng buộc. Công cụ lấy mỗi đoạn 16 byte
nghi ngờ, tự tính key schedule đúng-ra-phải-có, rồi so với các byte đứng ngay sau trong bộ nhớ. Nếu
khớp cả mảng thì gần như chắc chắn đó là khóa AES thật, vì một khối 176 byte thỏa đúng ràng buộc
key schedule thì không thể trùng hợp ngẫu nhiên.

**Quy trình hai bước** kết hợp cả hai: lọc thô bằng entropy để khoanh vùng cho nhanh, rồi xác nhận
chắc chắn bằng key schedule. Chính điểm tối ưu tốc độ của AES (lưu sẵn toàn bộ khóa con có cấu trúc
biết trước) lại trở thành chỗ để pháp chứng tóm được khóa.

## 6. Công cụ trích khóa

- **findaes** (Kornblum) và **aeskeyfind** (bắt nguồn từ tấn công Cold Boot "Lest We Remember"):
  viết bằng C, dựa trên cấu trúc AES key schedule, chạy rất nhanh.
- **interrogate** (Maartmann-Moe): cũng dựa trên cùng nguyên lý, nhưng chậm hơn khoảng 100 lần vì
  tính key schedule cho mọi ứng viên bất kể entropy.
- **RansomAES** (tác giả bài báo tự viết): công cụ lai, kết hợp logic của Volatility Framework với
  logic của findaes. Bài báo cho biết RansomAES có thời gian và kết quả tương đương findaes (phần
  mở rộng cho ransomware không cải thiện thêm), vì nó tái dùng lõi C của findaes.
- **keyscan** (nhóm tự viết): công cụ nguyên mẫu bằng Python, đóng vai trò tương tự RansomAES của
  bài báo. Làm đúng quy trình hai bước (lọc theo số byte phân biệt rồi xác nhận bằng key schedule),
  có thêm chế độ loại khóa nền (`--baseline`), đảo byte trong word (`--byteswap`) và quét riêng vùng
  nhớ một tiến trình. Vì viết lại thuần Python từ đầu (không tái dùng lõi C như RansomAES) nên chạy
  chậm hơn các tool C; thực chiến vẫn nên dùng findaes/aeskeyfind cho phần dò, keyscan dùng để minh
  họa phương pháp và tùy biến.

Kết quả đo của nhóm (trên dump 765 MB của tiến trình): keyscan có lọc mất
~54 phút, không lọc mất ~5 giờ (lọc nhanh hơn ~5,8 lần — cùng lý do với nhận xét về interrogate
trong bài báo); aeskeyfind viết bằng C chỉ mất khoảng 6 giây. Cả ba đều tìm ra đúng khóa.

## 7. Giới hạn và "cửa sổ thời gian"

Phương pháp chỉ hiệu quả khi thỏa một số điều kiện:

- **Key schedule chỉ tồn tại khi đang mã hóa.** Thực nghiệm của nhóm xác nhận: khi chương trình mã
  hóa xong và giải phóng context, key schedule biến mất khỏi RAM dù 16 byte khóa thô vẫn còn trong
  biến. Lúc đó mọi công cụ (findaes, aeskeyfind, keyscan) đều không tìm thấy, vì chúng tìm key
  schedule chứ không tìm 16 byte khóa. Vì vậy phải chụp RAM đúng lúc
- **Máy chưa reboot:** khóa AES không sống sót qua khởi động lại.
- **Mẫu dùng chung một khóa cho mọi file:** WannaCry dùng khóa riêng cho từng file nên không có khóa
  nào dùng lại được, mọi công cụ đều thất bại.
- **Không áp dụng cho mọi họ ransomware:** ví dụ Cerber không dùng AES.
