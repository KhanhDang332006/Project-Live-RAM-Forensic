# Kiến thức nền – Mảng 2: Ransomware, mã hóa AES và dấu vết trên đĩa
## 1. Ransomware là gì

Ransomware là mã độc tống tiền: nó chiếm quyền sử dụng dữ liệu hoặc hệ thống của nạn nhân rồi đòi
tiền chuộc để trả lại. Có hai dạng chính. **Locker ransomware** khóa cả máy (ví dụ chặn màn hình đăng
nhập) nhưng thường không đụng tới dữ liệu. **Crypto ransomware** mã hóa chính các file của nạn nhân:
máy vẫn chạy, nhưng tài liệu, ảnh, cơ sở dữ liệu không mở được nữa. Đề tài này điều tra dạng thứ hai.

Khác với phần lớn mã độc, ransomware không cần ẩn mình mãi. Trojan đánh cắp dữ liệu muốn tồn tại càng
lâu càng tốt mà không bị phát hiện; ransomware thì đến một lúc phải lộ diện, vì nạn nhân cần biết chuyện
gì đã xảy ra và trả tiền cho ai. Hành vi "ồn ào" đó (thả thư đòi tiền, mã hóa hàng loạt file, xóa bản
sao lưu) để lại rất nhiều dấu vết trên đĩa, là đối tượng của mục 6.

Ransomware có từ hơn 30 năm trước nhưng chỉ thành mối đe dọa lớn từ khi CryptoLocker (2013) kết hợp ba
thứ: tiền mã hóa để nhận tiền ẩn danh, mạng Tor để giấu máy chủ, và mật mã mạnh để nạn nhân không tự
giải mã được. Theo bài báo của Davies và cộng sự, NotPetya là vụ gây thiệt hại lớn nhất lịch sử (khoảng
10 tỷ USD), còn WannaCry ở mức 4 đến 8 tỷ USD. Về sau còn xuất hiện **tống tiền kép** (đánh cắp dữ liệu
trước khi mã hóa rồi dọa công bố) và mô hình **Ransomware-as-a-Service**, trong đó nhóm phát triển cho
"chi nhánh" thuê mã độc rồi chia tiền chuộc.

## 2. Phân loại theo cách mã hóa: SCR, ACR, HCR

Bài báo phân loại ransomware theo kiểu mã hóa (dựa trên khảo sát của Al-rimy và cộng sự, 2018). Cách
phân loại này quan trọng với điều tra viên, vì kiểu mã hóa quyết định có cơ hội lấy lại dữ liệu hay không.

| Loại | Cách làm | Điểm mạnh | Điểm yếu |
|---|---|---|---|
| **SCR** – Symmetric Crypto-Ransomware | Một khóa đối xứng (ví dụ AES) dùng cho cả mã hóa và giải mã | Nhanh, mã hóa xong sớm nên ít bị phát hiện | Khóa giải mã phải có mặt trên máy nạn nhân lúc mã hóa |
| **ACR** – Asymmetric Crypto-Ransomware | Mã hóa bằng khóa công khai, giải mã bằng khóa riêng (ví dụ RSA) | Khóa riêng không cần có trên máy nạn nhân | Rất chậm, mỗi lần chỉ mã hóa được một khối nhỏ |
| **HCR** – Hybrid Crypto-Ransomware | Mã hóa file bằng AES, sau đó mã hóa khóa AES bằng khóa công khai RSA | Nhanh như SCR, giữ được bí mật như ACR | Khóa AES vẫn phải nằm trong RAM lúc mã hóa |

**Vì sao HCR phổ biến nhất.** Mỗi loại thuần túy có một điểm yếu mà loại lai khắc phục được. SCR nhanh,
nhưng khóa giải mã nằm ngay trên máy nạn nhân, nên người điều tra có thể lấy lại. ACR giữ được khóa riêng
ở phía kẻ tấn công, nhưng RSA chậm hơn AES rất nhiều và mỗi lần chỉ xử lý được vài trăm byte (RSA-2048),
nên không thể dùng để mã hóa hàng nghìn file lớn. HCR chia việc: AES lo phần nặng là mã hóa dữ liệu, RSA
chỉ làm đúng một việc nhỏ là "khóa" lại khóa AES bằng khóa công khai của kẻ tấn công. Muốn mở khóa AES
phải có khóa riêng RSA, mà khóa này không bao giờ có trên máy nạn nhân. Cả ba mẫu trong bài báo
(NotPetya, Bad Rabbit, Phobos) đều thuộc loại này.

Hệ quả cho điều tra: tìm khóa riêng RSA là vô ích, điểm duy nhất khai thác được là khóa AES lúc nó còn
trong RAM (xem mục 4 của kiến thức nền Mảng 1). Khóa AES là khóa đối xứng nên cũng chính là khóa giải
mã: lấy được nó là đủ để mở file, không cần đụng tới phần RSA.

## 3. AES và chế độ CBC

**AES** (Advanced Encryption Standard, chuẩn FIPS-197) là mã khối: mỗi lần mã hóa đúng một khối 16 byte.
Khóa dài 128, 192 hoặc 256 bit, tương ứng 10, 12 hoặc 14 vòng biến đổi. Bài báo ghi nhầm "198 bit"
(mục 2.2.3); đúng phải là 192. Nếu không có khóa đúng thì gần như không thể giải mã.

File thường dài hơn 16 byte, nên cần một **chế độ mã hóa** (mode of operation) để ghép các khối lại.
Cách ngây thơ nhất là mã hóa độc lập từng khối (ECB), nhưng khi đó hai khối giống nhau cho ra hai bản mã
giống nhau, làm lộ cấu trúc của dữ liệu. Chế độ **CBC** (Cipher Block Chaining) khắc phục bằng cách
trộn mỗi khối với bản mã của khối trước đó:

```
Mã hóa:   C_i = E_K( P_i XOR C_(i-1) ),   với C_(-1) = IV
Giải mã:  P_i = D_K( C_i ) XOR C_(i-1)
```

`P_i` là khối bản rõ thứ i, `C_i` là khối bản mã, `K` là khóa. Khối đầu tiên không có "khối trước" nên
được trộn với một giá trị 16 byte gọi là **IV** (initialization vector).

**Padding.** Độ dài file hiếm khi chia hết cho 16, nên trước khi mã hóa phải đệm thêm cho đủ khối. Chuẩn
PKCS7 thêm `n` byte, mỗi byte có giá trị `n`: thiếu 3 byte thì thêm `03 03 03`. Nếu file đã chia hết cho
16 thì vẫn thêm nguyên một khối `10 10 … 10`, để lúc giải mã luôn biết chắc phải bỏ đi bao nhiêu byte.
Giải mã bằng khóa sai cho ra dữ liệu ngẫu nhiên, và phần đuôi gần như không bao giờ có dạng padding hợp
lệ. Đây là cách rẻ nhất để loại khóa sai: chỉ cần giải mã khối cuối cùng.

## 4. IV: vai trò, vì sao để công khai vẫn an toàn, nằm ở đâu

**Vai trò.** IV làm cho cùng một nội dung, mã hóa với cùng một khóa, vẫn ra hai bản mã khác nhau. Nếu
không có IV ngẫu nhiên, hai file có phần đầu giống nhau (ví dụ hai file docx cùng header) sẽ có phần đầu
bản mã giống nhau, và kẻ quan sát đoán được nội dung.

**Vì sao để công khai vẫn an toàn.** Toàn bộ bí mật của hệ mã nằm ở khóa, không nằm ở IV. Theo khuyến
nghị của NIST (SP 800-38A), IV cho CBC cần không đoán trước được và không lặp lại, nhưng **không cần giữ
bí mật**. Biết IV mà không có khóa thì vẫn không suy ra được gì về bản rõ: muốn tính `D_K(C_i)` vẫn phải
có `K`. Ransomware ghi IV ngay vào file bị mã hóa vì mỗi file có một IV riêng, và chính kẻ tấn công cũng
cần IV để giải mã sau khi nạn nhân trả tiền. Với điều tra viên, đó là may mắn: chỉ cần khóa AES từ RAM,
còn IV đọc ngay trong file.

**IV nằm ở đâu.** Mỗi họ ransomware có cách bố trí riêng, nên trước khi giải mã phải xác định layout bằng
cách so sánh hex file gốc với file bị mã hóa:

| Mẫu | Vị trí IV | Nguồn |
|---|---|---|
| NotPetya, Bad Rabbit | 16 byte đầu file | Bài báo, mục 5.1.3 và 5.2.3 |
| Phobos | Cuối file: padding, IV, khối 128 byte giống nhau ở mọi file, chuỗi đánh dấu `LOCK96` | Bài báo, mục 5.3.3 |
| Chương trình mô phỏng của nhóm | 16 byte đầu file (cả `prepend` và `overwrite16`) | DATA_CONTRACT.md, mục 6 |

**Khi IV chiếm chỗ đầu file.** Với NotPetya, IV nằm ở 16 byte đầu nên 16 byte đầu của bản gốc bị mất:
giải mã ra file thiếu header, phải chèn lại header theo từng loại file. Bài báo nói "16 byte đầu bị ghi đè
bằng IV" nhưng không nói rõ ghi đè lên đâu. Nếu IV ghi đè lên khối bản mã đầu tiên `C_0` thì theo công
thức CBC, cả `P_0` lẫn `P_1` đều hỏng (vì `P_1 = D_K(C_1) XOR C_0`), tức mất 32 byte, và IV trong file
trở thành vô dụng. Điều này trái với việc tác giả dùng IV để giải mã. Nhóm hiểu theo cách nhất quán với
bài báo: file = IV + bản mã của nội dung tính từ byte 16, nên mất đúng 16 byte. Đây là profile
`overwrite16` của nhóm.

## 5. Chứng minh file giải mã ra là đúng

Bài báo xác nhận kết quả bằng tay: mở file xem có đọc được không (mục 4.3.3). Cách này không định lượng
và không làm được khi có hàng trăm khóa ứng viên. Nhóm kiểm tra theo ba lớp, từ rẻ đến chắc:

1. **Padding hợp lệ:** khóa sai chỉ lọt qua với xác suất khoảng 1/256.
2. **Cấu trúc file:** magic bytes đúng với loại file (`%PDF` cho pdf, `PK\x03\x04` cho docx/xlsx,
   `D0 CF 11 E0` cho doc/xls), hoặc dấu kết thúc đặc trưng (`%%EOF` của pdf, `FF D9` của jpg).
3. **SHA-256:** trước khi cho mẫu chạy, lưu SHA-256 của mọi file mồi vào `manifest.csv`. Giải mã xong
   tính lại SHA-256; khớp nghĩa là file ra trùng từng byte với bản gốc. Đây là bằng chứng mạnh nhất, và
   là điểm nhóm làm tốt hơn bài báo.

## 6. Dấu vết ransomware trên ổ đĩa

Bài báo chỉ phân tích RAM. Để trả lời câu hỏi "chuyện gì đã xảy ra, lúc nào, bằng cách nào", Mảng 2
phân tích thêm ảnh ổ đĩa của máy nạn nhân. Các dấu vết chính:

| Dấu vết | Vị trí trên Windows | Cho biết điều gì |
|---|---|---|
| Thư đòi tiền chuộc | Các thư mục có file bị mã hóa, desktop, đôi khi thay cả hình nền | Có lây nhiễm; nhận dạng họ ransomware; mốc thời gian mã hóa |
| File bị mã hóa, đổi tên | Toàn ổ dữ liệu | Phạm vi thiệt hại; đuôi mới và chuỗi đánh dấu giúp nhận dạng họ |
| Run key trong Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, khóa tương ứng trong `HKLM`, dịch vụ trong `HKLM\SYSTEM\CurrentControlSet\Services` | Cơ chế tự khởi động lại sau mỗi lần bật máy (persistence) |
| Prefetch | `C:\Windows\Prefetch\*.pf` | Chương trình nào đã thực sự chạy, chạy mấy lần, lần gần nhất lúc nào |
| Xóa Volume Shadow Copy | Prefetch của `vssadmin.exe`, `wmic.exe`; Event Log | Hành vi chủ động chặn khôi phục dữ liệu |
| Mốc thời gian trong `$MFT` | Master File Table của phân vùng NTFS | Thời điểm hàng loạt file bị sửa, tức lúc mã hóa diễn ra |

**Thư đòi tiền và file bị mã hóa.** Thư đòi tiền (thường là `.txt`, `.html` hoặc `.hta`) là bằng chứng
trực quan nhất; tên và nội dung thư giúp nhận dạng họ mã độc. Nhận diện file bị mã hóa thì tùy mẫu. Theo
bài báo, NotPetya **không đổi tên** file, nên không lọc được theo đuôi mà phải dựa vào nội dung: magic
bytes không còn khớp với đuôi file, entropy cao bất thường. Phobos thì đổi tên file và gắn chuỗi
`LOCK96` vào cuối file, nên tìm theo từ khóa là ra.

**Registry.** Mã độc muốn sống sót qua lần khởi động lại thường ghi mình vào các khóa Run hoặc cài thành
dịch vụ. Một đường dẫn lạ trong các khóa này, nhất là trỏ vào thư mục tạm hay thư mục người dùng, là dấu
hiệu cần kiểm tra.

**Prefetch.** Mỗi khi một chương trình chạy, Windows tạo hoặc cập nhật một file `.pf` trong
`C:\Windows\Prefetch` để lần sau khởi động nhanh hơn. Vì vậy Prefetch là bằng chứng chương trình đã
**thực sự được thực thi**, không chỉ nằm trên đĩa. Prefetch của file mẫu hay của `vssadmin.exe` ngay
trước thời điểm mã hóa là mảnh ghép quan trọng cho timeline. Lưu ý: không thấy Prefetch chưa chắc là
chương trình chưa chạy, vì kẻ tấn công có thể xóa thư mục này.

**Xóa Volume Shadow Copy.** Windows giữ các bản chụp (shadow copy) để khôi phục file về trạng thái cũ.
Nếu chúng còn, nạn nhân không cần trả tiền, nên hầu hết ransomware xóa chúng bằng các lệnh như
`vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, hoặc dùng `bcdedit` để tắt chế độ tự sửa
lỗi khởi động. Khung MITRE ATT&CK gọi hành vi này là T1490 (Inhibit System Recovery), bên cạnh T1486
(Data Encrypted for Impact) cho việc mã hóa. Dấu vết nằm ở Prefetch của `vssadmin.exe`/`wmic.exe`, và ở
sự kiện tạo tiến trình 4688 trong Security Event Log nếu máy bật ghi nhận dòng lệnh. Việc chủ động xóa
bản sao lưu là bằng chứng mạnh cho thấy đây là phá hoại có chủ đích, không phải sự cố ngẫu nhiên.

**Timeline từ `$MFT`.** Mỗi file trên NTFS có các mốc thời gian sửa, truy cập, thay đổi bản ghi và tạo
(MACB). Xếp mốc thời gian của mọi file lên một trục sẽ thấy một "cơn bão" file bị sửa trong vài phút: đó
là lúc mã hóa. NTFS lưu thời gian ở hai thuộc tính, `$STANDARD_INFORMATION` và `$FILE_NAME`; kẻ tấn công
giả mạo thời gian thường chỉ sửa được thuộc tính thứ nhất, nên hai bộ thời gian lệch nhau là dấu hiệu nghi
ngờ. Timeline từ đĩa là khung để ghép thêm dữ liệu RAM và mạng thành timeline sự cố tổng hợp.

## 7. Liên hệ với các phần khác

- Vì sao khóa AES bắt buộc nằm trong RAM, cách nhận diện khóa bằng key schedule: kiến thức nền Mảng 1.
- Phân tích chi tiết Windows Event Log (đăng nhập, 4688, cài dịch vụ 7045, xóa log 1102): việc PHỤ của
  Trung Hải trong Mảng 2.
- Cách `decrypt.py` hiện thực các ý ở mục 3–5: `report/Task_Dang_P3.md`.

## Tài liệu tham khảo

- Davies, S. R., Macfarlane, R., Buchanan, W. J. (2020). *Evaluation of live forensic techniques in
  ransomware attack mitigation.* Forensic Science International: Digital Investigation.
- Al-rimy, B. A. S., Maarof, M. A., Shaid, S. Z. M. (2018). *Ransomware threat success factors, taxonomy,
  and countermeasures: A survey and research directions.* Computers & Security, 74, 144–166.
- NIST (2001). *FIPS PUB 197: Advanced Encryption Standard (AES).*
- NIST (2001). *SP 800-38A: Recommendation for Block Cipher Modes of Operation.*
- Issa, J. (2019). *A deep dive into Phobos ransomware.* Malwarebytes Labs.
- Sood, K., Hurley, S. (2017). *NotPetya Technical Analysis – A Triple Threat.* CrowdStrike.
- MITRE ATT&CK: T1486 Data Encrypted for Impact; T1490 Inhibit System Recovery.
